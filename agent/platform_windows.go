// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/platform_windows.go
// Purpose : Windows specifics: service control, registry settings, ACLs, uptime, power off, popups
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

// serviceName is the name registered by the MSI.
const serviceName = "rsd-agent"

// registryKey holds the values written by the MSI properties (MASTER, ENROLL_TOKEN, CA_FINGERPRINT).
const registryKey = `SOFTWARE\rsd-agent`

var (
	kernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64             = kernel32.NewProc("GetTickCount64")
	procQueryUnbiasedInterruptTime = kernel32.NewProc("QueryUnbiasedInterruptTime")
	procGetSystemDefaultLocaleName = kernel32.NewProc("GetSystemDefaultLocaleName")
	wtsapi32                       = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSSendMessageW            = wtsapi32.NewProc("WTSSendMessageW")
)

// programData returns %ProgramData%\rsd-agent.
func programData() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "rsd-agent")
}

// defaultConfigPath is the optional JSON configuration file.
func defaultConfigPath() string { return filepath.Join(programData(), "agent.json") }

// defaultStateDir holds the key and the certificates (ACL: SYSTEM and Administrators only).
func defaultStateDir() string { return filepath.Join(programData(), "state") }

// defaultLogFile is used when running as a service (no console).
func defaultLogFile() string { return filepath.Join(programData(), "agent.log") }

// isWindowsService reports whether the process was started by the service control manager.
func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// agentService adapts the agent to the service control manager.
type agentService struct{ cfg *Config }

// Execute implements svc.Handler.
func (s *agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		NewAgent(s.cfg).Run(ctx)
		close(done)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		case <-done:
			cancel()
			return false, 0
		}
	}
}

// runWindowsService runs the agent under the service control manager.
func runWindowsService(cfg *Config) error { return svc.Run(serviceName, &agentService{cfg: cfg}) }

// applyRegistry reads the values written by the MSI (empty values are ignored).
func applyRegistry(cfg *Config) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, registryKey, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	for name, dst := range map[string]*string{"Master": &cfg.Master, "EnrollToken": &cfg.EnrollToken,
		"CAFingerprint": &cfg.CAFingerprint} {
		if v, _, err := k.GetStringValue(name); err == nil && strings.TrimSpace(v) != "" {
			*dst = strings.TrimSpace(v)
		}
	}
}

// clearRegistryToken deletes the consumed enrollment token from the registry.
func clearRegistryToken() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, registryKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue("EnrollToken")
}

// requireAdmin fails unless the process is elevated.
func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator privileges required (run from an elevated prompt)")
	}
	return nil
}

// secureDir replaces the inherited ACL (Users can read ProgramData) by SYSTEM + Administrators.
func secureDir(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// enableBroadcast sets SO_BROADCAST on a UDP socket.
func enableBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

// bootUptime returns GetTickCount64 (milliseconds since boot).
func bootUptime() time.Duration {
	ms, _, _ := procGetTickCount64.Call()
	return time.Duration(ms) * time.Millisecond
}

// awakeClock returns QueryUnbiasedInterruptTime, which stops during sleep and hibernation
// (so the "fast startup" hybrid shutdown is detected as a resume).
func awakeClock() time.Duration {
	var t uint64
	if r, _, _ := procQueryUnbiasedInterruptTime.Call(uintptr(unsafe.Pointer(&t))); r == 0 {
		return bootUptime()
	}
	return time.Duration(t * 100)
}

// platformOSName returns e.g. "Windows 11 Pro 23H2".
func platformOSName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	display, _, _ := k.GetStringValue("DisplayVersion")
	if n, err := strconv.Atoi(build); err == nil && n >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1) // ProductName still says 10
	}
	return strings.TrimSpace(name + " " + display)
}

// powerOff halts the machine (force closes the applications without asking).
func powerOff(force bool) error {
	args := []string{"/s", "/t", "0", "/d", "p:0:0", "/c", "Remote Shutdown"}
	if force {
		args = append(args, "/f")
	}
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "shutdown.exe")
	return exec.Command(exe, args...).Run()
}

// Message box styles (winuser.h).
const (
	mbOK            = 0x00000000
	mbIconWarning   = 0x00000030
	mbSetForeground = 0x00010000
	mbTopMost       = 0x00040000
)

// activeSessions returns the ids of the sessions with a logged-in user.
func activeSessions() []uint32 {
	var infos *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &infos, &count); err != nil {
		return []uint32{windows.WTSGetActiveConsoleSessionId()}
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(infos)))
	var ids []uint32
	for _, s := range unsafe.Slice(infos, count) {
		if s.State == windows.WTSActive && s.SessionID != 0 {
			ids = append(ids, s.SessionID)
		}
	}
	return ids
}

// sessionLanguage returns the display language of the user of a session ("fr-FR"...): the
// preferred UI language of the profile, then its regional format, then the system locale.
func sessionLanguage(sessionID uint32) string {
	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err == nil {
		defer token.Close()
		if user, err := token.GetTokenUser(); err == nil {
			sid := user.User.Sid.String()
			if k, err := registry.OpenKey(registry.USERS, sid+`\Control Panel\Desktop`, registry.QUERY_VALUE); err == nil {
				langs, _, err := k.GetStringsValue("PreferredUILanguages")
				k.Close()
				if err == nil && len(langs) > 0 && langs[0] != "" {
					return langs[0]
				}
			}
			if k, err := registry.OpenKey(registry.USERS, sid+`\Control Panel\International`, registry.QUERY_VALUE); err == nil {
				name, _, err := k.GetStringValue("LocaleName")
				k.Close()
				if err == nil && name != "" {
					return name
				}
			}
		}
	}
	buf := make([]uint16, 85) // LOCALE_NAME_MAX_LENGTH
	if r, _, _ := procGetSystemDefaultLocaleName.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); r != 0 {
		return windows.UTF16ToString(buf)
	}
	return "en-US"
}

// ShowMessage shows a message box on every active session, in the language of its user
// (WTSSendMessage works from a service in session 0 and on every edition, unlike msg.exe
// which Home editions lack). The box is drawn by Windows itself: like every system message
// box it keeps the classic light style, whatever the dark mode setting.
func ShowMessage(note Note) error {
	ids := activeSessions()
	if len(ids) == 0 {
		return errors.New("no user session")
	}
	var lastErr error
	for _, id := range ids {
		title, text := note.Render(sessionLanguage(id))
		t, err := windows.UTF16FromString(title)
		if err != nil {
			return err
		}
		m, err := windows.UTF16FromString(text)
		if err != nil {
			return err
		}
		var response uint32
		r, _, callErr := procWTSSendMessageW.Call(0, uintptr(id),
			uintptr(unsafe.Pointer(&t[0])), uintptr((len(t)-1)*2),
			uintptr(unsafe.Pointer(&m[0])), uintptr((len(m)-1)*2),
			mbOK|mbIconWarning|mbSetForeground|mbTopMost, 600, uintptr(unsafe.Pointer(&response)), 0)
		if r == 0 {
			lastErr = callErr
		}
	}
	return lastErr
}

// AskReply shows the message only: a service cannot open an input dialog in a user session
// without launching a helper process there, so chat replies are not supported on Windows.
func AskReply(note Note) (string, string, error) {
	return "", "", ShowMessage(note)
}
