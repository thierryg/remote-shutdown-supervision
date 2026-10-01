// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/platform_darwin.go
// Purpose : macOS specifics: paths, uptime, OS name, power off, dialogs in the console user session
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const darwinDir = "/Library/Application Support/rsd-agent"

// defaultConfigPath is the configuration file installed by the pkg.
func defaultConfigPath() string { return darwinDir + "/agent.json" }

// defaultStateDir holds the key and the certificates.
func defaultStateDir() string { return darwinDir + "/state" }

// bootUptime is computed from the kern.boottime sysctl.
func bootUptime() time.Duration {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0
	}
	sec, nsec := tv.Unix()
	return time.Since(time.Unix(sec, nsec))
}

// platformOSName returns "macOS <version>".
func platformOSName() string {
	out, err := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
	if err != nil {
		return "macOS"
	}
	return "macOS " + strings.TrimSpace(string(out))
}

// powerOff halts the machine.
func powerOff(bool) error {
	return exec.Command("/sbin/shutdown", "-h", "now").Run()
}

// consoleUser returns the user logged in on the console (nil at the login window).
func consoleUser() *desktopUser {
	if os.Geteuid() != 0 {
		return &desktopUser{Name: os.Getenv("USER"), UID: os.Getuid(), GID: os.Getgid(), Home: os.Getenv("HOME")}
	}
	out, err := exec.Command("/usr/bin/stat", "-f", "%Su", "/dev/console").Output()
	name := strings.TrimSpace(string(out))
	if err != nil || name == "" || name == "root" || name == "_mbsetupuser" {
		return nil
	}
	du, err := lookupDesktopUser(name)
	if err != nil {
		return nil
	}
	return du
}

// osascript runs an AppleScript in the console user's GUI session; the texts are passed as
// arguments (never interpolated in the script), so they cannot inject AppleScript code.
func osascript(ctx context.Context, du *desktopUser, script string, args ...string) (string, int, error) {
	cmdArgs := []string{}
	for _, line := range strings.Split(script, "\n") {
		cmdArgs = append(cmdArgs, "-e", line)
	}
	cmdArgs = append(cmdArgs, args...)
	if os.Geteuid() == 0 {
		// launchctl asuser enters the user's bootstrap namespace (required to show UI).
		full := append([]string{"asuser", strconv.Itoa(du.UID), "/usr/bin/osascript"}, cmdArgs...)
		return runAs(ctx, &desktopUser{Name: du.Name, Home: du.Home, UID: 0}, "/bin/launchctl", full...)
	}
	return runAs(ctx, du, "/usr/bin/osascript", cmdArgs...)
}

// Dialogs of osascript follow the light/dark appearance of the user automatically; the texts
// and button labels are passed as arguments (item 1: title, 2: text, 3+: buttons).
const infoScript = `on run argv
display dialog (item 2 of argv) with title (item 1 of argv) buttons {item 3 of argv} default button 1 with icon caution giving up after 600
end run`

const replyScript = `on run argv
set r to display dialog (item 2 of argv) with title (item 1 of argv) default answer "" buttons {item 3 of argv, item 4 of argv} default button 2 giving up after 900
if button returned of r is (item 4 of argv) then return text returned of r
return ""
end run`

// userLanguage returns the first preferred language of the console user ("fr-FR"...).
func userLanguage(du *desktopUser) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var out string
	var err error
	if os.Geteuid() == 0 {
		out, _, err = runAs(ctx, &desktopUser{Name: du.Name, Home: du.Home, UID: 0}, "/bin/launchctl",
			"asuser", strconv.Itoa(du.UID), "/usr/bin/sudo", "-u", du.Name, "/usr/bin/defaults", "read", "-g", "AppleLanguages")
	} else {
		out, _, err = runAs(ctx, du, "/usr/bin/defaults", "read", "-g", "AppleLanguages")
	}
	if err == nil {
		// Output: ( "fr-FR", "en-US" )
		for _, field := range strings.FieldsFunc(out, func(r rune) bool { return r == '(' || r == ')' || r == ',' || r == '\n' }) {
			if v := strings.Trim(strings.TrimSpace(field), `"`); v != "" {
				return v
			}
		}
	}
	return "en-US"
}

// ShowMessage shows a dialog in the console user's session, in the user's language.
func ShowMessage(note Note) error {
	du := consoleUser()
	if du == nil {
		return errors.New("no user logged in on the console")
	}
	lang := userLanguage(du)
	title, text := note.Render(lang)
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()
	_, _, err := osascript(ctx, du, infoScript, title, text, tr(lang, "button.ok", nil))
	return err
}

// AskReply shows a dialog with a reply field; it returns the reply and the user name.
func AskReply(note Note) (string, string, error) {
	du := consoleUser()
	if du == nil {
		return "", "", errors.New("no user logged in on the console")
	}
	lang := userLanguage(du)
	title, text := note.Render(lang)
	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Minute)
	defer cancel()
	reply, code, err := osascript(ctx, du, replyScript, title, text, tr(lang, "button.close", nil),
		tr(lang, "button.reply", nil))
	if err != nil && code == 1 { // user cancelled (-128)
		return "", du.Name, nil
	}
	return strings.TrimSpace(reply), du.Name, err
}
