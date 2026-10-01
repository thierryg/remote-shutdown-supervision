// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/platform_linux.go
// Purpose : Linux specifics: paths, uptime, OS name, power off, desktop popups (X11 / Wayland)
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultConfigPath is the configuration file installed by the Debian package.
func defaultConfigPath() string { return "/etc/rsd-agent/agent.json" }

// defaultStateDir holds the key and the certificates.
func defaultStateDir() string { return "/var/lib/rsd-agent" }

// bootUptime reads /proc/uptime.
func bootUptime() time.Duration {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// platformOSName returns PRETTY_NAME from /etc/os-release.
func platformOSName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return "Linux"
}

// powerOff halts the machine through systemd (force ignores inhibitors and other sessions).
func powerOff(force bool) error {
	args := []string{"poweroff"}
	if force {
		args = append(args, "-i")
	}
	if err := exec.Command("systemctl", args...).Run(); err == nil {
		return nil
	}
	return exec.Command("shutdown", "-h", "now").Run()
}

// graphicalUsers returns the users of the active graphical sessions (loginctl), each with
// the environment needed to reach its desktop (DISPLAY, WAYLAND_DISPLAY, D-Bus, XAUTHORITY).
func graphicalUsers() []*desktopUser {
	out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var users []*desktopUser
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		props, err := exec.Command("loginctl", "show-session", fields[0],
			"-p", "Name", "-p", "Type", "-p", "Display", "-p", "Active", "-p", "State", "-p", "Class").Output()
		if err != nil {
			continue
		}
		p := map[string]string{}
		for _, kv := range strings.Split(string(props), "\n") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				p[k] = v
			}
		}
		if p["Class"] != "user" || (p["Type"] != "x11" && p["Type"] != "wayland") || p["State"] == "closing" ||
			p["Name"] == "" || seen[p["Name"]] {
			continue
		}
		du, err := lookupDesktopUser(p["Name"])
		if err != nil {
			continue
		}
		seen[p["Name"]] = true
		runtimeDir := fmt.Sprintf("/run/user/%d", du.UID)
		display := p["Display"]
		if display == "" {
			display = ":0"
		}
		du.Env = []string{"DISPLAY=" + display, "XDG_RUNTIME_DIR=" + runtimeDir,
			"DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtimeDir + "/bus"}
		if sockets, _ := filepath.Glob(runtimeDir + "/wayland-[0-9]"); len(sockets) > 0 {
			du.Env = append(du.Env, "WAYLAND_DISPLAY="+filepath.Base(sockets[0]))
		}
		for _, xa := range []string{runtimeDir + "/gdm/Xauthority", du.Home + "/.Xauthority"} {
			if _, err := os.Stat(xa); err == nil {
				du.Env = append(du.Env, "XAUTHORITY="+xa)
				break
			}
		}
		// Active sessions first: they get the reply dialog of a chat message.
		if p["Active"] == "yes" {
			users = append([]*desktopUser{du}, users...)
		} else {
			users = append(users, du)
		}
	}
	return users
}

// currentUserSession is used when the agent runs unprivileged (development): the popup goes
// to the caller's own desktop.
func currentUserSession() []*desktopUser {
	if os.Geteuid() == 0 {
		return nil
	}
	du := &desktopUser{Name: os.Getenv("USER"), UID: os.Getuid(), GID: os.Getgid(), Home: os.Getenv("HOME")}
	for _, k := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XAUTHORITY"} {
		if v := os.Getenv(k); v != "" {
			du.Env = append(du.Env, k+"="+v)
		}
	}
	return []*desktopUser{du}
}

// sessions returns the desktop sessions to notify.
func sessions() []*desktopUser {
	if s := currentUserSession(); s != nil {
		return s
	}
	return graphicalUsers()
}

// pangoEscape escapes the markup characters for notify-send.
func pangoEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// readKey returns the value of KEY=value in a file (quotes removed), or "".
func readKey(file, key string) string {
	data, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			if f := strings.Fields(v); len(f) > 0 {
				return strings.Trim(f[0], `"'`)
			}
			return ""
		}
		if v, ok := strings.CutPrefix(line, key+" DEFAULT="); ok { // ~/.pam_environment syntax
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// userLanguage returns the language of a desktop user: AccountsService (set by the GNOME,
// Cinnamon/Mint, KDE and MATE settings), ~/.pam_environment, then the system locale.
func userLanguage(du *desktopUser) string {
	if os.Geteuid() != 0 {
		for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
			if v := os.Getenv(k); v != "" {
				return v
			}
		}
	}
	candidates := []struct{ file, key string }{
		{"/var/lib/AccountsService/users/" + du.Name, "Language"},
		{du.Home + "/.config/locale.conf", "LANG"},
		{du.Home + "/.pam_environment", "LANG"},
		{"/etc/default/locale", "LANG"},
		{"/etc/locale.conf", "LANG"},
	}
	for _, c := range candidates {
		if v := readKey(c.file, c.key); v != "" {
			return v
		}
	}
	return "en_US.UTF-8"
}

var (
	zenityOnce  sync.Once
	zenityMajor int
)

// zenityVersion returns the major version of zenity: 4 is libadwaita (GTK 4), 3 is GTK 3;
// 0 when zenity is missing.
func zenityVersion() int {
	zenityOnce.Do(func() {
		out, err := exec.Command("zenity", "--version").Output()
		if err != nil {
			return
		}
		zenityMajor, _ = strconv.Atoi(strings.SplitN(strings.TrimSpace(string(out)), ".", 2)[0])
		if zenityMajor == 0 { // some builds print nothing without a display: assume GTK 3
			zenityMajor = 3
		}
	})
	return zenityMajor
}

// themeEnv returns the environment that makes the dialogs follow the user's light/dark choice
// (checked on real zenity 3 and 4 renderings). libadwaita (zenity 4) gets the color scheme
// (ADW_DEBUG_COLOR_SCHEME; GTK_THEME would break its style); GTK 3 (zenity 3, Ubuntu 22.04 /
// Mint 21) only knows theme names, so a dark color scheme with a light theme name selects the
// dark variant of that theme.
func themeEnv(du *desktopUser) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	scheme, _, _ := runAs(ctx, du, "gsettings", "get", "org.gnome.desktop.interface", "color-scheme")
	theme, _, _ := runAs(ctx, du, "gsettings", "get", "org.gnome.desktop.interface", "gtk-theme")
	scheme, theme = strings.Trim(scheme, "' \n"), strings.Trim(theme, "' \n")
	darkTheme := strings.Contains(strings.ToLower(theme), "dark")
	if scheme != "prefer-dark" && !darkTheme {
		return nil
	}
	if zenityVersion() >= 4 {
		return []string{"ADW_DEBUG_COLOR_SCHEME=prefer-dark"}
	}
	if theme != "" && !darkTheme {
		return []string{"GTK_THEME=" + theme + ":dark"}
	}
	return nil
}

// localized returns a copy of du whose environment carries its language and theme, plus the
// language itself.
func localized(du *desktopUser) (*desktopUser, string) {
	lang := userLanguage(du)
	copyDU := *du
	copyDU.Env = append(append(append([]string{}, du.Env...), "LANG="+lang, "LANGUAGE="+strings.SplitN(lang, ".", 2)[0]),
		themeEnv(du)...)
	return &copyDU, lang
}

// ShowMessage shows an information dialog on every graphical session (zenity, kdialog or
// notify-send) in the language and the light/dark theme of its user, falling back to wall(1)
// on text consoles.
func ShowMessage(note Note) error {
	users := sessions()
	if len(users) == 0 {
		title, text := note.Render(userLanguage(&desktopUser{}))
		return exec.Command("wall", title+": "+text).Run()
	}
	var lastErr error
	for _, raw := range users {
		du, lang := localized(raw)
		title, text := note.Render(lang)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		_, _, err := runAs(ctx, du, "zenity", "--info", "--no-markup", "--title", title, "--text", text, "--width", "420")
		if err != nil && ctx.Err() == nil {
			_, _, err = runAs(ctx, du, "kdialog", "--title", title, "--msgbox", text)
		}
		if err != nil && ctx.Err() == nil {
			_, _, err = runAs(ctx, du, "notify-send", "-u", "critical", "-a", "rsd-agent", title, pangoEscape(text))
		}
		cancel()
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// AskReply shows a message with a reply field on the active session (its language and theme);
// it returns the reply (empty when the user closed the dialog) and the local user name.
func AskReply(note Note) (string, string, error) {
	users := sessions()
	if len(users) == 0 {
		return "", "", ShowMessage(note)
	}
	du, lang := localized(users[0])
	title, text := note.Render(lang)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	reply, code, err := runAs(ctx, du, "zenity", "--entry", "--title", title, "--text", text, "--width", "420",
		"--ok-label", tr(lang, "button.reply", nil), "--cancel-label", tr(lang, "button.close", nil))
	if err == nil {
		return strings.TrimSpace(reply), du.Name, nil
	}
	if code == 1 { // dialog closed / cancelled
		return "", du.Name, nil
	}
	if ctx.Err() == nil {
		reply, code, err = runAs(ctx, du, "kdialog", "--title", title, "--inputbox", text)
		if err == nil {
			return strings.TrimSpace(reply), du.Name, nil
		}
		if code == 1 {
			return "", du.Name, nil
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", du.Name, nil
	}
	return "", du.Name, ShowMessage(note)
}
