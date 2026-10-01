// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/i18n.go
// Purpose : Localization of the agent dialogs in the language of the desktop user (12 locales)
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"sync"
)

// The translation tables are embedded: the agent stays a single standalone binary.
//
//go:embed i18n/*.json
var localeFS embed.FS

// referenceLocale is complete and used as the fallback of every other locale.
const referenceLocale = "en-US"

var (
	localesOnce sync.Once
	locales     map[string]map[string]string
)

// loadLocales parses the embedded tables once.
func loadLocales() map[string]map[string]string {
	localesOnce.Do(func() {
		locales = map[string]map[string]string{}
		entries, _ := localeFS.ReadDir("i18n")
		for _, e := range entries {
			data, err := localeFS.ReadFile(path.Join("i18n", e.Name()))
			if err != nil {
				continue
			}
			table := map[string]string{}
			if json.Unmarshal(data, &table) == nil {
				locales[strings.TrimSuffix(e.Name(), ".json")] = table
			}
		}
	})
	return locales
}

// matchLocale maps an OS locale (fr_FR.UTF-8, zh-Hans-CN, en-GB, C...) to a supported locale.
func matchLocale(lang string) string {
	lang = strings.TrimSpace(lang)
	if i := strings.IndexAny(lang, ".@:"); i >= 0 { // fr_FR.UTF-8, sr_RS@latin, fr:en (LANGUAGE)
		lang = lang[:i]
	}
	lang = strings.ReplaceAll(lang, "_", "-")
	short := strings.ToLower(strings.SplitN(lang, "-", 2)[0])
	if short == "" || short == "c" || short == "posix" || short == "en" {
		return referenceLocale
	}
	if _, ok := loadLocales()[short]; ok {
		return short
	}
	return referenceLocale
}

// tr returns the text of key in the given OS language, with {name} placeholders replaced.
// Unknown keys return "" so that the caller can fall back to the text sent by the master.
func tr(lang, key string, params map[string]any) string {
	all := loadLocales()
	text, ok := all[matchLocale(lang)][key]
	if !ok || text == "" {
		if text, ok = all[referenceLocale][key]; !ok {
			return ""
		}
	}
	for name, value := range params {
		text = strings.ReplaceAll(text, "{"+name+"}", fmt.Sprint(value))
	}
	return text
}

// Note is a message to show on the desktop; it is rendered per session, in the language of
// the user of that session.
type Note struct {
	// Key is an i18n key (shutdown.default, policy.warning...); empty for free text.
	Key string
	// Params fills the {placeholders} of Key.
	Params map[string]any
	// Text is shown when Key is empty or unknown (free text typed by the administrator).
	Text string
	// TitleKey / TitleParams localize the window title (default "title").
	TitleKey    string
	TitleParams map[string]any
}

// Render returns the title and the text of the note in lang.
func (n Note) Render(lang string) (string, string) {
	titleKey := n.TitleKey
	if titleKey == "" {
		titleKey = "title"
	}
	title := tr(lang, titleKey, n.TitleParams)
	text := n.Text
	if n.Key != "" {
		if localized := tr(lang, n.Key, n.Params); localized != "" {
			text = localized
		}
	}
	return title, text
}
