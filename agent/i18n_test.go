// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/i18n_test.go
// Purpose : Tests of the agent localization: locale completeness, OS locale matching, rendering
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"regexp"
	"sort"
	"testing"
)

var placeholder = regexp.MustCompile(`\{\w+\}`)

func TestEveryLocaleHasTheReferenceKeys(t *testing.T) {
	all := loadLocales()
	if len(all) != 12 {
		t.Fatalf("expected 12 locales, got %d", len(all))
	}
	ref := all[referenceLocale]
	for code, table := range all {
		if len(table) != len(ref) {
			t.Errorf("%s: %d keys, reference has %d", code, len(table), len(ref))
		}
		for key, text := range ref {
			got, ok := table[key]
			if !ok || got == "" {
				t.Errorf("%s: missing %s", code, key)
				continue
			}
			want, have := placeholder.FindAllString(text, -1), placeholder.FindAllString(got, -1)
			sort.Strings(want)
			sort.Strings(have)
			if len(want) != len(have) {
				t.Errorf("%s/%s: placeholders %v, reference %v", code, key, have, want)
			}
		}
	}
}

func TestMatchLocale(t *testing.T) {
	cases := map[string]string{
		"fr_FR.UTF-8": "fr", "de-DE": "de", "zh-Hans-CN": "zh", "pt_BR.UTF-8": "en-US", "C": "en-US",
		"C.UTF-8": "en-US", "en_GB.UTF-8": "en-US", "ja": "ja", "sr_RS@latin": "en-US", "fr:en": "fr", "": "en-US",
	}
	for in, want := range cases {
		if got := matchLocale(in); got != want {
			t.Errorf("matchLocale(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNoteRender(t *testing.T) {
	title, text := Note{Key: "shutdown.default", Params: map[string]any{"seconds": 30}}.Render("fr_FR.UTF-8")
	if title != "Remote Shutdown" || text != "Cet ordinateur va s'éteindre dans 30 secondes." {
		t.Fatalf("got %q / %q", title, text)
	}
	// Free text typed by the administrator is shown as is; the title is still localized.
	title, text = Note{Text: "Dîner !", TitleKey: "chat.from", TitleParams: map[string]any{"author": "papa"}}.Render("de")
	if title != "Nachricht von papa" || text != "Dîner !" {
		t.Fatalf("got %q / %q", title, text)
	}
	// An unknown key (newer master) falls back to the English text it sent.
	if _, text = (Note{Key: "future.key", Text: "fallback"}).Render("ja"); text != "fallback" {
		t.Fatalf("got %q", text)
	}
}
