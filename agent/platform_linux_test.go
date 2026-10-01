// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/platform_linux_test.go
// Purpose : Tests of the Linux locale sources (AccountsService, pam_environment, /etc/default/locale)
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadKey(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"accounts": "[User]\nLanguage=fr_FR.UTF-8\nXSession=cinnamon\n",
		"pam":      "LANG DEFAULT=de_DE.UTF-8\n",
		"default":  "# comment\nexport LANG=\"es_ES.UTF-8\"\n",
		"empty":    "LANG=\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checks := []struct{ file, key, want string }{
		{"accounts", "Language", "fr_FR.UTF-8"}, {"pam", "LANG", "de_DE.UTF-8"},
		{"default", "LANG", "es_ES.UTF-8"}, {"empty", "LANG", ""}, {"missing", "LANG", ""},
	}
	for _, c := range checks {
		if got := readKey(filepath.Join(dir, c.file), c.key); got != c.want {
			t.Errorf("%s: got %q, want %q", c.file, got, c.want)
		}
	}
}
