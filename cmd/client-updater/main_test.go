package main

import "testing"

func TestValidateInvocation(t *testing.T) {
	tests := []struct {
		name                    string
		dryRun, install         bool
		stage, rollback         string
		allowLightDMMaintenance bool
		wantError               bool
	}{
		{"dry run", true, false, "", "", false, false},
		{"install", false, true, "/var/lib/swbadge/stage", "/var/backups/stumpfworks-badge/rollback", false, false},
		{"no mode", false, false, "", "", false, true},
		{"both modes", true, true, "", "", false, true},
		{"install missing rollback", false, true, "/var/lib/swbadge/stage", "", false, true},
		{"relative install path", false, true, "stage", "/var/backups/swbadge/rollback", false, true},
		{"same directories", false, true, "/var/lib/swbadge/update", "/var/lib/swbadge/update", false, true},
		{"unmanaged rollback", false, true, "/var/lib/swbadge/stage", "/tmp/rollback", false, true},
		{"maintenance during dry run", true, false, "", "", true, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateInvocation(test.dryRun, test.install, test.stage, test.rollback, test.allowLightDMMaintenance)
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
