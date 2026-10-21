package main

import "testing"

func TestValidateInvocation(t *testing.T) {
	tests := []struct {
		name                    string
		dryRun, install, accept bool
		stage, rollback         string
		allowLightDMMaintenance bool
		wantError               bool
	}{
		{"dry run", true, false, false, "", "", false, false},
		{"install", false, true, false, "/var/lib/swbadge/stage", "/var/backups/stumpfworks-badge/rollback", false, false},
		{"accept", false, false, true, "", "/var/backups/stumpfworks-badge/rollback", false, false},
		{"no mode", false, false, false, "", "", false, true},
		{"multiple modes", true, true, false, "", "", false, true},
		{"install missing rollback", false, true, false, "/var/lib/swbadge/stage", "", false, true},
		{"relative install path", false, true, false, "stage", "/var/backups/swbadge/rollback", false, true},
		{"same directories", false, true, false, "/var/lib/swbadge/update", "/var/lib/swbadge/update", false, true},
		{"unmanaged rollback", false, true, false, "/var/lib/swbadge/stage", "/tmp/rollback", false, true},
		{"maintenance during dry run", true, false, false, "", "", true, true},
		{"accept with stage", false, false, true, "/var/lib/swbadge/stage", "/var/backups/stumpfworks-badge/rollback", false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateInvocation(test.dryRun, test.install, test.accept, test.stage, test.rollback, test.allowLightDMMaintenance)
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
