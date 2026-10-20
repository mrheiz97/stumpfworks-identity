package clientupdate

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = nil
	command.Stderr = nil
	return command.Run()
}

func PostInstallHealthCheck(parent context.Context, plan StagePlan, runner CommandRunner) func() error {
	return serviceHealthCheck(parent, plan, runner, RequiresLightDMMaintenance(plan))
}

func PostRollbackRecovery(parent context.Context, plan StagePlan, runner CommandRunner) func() error {
	return serviceHealthCheck(parent, plan, runner, RequiresLightDMMaintenance(plan))
}

// PostInterruptedRecovery runs from the status service's ExecStartPre. It must
// not start that same service recursively; ExecStart proceeds after recovery.
func PostInterruptedRecovery(parent context.Context, plan StagePlan, runner CommandRunner) func() error {
	return func() error {
		if runner == nil {
			return errors.New("health-check command runner is required")
		}
		ctx, cancel := context.WithTimeout(parent, 30*time.Second)
		defer cancel()
		hasSystemdUnit, hasStatusComponent := false, false
		for _, component := range plan.Components {
			switch component.Component {
			case "swbadge-client-status.service", "swbadge-client-status.timer":
				hasSystemdUnit = true
			case "sw-badge-client-status":
				hasStatusComponent = true
			}
		}
		if hasSystemdUnit {
			if err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
				return fmt.Errorf("systemd daemon-reload: %w", err)
			}
		}
		if hasSystemdUnit || hasStatusComponent {
			if err := runner.Run(ctx, "systemctl", "is-active", "swbadge-client-status.timer"); err != nil {
				return fmt.Errorf("client status timer: %w", err)
			}
		}
		if RequiresLightDMMaintenance(plan) {
			if err := runner.Run(ctx, "systemctl", "restart", "lightdm.service"); err != nil {
				return fmt.Errorf("LightDM restart: %w", err)
			}
			if err := runner.Run(ctx, "systemctl", "try-restart", "swbadge-vnc.service"); err != nil {
				return fmt.Errorf("VNC rebind: %w", err)
			}
		}
		if err := runner.Run(ctx, "systemctl", "is-active", "lightdm.service"); err != nil {
			return fmt.Errorf("LightDM health: %w", err)
		}
		return nil
	}
}

// UpdateHealthCallbacks couples the transactional health checks to the bounded
// state reported by the client-status agent. A failed installation records its
// failure only after the previous files have been restored.
func UpdateHealthCallbacks(parent context.Context, plan StagePlan, runner CommandRunner, statePath string, installedAt time.Time) (func() error, func() error) {
	health := func() error {
		if err := WriteUpdateState(statePath, UpdateState{Version: plan.ReleaseVersion, Status: "success", UpdatedAt: installedAt, RollbackAvailable: true}); err != nil {
			return err
		}
		return PostInstallHealthCheck(parent, plan, runner)()
	}
	recovery := func() error {
		if err := WriteUpdateState(statePath, UpdateState{Version: plan.ReleaseVersion, Status: "failed", UpdatedAt: installedAt, RollbackAvailable: true}); err != nil {
			return err
		}
		return PostRollbackRecovery(parent, plan, runner)()
	}
	return health, recovery
}

func serviceHealthCheck(parent context.Context, plan StagePlan, runner CommandRunner, restartLightDM bool) func() error {
	return func() error {
		if runner == nil {
			return errors.New("health-check command runner is required")
		}
		ctx, cancel := context.WithTimeout(parent, 30*time.Second)
		defer cancel()
		hasSystemdUnit, hasStatusComponent := false, false
		for _, component := range plan.Components {
			switch component.Component {
			case "swbadge-client-status.service", "swbadge-client-status.timer":
				hasSystemdUnit = true
			case "sw-badge-client-status":
				hasStatusComponent = true
			}
		}
		if hasSystemdUnit {
			if err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
				return fmt.Errorf("systemd daemon-reload: %w", err)
			}
		}
		if hasSystemdUnit || hasStatusComponent {
			if err := runner.Run(ctx, "systemctl", "start", "swbadge-client-status.service"); err != nil {
				return fmt.Errorf("client status report: %w", err)
			}
			if err := runner.Run(ctx, "systemctl", "is-active", "swbadge-client-status.timer"); err != nil {
				return fmt.Errorf("client status timer: %w", err)
			}
		}
		if restartLightDM {
			if err := runner.Run(ctx, "systemctl", "restart", "lightdm.service"); err != nil {
				return fmt.Errorf("LightDM restart: %w", err)
			}
			if err := runner.Run(ctx, "systemctl", "try-restart", "swbadge-vnc.service"); err != nil {
				return fmt.Errorf("VNC rebind: %w", err)
			}
		}
		if err := runner.Run(ctx, "systemctl", "is-active", "lightdm.service"); err != nil {
			return fmt.Errorf("LightDM health: %w", err)
		}
		return nil
	}
}
