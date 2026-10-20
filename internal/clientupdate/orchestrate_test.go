package clientupdate

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	calls  []string
	failAt string
}

func TestUpdateHealthCallbacksRecordSuccessAndRecoveredFailure(t *testing.T) {
	plan := StagePlan{ReleaseVersion: "1.2.1"}
	statePath := filepath.Join(t.TempDir(), "update-state.json")
	installedAt := time.Unix(100, 0).UTC()
	health, recovery := UpdateHealthCallbacks(context.Background(), plan, &fakeRunner{}, statePath, installedAt)
	if err := health(); err != nil {
		t.Fatal(err)
	}
	state, err := ReadUpdateState(statePath)
	if err != nil || state == nil || state.Status != "success" || state.Version != plan.ReleaseVersion {
		t.Fatalf("unexpected successful update state: %+v, %v", state, err)
	}
	if err = recovery(); err != nil {
		t.Fatal(err)
	}
	state, err = ReadUpdateState(statePath)
	if err != nil || state == nil || state.Status != "failed" || !state.RollbackAvailable {
		t.Fatalf("unexpected recovered failure state: %+v, %v", state, err)
	}
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if call == r.failAt {
		return errors.New("injected command failure")
	}
	return nil
}

func TestPostInstallHealthCheckSelectsRequiredCommands(t *testing.T) {
	plan := StagePlan{Components: []StagedComponent{{Component: "sw-badge-client-status"}, {Component: "swbadge-client-status.timer"}}}
	runner := &fakeRunner{}
	if err := PostInstallHealthCheck(context.Background(), plan, runner)(); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl daemon-reload", "systemctl start swbadge-client-status.service", "systemctl is-active swbadge-client-status.timer", "systemctl is-active lightdm.service"}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected commands: %v", runner.calls)
	}
}

func TestPostInstallHealthCheckPropagatesFailure(t *testing.T) {
	runner := &fakeRunner{failAt: "systemctl is-active swbadge-client-status.timer"}
	plan := StagePlan{Components: []StagedComponent{{Component: "sw-badge-client-status"}}}
	err := PostInstallHealthCheck(context.Background(), plan, runner)()
	if err == nil || !strings.Contains(err.Error(), "timer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGreeterPlanRequiresMaintenanceWindow(t *testing.T) {
	plan := StagePlan{Components: []StagedComponent{{Component: "sw-badge-native-greeter", RestartLightDM: true}}}
	if !RequiresLightDMMaintenance(plan) {
		t.Fatal("greeter update did not require maintenance")
	}
}

func TestGreeterHealthRestartsLightDM(t *testing.T) {
	plan := StagePlan{Components: []StagedComponent{{Component: "sw-badge-native-greeter", RestartLightDM: true}}}
	runner := &fakeRunner{}
	if err := PostInstallHealthCheck(context.Background(), plan, runner)(); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl restart lightdm.service", "systemctl try-restart swbadge-vnc.service", "systemctl is-active lightdm.service"}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected commands: %v", runner.calls)
	}
}

func TestInterruptedRecoveryDoesNotStartStatusServiceRecursively(t *testing.T) {
	plan := StagePlan{Components: []StagedComponent{{Component: "sw-badge-client-status"}, {Component: "swbadge-client-status.service"}}}
	runner := &fakeRunner{}
	if err := PostInterruptedRecovery(context.Background(), plan, runner)(); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl daemon-reload", "systemctl is-active swbadge-client-status.timer", "systemctl is-active lightdm.service"}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected commands: %v", runner.calls)
	}
}
