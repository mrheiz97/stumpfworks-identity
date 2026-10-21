package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/clientupdate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/version"
)

func main() {
	packageFile := flag.String("package", "", "local signed update ZIP")
	publicKeyFile := flag.String("public-key", "", "trusted Ed25519 public-key file")
	architecture := flag.String("architecture", "", "expected OS-architecture (defaults to current platform)")
	stageDir := flag.String("stage-dir", "", "optional new directory for verified payload staging")
	dryRun := flag.Bool("dry-run", false, "verify without installing")
	install := flag.Bool("install", false, "install a verified package with automatic rollback")
	accept := flag.Bool("accept", false, "verify signed release, installed files, rollback and service health")
	rollbackDir := flag.String("rollback-dir", "", "new rollback directory required for installation")
	allowLightDMMaintenance := flag.Bool("allow-lightdm-maintenance", false, "allow a greeter update to restart LightDM")
	recoverPending := flag.Bool("recover-pending", false, "recover an interrupted installation from its validated rollback")
	show := flag.Bool("version", false, "show version")
	flag.Parse()
	if *show {
		fmt.Println("sw-badge-client-updater", version.Version)
		return
	}
	if *recoverPending {
		if flag.NArg() != 0 || *dryRun || *install || *accept || *packageFile != "" || *publicKeyFile != "" || *stageDir != "" || *rollbackDir != "" || *allowLightDMMaintenance {
			fatal("recovery cannot be combined with package or installation options")
		}
		recovered, err := clientupdate.RecoverPendingUpdate(context.Background(), "/", clientupdate.DefaultTransactionPath, clientupdate.DefaultStatePath, clientupdate.ExecRunner{})
		if err != nil {
			fatal(err.Error())
		}
		if recovered {
			fmt.Println("recovered interrupted client update")
		}
		return
	}
	if err := validateInvocation(*dryRun, *install, *accept, *stageDir, *rollbackDir, *allowLightDMMaintenance); err != nil {
		fatal(err.Error())
	}
	if *packageFile == "" || *publicKeyFile == "" {
		fatal("package and public key are required")
	}
	publicKey, err := clientupdate.LoadPublicKey(*publicKeyFile)
	if err != nil {
		fatal(err.Error())
	}
	if *install {
		plan, err := clientupdate.VerifyAndStage(*packageFile, publicKey, *architecture, version.Version, *stageDir)
		if err != nil {
			fatal(err.Error())
		}
		runner := clientupdate.ExecRunner{}
		installedAt := time.Now().UTC()
		health, recovery := clientupdate.UpdateHealthCallbacks(context.Background(), plan, runner, clientupdate.DefaultStatePath, installedAt)
		if err = clientupdate.InstallStagedWithTransaction("/", *stageDir, *rollbackDir, clientupdate.DefaultTransactionPath, installedAt, *allowLightDMMaintenance, health, recovery); err != nil {
			fatal(err.Error())
		}
		fmt.Printf("installed release=%s components=%d rollback=%s\n", plan.ReleaseVersion, len(plan.Components), *rollbackDir)
		return
	}
	if *accept {
		result, err := clientupdate.VerifyPackage(*packageFile, publicKey, *architecture, "")
		if err != nil {
			fatal(err.Error())
		}
		plan, err := clientupdate.VerifyReleaseAcceptance("/", result, *rollbackDir)
		if err != nil {
			fatal(err.Error())
		}
		if err = clientupdate.ReleaseAcceptanceHealthCheck(context.Background(), plan, clientupdate.ExecRunner{}); err != nil {
			fatal(err.Error())
		}
		fmt.Printf("accepted release=%s components=%d rollback=%s\n", result.Manifest.ReleaseVersion, len(plan.Components), *rollbackDir)
		return
	}
	result, err := clientupdate.VerifyPackage(*packageFile, publicKey, *architecture, version.Version)
	if err != nil {
		fatal(err.Error())
	}
	if *stageDir != "" {
		plan, err := clientupdate.VerifyAndStage(*packageFile, publicKey, *architecture, version.Version, *stageDir)
		if err != nil {
			fatal(err.Error())
		}
		fmt.Printf("staged directory=%s components=%d restart_lightdm=%t\n", *stageDir, len(plan.Components), clientupdate.RequiresLightDMMaintenance(plan))
	}
	fmt.Printf("verified release=%s channel=%s architecture=%s files=%d\n", result.Manifest.ReleaseVersion, result.Manifest.Channel, result.Manifest.Architecture, len(result.Files))
}

func validateInvocation(dryRun, install, accept bool, stageDir, rollbackDir string, allowLightDMMaintenance bool) error {
	modes := 0
	for _, enabled := range []bool{dryRun, install, accept} {
		if enabled {
			modes++
		}
	}
	if modes != 1 {
		return fmt.Errorf("exactly one of --dry-run, --install or --accept is required")
	}
	if dryRun {
		if rollbackDir != "" || allowLightDMMaintenance {
			return fmt.Errorf("rollback and LightDM maintenance options require --install")
		}
		return nil
	}
	if accept {
		if stageDir != "" || allowLightDMMaintenance {
			return fmt.Errorf("staging and LightDM maintenance options cannot be used with --accept")
		}
		return validateManagedRollback(rollbackDir)
	}
	if stageDir == "" || rollbackDir == "" {
		return fmt.Errorf("--install requires --stage-dir and --rollback-dir")
	}
	if !path.IsAbs(stageDir) || !path.IsAbs(rollbackDir) {
		return fmt.Errorf("installation stage and rollback directories must be absolute paths")
	}
	if path.Clean(stageDir) == path.Clean(rollbackDir) {
		return fmt.Errorf("stage and rollback directories must differ")
	}
	return validateManagedRollback(rollbackDir)
}

func validateManagedRollback(rollbackDir string) error {
	if !path.IsAbs(rollbackDir) {
		return fmt.Errorf("rollback directory must be absolute")
	}
	cleanRollback := path.Clean(rollbackDir)
	if !strings.HasPrefix(cleanRollback, "/var/backups/stumpfworks-badge/") {
		return fmt.Errorf("rollback directory must be below /var/backups/stumpfworks-badge")
	}
	return nil
}

func fatal(message string) { fmt.Fprintln(os.Stderr, "client updater:", message); os.Exit(1) }
