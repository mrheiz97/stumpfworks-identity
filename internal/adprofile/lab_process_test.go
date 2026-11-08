package adprofile

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Actual process and Unix-socket boundary, with the synthetic networkless DC.
func testSambaExecutorProcess(t *testing.T, c Config, password, target string) {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal(e)
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(root, name)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	disabled := write("disabled.json", []byte(`{"Directory":{"Enabled":false}}`))
	binary := "/workspace/dist/ad-profile-tests/executor"
	if out, e := exec.Command(binary, "--config", disabled).CombinedOutput(); e != nil || !bytes.Contains(out, []byte("disabled")) {
		t.Fatal("disabled executor touched dependencies")
	}
	dbPath := filepath.Join(root, "journal.db")
	cfg := struct {
		Directory                             Config
		Driver, DatabaseFile, KeyFile, Socket string
	}{c, "sqlite", write("dsn", []byte(dbPath)), write("key", key), filepath.Join(root, "executor.sock")}
	raw, _ := json.Marshal(cfg)
	path := write("executor.json", raw)
	if _, e := exec.Command(binary, "--config", path, "--initialize-journal").CombinedOutput(); e != nil {
		t.Fatal("explicit journal initialization failed")
	}
	cmd := exec.Command(binary, "--config", path)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	for i := 0; i < 100; i++ {
		if _, e := os.Stat(cfg.Socket); e == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", cfg.Socket)
	}}
	defer transport.CloseIdleConnections()
	call := func(action string) (int, Response) {
		t.Helper()
		body, _ := json.Marshal(Request{Action: action, Username: "operator", Password: password, ID: testID, Target: target, Changes: Values{"displayName": {"blocked process change"}}})
		response, e := (&http.Client{Transport: transport, Timeout: 20 * time.Second}).Post("http://executor/operation", "application/json", bytes.NewReader(body))
		if e != nil {
			t.Fatal("executor socket unavailable")
		}
		defer response.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(response.Body, 16384))
		var result Response
		if json.Unmarshal(b, &result) != nil {
			t.Fatal("invalid bounded response")
		}
		if bytes.Contains(b, []byte(password)) {
			t.Fatal("credential leaked")
		}
		return response.StatusCode, result
	}
	if status, result := call("read"); status != 200 || len(result.Before) != 4 {
		t.Fatal("real process read/step-up failed")
	}
	if status, _ := call("prepare"); status != 409 {
		t.Fatal("missing CAS bypassed through socket")
	}
	db, e := sql.Open("sqlite", dbPath)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var count int
	if e = db.QueryRow(`SELECT count(*) FROM ad_profile_operations`).Scan(&count); e != nil || count != 0 {
		t.Fatal("process queued unsupported write")
	}
	if e = db.QueryRow(`SELECT count(*) FROM ad_profile_audit WHERE event='denied'`).Scan(&count); e != nil || count != 1 {
		t.Fatal("process denial not durable")
	}
	// A second executor must not perform startup recovery while this one runs.
	if e = exec.Command(binary, "--config", path).Run(); e == nil {
		t.Fatal("concurrent executor accepted")
	}
}
