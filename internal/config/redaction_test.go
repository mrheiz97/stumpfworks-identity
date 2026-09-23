package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestConfigurationSecretsAreOpaque(t *testing.T) {
	const secret = "synthetic-secret-marker-not-real"
	value := Config{BindPassword: secret, SessionSecret: secret, MetricsToken: secret}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, value), secret) {
			t.Fatal("secret exposed by formatting")
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil || bytes.Contains(encoded, []byte(secret)) {
		t.Fatal("secret exposed by JSON")
	}
	var output bytes.Buffer
	slog.New(slog.NewJSONHandler(&output, nil)).Info("config", "value", value)
	if strings.Contains(output.String(), secret) {
		t.Fatal("secret exposed by structured logging")
	}
}
