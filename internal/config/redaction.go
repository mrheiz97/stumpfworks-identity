package config

import "log/slog"

// Config may contain session, directory, and metrics credentials. Keep common
// formatting and structured logging opaque even when startup validation fails.
func (Config) String() string               { return "Identity configuration [REDACTED]" }
func (c Config) GoString() string           { return c.String() }
func (c Config) LogValue() slog.Value       { return slog.StringValue(c.String()) }
func (Config) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
