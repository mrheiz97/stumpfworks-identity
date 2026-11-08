//go:build !linux

package adcreateipc

import (
	"context"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"net"
)

func validateConfig(Config, bool) error              { return adcreate.ErrDenied }
func dial(context.Context, Config) (net.Conn, error) { return nil, adcreate.ErrDenied }

type Server struct{}

func Listen(Config, adcreate.Operations) (*Server, error) { return nil, adcreate.ErrDenied }
func (*Server) Serve() error                              { return adcreate.ErrDenied }
func (*Server) Close() error                              { return nil }
func (*Server) Shutdown(context.Context) error            { return adcreate.ErrDenied }
