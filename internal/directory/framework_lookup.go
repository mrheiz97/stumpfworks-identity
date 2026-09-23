package directory

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"os"

	frameworkldap "github.com/TheRealHZL/stumpfworks-framework/directory/ldap"
)

// WithFrameworkLookups uses this exact LDAP configuration for reads and keeps
// this LDAP instance for authentication/listing. Legacy SAN-bypass pinning must
// be removed only after the directory has a CA-trusted, hostname-valid cert.
func (d LDAP) WithFrameworkLookups() (Directory, error) {
	return d.WithFrameworkLookupsObserved(nil)
}

// WithFrameworkLookupsObserved additionally emits privacy-bounded framework
// observations. Authentication and listing remain on this exact LDAP adapter.
func (d LDAP) WithFrameworkLookupsObserved(observer frameworkldap.Observer) (Directory, error) {
	if d.CertSHA256 != "" {
		return nil, errors.New("framework directory requires CA and hostname verification, not legacy certificate pinning")
	}
	config := frameworkldap.Config{URL: d.URL, BaseDN: d.BaseDN, BindDN: d.BindDN, BindPassword: d.BindPassword, Observer: observer}
	if d.CAFile != "" {
		f, err := os.Open(d.CAFile)
		if err != nil {
			return nil, errors.New("directory CA file unavailable")
		}
		defer f.Close()
		const maxCABytes = 1 << 20
		pem, err := io.ReadAll(io.LimitReader(f, maxCABytes+1))
		if err != nil || len(pem) > maxCABytes {
			return nil, errors.New("directory CA file exceeds limits or cannot be read")
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			return nil, errors.New("directory system certificate roots unavailable")
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("directory CA file contains no certificates")
		}
		config.Roots = roots
	}
	return WithFrameworkUserLookup(d, config)
}

// WithFrameworkUserLookup stages verified, read-only AD/Samba lookups. Password
// authentication, admin policy and listing stay with the existing Directory.
// Production startup does not call this constructor yet.
func WithFrameworkUserLookup(existing Directory, config frameworkldap.Config) (Directory, error) {
	reader, err := frameworkldap.New(config)
	if err != nil {
		return nil, err
	}
	return WithUserLookup(existing, frameworkUserLookup(reader))
}

type frameworkUserReader interface {
	GetUser(context.Context, string) (*frameworkldap.User, error)
}

func frameworkUserLookup(reader frameworkUserReader) UserLookup {
	return func(ctx context.Context, username string) (*User, error) {
		u, err := reader.GetUser(ctx, username)
		if errors.Is(err, frameworkldap.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		if err != nil {
			// Unavailability and ambiguity are not missing-user results. Never
			// fall back to the permissive local directory on lookup failure.
			return nil, err
		}
		if u == nil || u.Username == "" {
			return nil, errors.New("framework directory returned invalid user")
		}
		return &User{Username: u.Username, DisplayName: u.DisplayName, DN: u.DN, Mail: u.Mail}, nil
	}
}
