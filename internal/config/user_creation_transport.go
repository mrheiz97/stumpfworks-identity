package config

import (
	"errors"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreateipc"
	"path/filepath"
	"strconv"
	"strings"
)

func (c Config) UserCreationTransport() (adcreateipc.Config, error) {
	if !c.ADUserCreationEnabled {
		return adcreateipc.Config{}, nil
	}
	denied := errors.New("user creation transport requires explicit protected AD/HTTPS, Unix path and identity pins")
	if !c.DirectoryEnabled || c.Demo || c.TLSCertFile == "" || c.TLSKeyFile == "" || c.DirectoryUserCreatorGroup == "" || c.DirectoryUserCreatorGroupGUID == "" || validateRoleGroups(c) != nil {
		return adcreateipc.Config{}, denied
	}
	path := c.ADUserCreationSocket
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 || strings.ContainsAny(path, "\x00\r\n") {
		return adcreateipc.Config{}, denied
	}
	values := []string{c.ADUserCreationExecutorUID, c.ADUserCreationExecutorGID, c.ADUserCreationSocketGID}
	pins := make([]uint32, 3)
	for index, value := range values {
		n, e := strconv.ParseUint(value, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != value {
			return adcreateipc.Config{}, denied
		}
		pins[index] = uint32(n)
	}
	return adcreateipc.Config{Enabled: true, Socket: path, Peer: &adcreateipc.Identity{UID: pins[0], GID: pins[1]}, Owner: &adcreateipc.Identity{UID: pins[0], GID: pins[2]}}, nil
}
