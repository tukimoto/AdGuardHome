//go:build !linux

package ipset

import (
	"log/slog"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
)

func newManager(_ *slog.Logger, _ []string) (mgr Manager, err error) {
	return nil, aghos.Unsupported("ipset")
}
