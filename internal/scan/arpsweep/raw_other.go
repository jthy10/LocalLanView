//go:build !linux && !darwin && !windows

package arpsweep

import (
	"context"
	"errors"
	"net"

	"github.com/jthy10/LocalLanView/internal/scan"
)

const resolverOnly = false

func resolveAll(context.Context, *scan.Env, func(scan.Observation)) error { return nil }

func Open(net.Interface) (Transport, error) {
	return nil, errors.New("raw ARP isn't supported on this OS")
}
