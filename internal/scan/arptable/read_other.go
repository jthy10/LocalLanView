//go:build !linux && !darwin && !windows

package arptable

import "errors"

const supported = false

func Read() ([]Entry, error) { return nil, errors.New("not supported on this OS") }
