//go:build !windows

package system

import "errors"

type WFPSession struct{}

func StartWFPBlocker() (*WFPSession, error) {
	return nil, errors.New("WFP blocker is not supported on this platform")
}

func (s *WFPSession) Close() {}
