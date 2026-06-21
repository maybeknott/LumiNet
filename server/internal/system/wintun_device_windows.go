//go:build windows

package system

import (
	"errors"

	"golang.org/x/sys/windows"
)

type wintunDevice struct {
	adapter *wintunAdapter
	session *wintunSession
	event   windows.Handle
}

func newWintunDevice(name string) (*wintunDevice, error) {
	// Create adapter
	adapter, err := createWintunAdapter(name, "Wintun", nil)
	if err != nil {
		return nil, err
	}

	// Start session with default ring capacity
	session, err := adapter.StartSession(0x100000) // 1 MiB
	if err != nil {
		adapter.Close()
		return nil, err
	}

	event := session.ReadWaitEvent()
	return &wintunDevice{
		adapter: adapter,
		session: session,
		event:   event,
	}, nil
}

func (d *wintunDevice) Read(buf []byte) (int, error) {
	for {
		packet, err := d.session.ReceivePacket()
		if err == nil {
			n := copy(buf, packet)
			d.session.ReleaseReceivePacket(packet)
			return n, nil
		}

		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			_, errWait := windows.WaitForSingleObject(d.event, windows.INFINITE)
			if errWait != nil {
				return 0, errWait
			}
			continue
		}
		return 0, err
	}
}

func (d *wintunDevice) Write(buf []byte) (int, error) {
	packet, err := d.session.AllocateSendPacket(len(buf))
	if err != nil {
		return 0, err
	}
	copy(packet, buf)
	d.session.SendPacket(packet)
	return len(buf), nil
}

func (d *wintunDevice) Close() error {
	if d.session != nil {
		d.session.End()
		d.session = nil
	}
	if d.adapter != nil {
		err := d.adapter.Close()
		d.adapter = nil
		return err
	}
	return nil
}
