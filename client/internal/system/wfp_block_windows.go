//go:build windows

package system

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0  = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0 = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmFilterAdd0   = modfwpuclnt.NewProc("FwpmFilterAdd0")
)

const (
	FWPM_SESSION_FLAG_DYNAMIC = 0x00000001
	FWP_ACTION_FLAG_TERMINATING = 0x00001000
	FWP_ACTION_BLOCK            = 0x00000001 | FWP_ACTION_FLAG_TERMINATING
	FWP_ACTION_PERMIT           = 0x00000002 | FWP_ACTION_FLAG_TERMINATING
	FWP_MATCH_EQUAL           = 0
	FWP_UINT8                 = 1
	FWP_UINT16                = 2
	FWP_UINT32                = 3
	IPPROTO_UDP               = 17
)

var (
	FWPM_LAYER_ALE_AUTH_CONNECT_V4 = windows.GUID{
		Data1: 0xc38d57d1,
		Data2: 0x05ea,
		Data3: 0x4d30,
		Data4: [8]byte{0x90, 0xf4, 0x8f, 0xde, 0xc0, 0x01, 0x00, 0x3f},
	}

	FWPM_SUBLAYER_UNIVERSAL = windows.GUID{
		Data1: 0xe0b4a450,
		Data2: 0xef80,
		Data3: 0x4be6,
		Data4: [8]byte{0x94, 0x67, 0x33, 0xf7, 0xcc, 0xfc, 0x53, 0x96},
	}

	FWPM_CONDITION_IP_REMOTE_PORT = windows.GUID{
		Data1: 0xc35a3630,
		Data2: 0x3cc3,
		Data3: 0x4bc7,
		Data4: [8]byte{0xb8, 0x73, 0x45, 0x5b, 0x57, 0xf0, 0x0b, 0xf7},
	}

	FWPM_CONDITION_IP_PROTOCOL = windows.GUID{
		Data1: 0x1e4d0d0c,
		Data2: 0x6685,
		Data3: 0x45ec,
		Data4: [8]byte{0xbf, 0x30, 0x5b, 0xe1, 0x32, 0x80, 0x14, 0x5c},
	}

	FWPM_CONDITION_IP_LOCAL_INTERFACE = windows.GUID{
		Data1: 0xcf1076b1,
		Data2: 0x0941,
		Data3: 0x4774,
		Data4: [8]byte{0x8b, 0x9a, 0x7c, 0x98, 0x07, 0x57, 0xd5, 0x98},
	}
)

type FWPM_DISPLAY_DATA0 struct {
	Name        *uint16
	Description *uint16
}

type FWPM_SESSION0 struct {
	SessionKey           windows.GUID
	DisplayData          FWPM_DISPLAY_DATA0
	Flags                uint32
	TxnWaitTimeoutInMSec uint32
	ProcessId            uint32
	Sid                  uintptr
	Username             *uint16
	KernelMode           int32
}

type FWP_VALUE0 struct {
	Type  uint32
	Value uintptr
}

type FWPM_FILTER_CONDITION0 struct {
	FieldKey       windows.GUID
	MatchType      uint32
	ConditionValue FWP_VALUE0
}

type FWPM_ACTION0 struct {
	Type  uint32
	Value windows.GUID
}

type FWP_BYTE_BLOB struct {
	Size uint32
	Data *byte
}

type FWPM_FILTER0 struct {
	FilterKey           windows.GUID
	DisplayData         FWPM_DISPLAY_DATA0
	Flags               uint32
	ProviderKey         *windows.GUID
	ProviderData        FWP_BYTE_BLOB
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	Weight              FWP_VALUE0
	NumFilterConditions uint32
	FilterCondition     *FWPM_FILTER_CONDITION0
	Action              FWPM_ACTION0
	Offset1             [4]byte
	Context             windows.GUID
	Reserved            *windows.GUID
	FilterId            uint64
	EffectiveWeight     FWP_VALUE0
}

type WFPSession struct {
	handle uintptr
}

func FwpmEngineOpen0(serverName *uint16, authnService uint32, authIdentity uintptr, session *FWPM_SESSION0, engineHandle unsafe.Pointer) uint32 {
	r1, _, _ := syscall.Syscall6(procFwpmEngineOpen0.Addr(), 5,
		uintptr(unsafe.Pointer(serverName)),
		uintptr(authnService),
		authIdentity,
		uintptr(unsafe.Pointer(session)),
		uintptr(engineHandle),
		0)
	return uint32(r1)
}

func FwpmEngineClose0(engineHandle uintptr) uint32 {
	r1, _, _ := syscall.Syscall(procFwpmEngineClose0.Addr(), 1,
		engineHandle,
		0,
		0)
	return uint32(r1)
}

func FwpmFilterAdd0(engineHandle uintptr, filter *FWPM_FILTER0, sd uintptr, id *uint64) uint32 {
	r1, _, _ := syscall.Syscall6(procFwpmFilterAdd0.Addr(), 4,
		engineHandle,
		uintptr(unsafe.Pointer(filter)),
		sd,
		uintptr(unsafe.Pointer(id)),
		0,
		0)
	return uint32(r1)
}

func findTunInterfaceIndex() uint32 {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, iface := range ifaces {
		lowerName := strings.ToLower(iface.Name)
		if strings.Contains(lowerName, "wintun") || strings.Contains(lowerName, "luminet") || strings.Contains(lowerName, "tap") {
			return uint32(iface.Index)
		}
	}
	return 0
}

// StartWFPBlocker opens a dynamic session to block external DNS queries.
func StartWFPBlocker() (*WFPSession, error) {
	var handle uintptr
	sessionKey := windows.GUID{
		Data1: 0x77c20fd9,
		Data2: 0x1830,
		Data3: 0x4c0f,
		Data4: [8]byte{0x87, 0x9e, 0x1c, 0x04, 0xb5, 0xda, 0x4d, 0x7d},
	}

	sessionName, err := windows.UTF16PtrFromString("LumiNet Dynamic DNS Leak Prevention Session")
	if err != nil {
		return nil, err
	}

	session := FWPM_SESSION0{
		SessionKey: sessionKey,
		DisplayData: FWPM_DISPLAY_DATA0{
			Name: sessionName,
		},
		Flags: FWPM_SESSION_FLAG_DYNAMIC,
	}

	ret := FwpmEngineOpen0(nil, 10, 0, &session, unsafe.Pointer(&handle))
	if ret != 0 {
		return nil, fmt.Errorf("failed to open WFP engine: 0x%x", ret)
	}

	// 1. Add BLOCK filter targeting UDP Port 53 (DNS) on standard adapters
	blockFilterName, err := windows.UTF16PtrFromString("LumiNet Block Outgoing DNS")
	if err != nil {
		FwpmEngineClose0(handle)
		return nil, err
	}

	conditions := make([]FWPM_FILTER_CONDITION0, 2)
	conditions[0].FieldKey = FWPM_CONDITION_IP_REMOTE_PORT
	conditions[0].MatchType = FWP_MATCH_EQUAL
	conditions[0].ConditionValue.Type = FWP_UINT16
	conditions[0].ConditionValue.Value = uintptr(uint16(53))

	conditions[1].FieldKey = FWPM_CONDITION_IP_PROTOCOL
	conditions[1].MatchType = FWP_MATCH_EQUAL
	conditions[1].ConditionValue.Type = FWP_UINT8
	conditions[1].ConditionValue.Value = uintptr(uint8(IPPROTO_UDP))

	blockFilter := FWPM_FILTER0{
		DisplayData: FWPM_DISPLAY_DATA0{
			Name: blockFilterName,
		},
		LayerKey:    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		Action:      FWPM_ACTION0{Type: FWP_ACTION_BLOCK},
		SubLayerKey: FWPM_SUBLAYER_UNIVERSAL,
		Weight: FWP_VALUE0{
			Type:  FWP_UINT8,
			Value: 10,
		},
		FilterCondition:     &conditions[0],
		NumFilterConditions: 2,
	}

	var filterId uint64
	ret = FwpmFilterAdd0(handle, &blockFilter, 0, &filterId)
	if ret != 0 {
		FwpmEngineClose0(handle)
		return nil, fmt.Errorf("failed to add block filter: 0x%x", ret)
	}

	// 2. Add PERMIT filter for TUN interface with a higher weight, if active
	if tunIndex := findTunInterfaceIndex(); tunIndex != 0 {
		permitFilterName, err := windows.UTF16PtrFromString("LumiNet Permit Outgoing DNS via TUN Interface")
		if err == nil {
			permitConditions := make([]FWPM_FILTER_CONDITION0, 3)
			permitConditions[0].FieldKey = FWPM_CONDITION_IP_REMOTE_PORT
			permitConditions[0].MatchType = FWP_MATCH_EQUAL
			permitConditions[0].ConditionValue.Type = FWP_UINT16
			permitConditions[0].ConditionValue.Value = uintptr(uint16(53))

			permitConditions[1].FieldKey = FWPM_CONDITION_IP_PROTOCOL
			permitConditions[1].MatchType = FWP_MATCH_EQUAL
			permitConditions[1].ConditionValue.Type = FWP_UINT8
			permitConditions[1].ConditionValue.Value = uintptr(uint8(IPPROTO_UDP))

			permitConditions[2].FieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE
			permitConditions[2].MatchType = FWP_MATCH_EQUAL
			permitConditions[2].ConditionValue.Type = FWP_UINT32
			permitConditions[2].ConditionValue.Value = uintptr(permitConditions[2].ConditionValue.Value) // placeholder placeholder
			permitConditions[2].ConditionValue.Value = uintptr(tunIndex)

			permitFilter := FWPM_FILTER0{
				DisplayData: FWPM_DISPLAY_DATA0{
					Name: permitFilterName,
				},
				LayerKey:    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
				Action:      FWPM_ACTION0{Type: FWP_ACTION_PERMIT},
				SubLayerKey: FWPM_SUBLAYER_UNIVERSAL,
				Weight: FWP_VALUE0{
					Type:  FWP_UINT8,
					Value: 20,
				},
				FilterCondition:     &permitConditions[0],
				NumFilterConditions: 3,
			}
			_ = FwpmFilterAdd0(handle, &permitFilter, 0, &filterId)
		}
	}

	return &WFPSession{handle: handle}, nil
}

func (s *WFPSession) Close() {
	if s.handle != 0 {
		FwpmEngineClose0(s.handle)
		s.handle = 0
	}
}
