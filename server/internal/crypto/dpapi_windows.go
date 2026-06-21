//go:build windows

package crypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Encrypt uses Windows DPAPI to encrypt sensitive data.
func Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	// Create BLOBs for encryption
	var dataIn, dataOut windows.DataBlob
	dataIn.Size = uint32(len(data))
	dataIn.Data = &data[0]

	// CRYPTPROTECT_UI_FORBIDDEN flag forbids UI prompts
	err := windows.CryptProtectData(
		&dataIn,
		nil,
		nil,
		0,
		nil,
		0x01, // CRYPTPROTECT_UI_FORBIDDEN
		&dataOut,
	)
	if err != nil {
		return nil, err
	}
	// Note: The caller must free dataOut.Data using LocalFree.
	// Using defer to free it here won't work because we need to return the data first.
	// We need to copy the data out before freeing it.

	result := unsafe.Slice(dataOut.Data, dataOut.Size)
	copyResult := make([]byte, len(result))
	copy(copyResult, result)

	windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))

	return copyResult, nil
}

// Decrypt uses Windows DPAPI to decrypt sensitive data.
func Decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var dataIn, dataOut windows.DataBlob
	dataIn.Size = uint32(len(data))
	dataIn.Data = &data[0]

	err := windows.CryptUnprotectData(
		&dataIn,
		nil,
		nil,
		0,
		nil,
		0x01, // CRYPTPROTECT_UI_FORBIDDEN
		&dataOut,
	)
	if err != nil {
		return nil, err
	}

	result := unsafe.Slice(dataOut.Data, dataOut.Size)
	copyResult := make([]byte, len(result))
	copy(copyResult, result)

	windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))

	return copyResult, nil
}
