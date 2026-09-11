//go:build windows

#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>

#pragma comment(lib, "fwpuclnt.lib")

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

// Creates a Dynamic WFP Session. The OS will automatically clean up all associated
// dynamic filters if the process crashes or shuts down.
DWORD InitializeDynamicWfpSession(HANDLE* outEngineHandle) {
    FWPM_SESSION0 session = { 0 };
    DWORD result = ERROR_SUCCESS;

    // Set dynamic flag to prevent orphaned filters on crash
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.txnWaitTimeoutInMSec = 5000;
    session.displayData.name = L"LumiNet Security Filter Session";
    session.displayData.description = L"Dynamic session for diagnostic interception filters";

    result = FwpmEngineOpen0(
        NULL, 
        RPC_C_AUTHN_WINNT, 
        NULL, 
        &session, 
        outEngineHandle
    );

    if (result != ERROR_SUCCESS) {
        wprintf(L"FwpmEngineOpen0 failed: 0x%08X\n", result);
    }
    return result;
}

DWORD CloseDynamicWfpSession(HANDLE engineHandle) {
    DWORD result = FwpmEngineClose0(engineHandle);
    return result;
}
