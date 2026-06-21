#include "wfp_leak_prevention.h"
#include <fwpmu.h>

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

// Define standard WFP GUIDs directly to avoid header dependency conflicts
// FWPM_LAYER_ALE_AUTH_CONNECT_V4: {c38d57d1-05ea-4d30-90f4-8fdec001003f}
static const GUID LUMINET_FWPM_LAYER_ALE_AUTH_CONNECT_V4 = 
{ 0xc38d57d1, 0x05ea, 0x4d30, { 0x90, 0xf4, 0x8f, 0xde, 0xc0, 0x01, 0x00, 0x3f } };

// FWPM_SUBLAYER_UNIVERSAL: {e0b4a450-ef80-4be6-9467-33f7ccfc5396}
static const GUID LUMINET_FWPM_SUBLAYER_UNIVERSAL = 
{ 0xe0b4a450, 0xef80, 0x4be6, { 0x94, 0x67, 0x33, 0xf7, 0xcc, 0xfc, 0x53, 0x96 } };

// FW_CONDITION_IP_REMOTE_PORT: {c35a3630-3cc3-4bc7-b873-455b57f00bf7}
static const GUID LUMINET_FW_CONDITION_IP_REMOTE_PORT = 
{ 0xc35a3630, 0x3cc3, 0x4bc7, { 0xb8, 0x73, 0x45, 0x5b, 0x57, 0xf0, 0x0b, 0xf7 } };

// FW_CONDITION_IP_PROTOCOL: {1e4d0d0c-6685-45ec-bf30-5be13280145c}
static const GUID LUMINET_FW_CONDITION_IP_PROTOCOL = 
{ 0x1e4d0d0c, 0x6685, 0x45ec, { 0xbf, 0x30, 0x5b, 0xe1, 0x32, 0x80, 0x14, 0x5c } };

// FW_CONDITION_IP_LOCAL_INTERFACE: {cf1076b1-0941-4774-8b9a-7c980757d598}
static const GUID LUMINET_FW_CONDITION_IP_LOCAL_INTERFACE = 
{ 0xcf1076b1, 0x0941, 0x4774, { 0x8b, 0x9a, 0x7c, 0x98, 0x07, 0x57, 0xd5, 0x98 } };

// {77C20FD9-1830-4C0F-879E-1C04B5DA4D7D}
static const GUID LUMINET_WFP_SESSION_KEY = 
{ 0x77c20fd9, 0x1830, 0x4c0f, { 0x87, 0x9e, 0x1c, 0x04, 0xb5, 0xda, 0x4d, 0x7d } };

static HANDLE g_engineHandle = NULL;

DWORD InitializeDnsLeakPreventer(UINT32 tunInterfaceIndex) {
    if (g_engineHandle != NULL) {
        return ERROR_ALREADY_INITIALIZED;
    }

    FWPM_SESSION0 session = {0};
    DWORD result = ERROR_SUCCESS;

    session.sessionKey = LUMINET_WFP_SESSION_KEY;
    session.displayData.name = L"LumiNet Dynamic DNS Leak Prevention Session";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; 

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_engineHandle);
    if (result != ERROR_SUCCESS) {
        g_engineHandle = NULL;
        return result;
    }

    // 1. Add BLOCK filter targeting UDP Port 53 (DNS) on standard adapters
    FWPM_FILTER0 blockFilter = {0};
    blockFilter.displayData.name = L"LumiNet Block Outgoing DNS";
    blockFilter.layerKey = LUMINET_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    blockFilter.action.type = FWP_ACTION_BLOCK;
    blockFilter.subLayerKey = LUMINET_FWPM_SUBLAYER_UNIVERSAL;
    blockFilter.weight.type = FWP_UINT8;
    blockFilter.weight.uint8 = 10; 

    FWPM_FILTER_CONDITION0 conditions[2] = {0};
    
    conditions[0].fieldKey = LUMINET_FW_CONDITION_IP_REMOTE_PORT;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_UINT16;
    conditions[0].conditionValue.uint16 = 53;

    conditions[1].fieldKey = LUMINET_FW_CONDITION_IP_PROTOCOL;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT8;
    conditions[1].conditionValue.uint8 = IPPROTO_UDP;

    blockFilter.filterCondition = conditions;
    blockFilter.numFilterConditions = 2;

    result = FwpmFilterAdd0(g_engineHandle, &blockFilter, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        FwpmEngineClose0(g_engineHandle);
        g_engineHandle = NULL;
        return result;
    }

    // 2. Add PERMIT filter for TUN interface with a higher weight
    FWPM_FILTER0 permitFilter = {0};
    permitFilter.displayData.name = L"LumiNet Permit Outgoing DNS via TUN Interface";
    permitFilter.layerKey = LUMINET_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    permitFilter.action.type = FWP_ACTION_PERMIT;
    permitFilter.subLayerKey = LUMINET_FWPM_SUBLAYER_UNIVERSAL;
    permitFilter.weight.type = FWP_UINT8;
    permitFilter.weight.uint8 = 20; 

    FWPM_FILTER_CONDITION0 permitConditions[3] = {0};
    
    permitConditions[0].fieldKey = LUMINET_FW_CONDITION_IP_REMOTE_PORT;
    permitConditions[0].matchType = FWP_MATCH_EQUAL;
    permitConditions[0].conditionValue.type = FWP_UINT16;
    permitConditions[0].conditionValue.uint16 = 53;

    permitConditions[1].fieldKey = LUMINET_FW_CONDITION_IP_PROTOCOL;
    permitConditions[1].matchType = FWP_MATCH_EQUAL;
    permitConditions[1].conditionValue.type = FWP_UINT8;
    permitConditions[1].conditionValue.uint8 = IPPROTO_UDP;

    permitConditions[2].fieldKey = LUMINET_FW_CONDITION_IP_LOCAL_INTERFACE;
    permitConditions[2].matchType = FWP_MATCH_EQUAL;
    permitConditions[2].conditionValue.type = FWP_UINT32;
    permitConditions[2].conditionValue.uint32 = tunInterfaceIndex;

    permitFilter.filterCondition = permitConditions;
    permitFilter.numFilterConditions = 3;

    result = FwpmFilterAdd0(g_engineHandle, &permitFilter, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        FwpmEngineClose0(g_engineHandle);
        g_engineHandle = NULL;
        return result;
    }

    return ERROR_SUCCESS;
}

DWORD DeinitializeDnsLeakPreventer(void) {
    if (g_engineHandle == NULL) {
        return ERROR_SUCCESS;
    }
    DWORD result = FwpmEngineClose0(g_engineHandle);
    g_engineHandle = NULL;
    return result;
}
