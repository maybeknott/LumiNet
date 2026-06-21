#ifndef WFP_LEAK_PREVENTION_H
#define WFP_LEAK_PREVENTION_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

DWORD InitializeDnsLeakPreventer(UINT32 tunInterfaceIndex);
DWORD DeinitializeDnsLeakPreventer(void);

#ifdef __cplusplus
}
#endif

#endif // WFP_LEAK_PREVENTION_H
