// call_trace.cpp – function-level call diagnostics via -finstrument-functions.
//
// This logs function enter/exit addresses for all instrumented code in the
// current process. Keep this minimal and non-recursive.

#include <windows.h>

extern "C" {

__attribute__((no_instrument_function))
void __cyg_profile_func_enter(void* this_fn, void* call_site) {
    char buf[128];
    int n = wsprintfA(buf, "[trace] enter fn=%p from=%p\n", this_fn, call_site);
    if (n <= 0) return;
    DWORD written = 0;
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE)
        (void)WriteFile(h, buf, static_cast<DWORD>(n), &written, nullptr);
    OutputDebugStringA(buf);
}

__attribute__((no_instrument_function))
void __cyg_profile_func_exit(void* this_fn, void* call_site) {
    char buf[128];
    int n = wsprintfA(buf, "[trace] exit  fn=%p to=%p\n", this_fn, call_site);
    if (n <= 0) return;
    DWORD written = 0;
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE)
        (void)WriteFile(h, buf, static_cast<DWORD>(n), &written, nullptr);
    OutputDebugStringA(buf);
}

} // extern "C"

