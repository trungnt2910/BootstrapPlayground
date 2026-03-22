// ---- Reference counting ----------------------------------------------------

static LONG_PTR FASTCALL impl_ObfReferenceObject(PVOID /*object*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return 1;
}

static LONG_PTR FASTCALL impl_ObfDereferenceObject(PVOID /*object*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return 0;
}

static NTSTATUS NTAPI impl_ObReferenceObjectByHandle(HANDLE /*handle*/,
                        ULONG /*access*/, PVOID /*objectType*/,
                        UCHAR /*accessMode*/, PVOID* object,
                        PVOID /*handleInfo*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (object) *object = nullptr;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS NTAPI impl_ObOpenObjectByPointer(PVOID /*object*/,
                        ULONG /*attrs*/, PVOID /*accessState*/,
                        ULONG /*access*/, PVOID /*objectType*/,
                        UCHAR /*accessMode*/, HANDLE* handle) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (handle) *handle = nullptr;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI impl_ObQueryNameString(PVOID /*object*/,
                        PVOID nameInfo, ULONG length, ULONG* returnLength) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (returnLength) *returnLength = 0;
    if (nameInfo && length > 0)
        static_cast<char*>(nameInfo)[0] = '\0';
    return STATUS_SUCCESS;
}

// ---- System routine lookup -------------------------------------------------

static PVOID NTAPI impl_MmGetSystemRoutineAddress(UNICODE_STRING* routineName) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!routineName || !routineName->Buffer) return nullptr;
    char narrow[256] = {};
    const int len = WideCharToMultiByte(CP_ACP, 0,
        routineName->Buffer,
        routineName->Length / static_cast<int>(sizeof(WCHAR)),
        narrow, static_cast<int>(sizeof(narrow)) - 1, nullptr, nullptr);
    if (len <= 0) return nullptr;
    narrow[len] = '\0';
    void* sym = nt_stubs_lookup(narrow);
    if (sym) {
        std::println(stderr,
            "[nt_stubs] MmGetSystemRoutineAddress({}) -> {:p}",
            narrow, sym);
        std::flush(std::cerr);
        return sym;
    }
    void* stub = nt_stubs_allocate(narrow);
    std::println(stderr,
        "[nt_stubs] MmGetSystemRoutineAddress({}) unresolved; using stub @ {:p}",
        narrow, stub);
    std::flush(std::cerr);
    return stub;
}
