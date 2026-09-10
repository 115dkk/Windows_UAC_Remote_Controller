// SPDX-License-Identifier: GPL-2.0-or-later
// Fixed one-time diagnostic bootstrap. Build /MT and /DEPENDENTLOADFLAG:0x800.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winsvc.h>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {
constexpr wchar_t Name[] = L"UacPcpContextProbe20260910";
constexpr wchar_t Stage[] = L"C:\\Users\\32170336\\AppData\\Local\\Temp\\uac-pcp-context-20260910\\PcpContextProbe.exe";
constexpr wchar_t Install[] = L"C:\\Program Files\\UacPcpContextProbe20260910";
constexpr wchar_t Image[] = L"C:\\Program Files\\UacPcpContextProbe20260910\\PcpContextProbe.Service.exe";
constexpr wchar_t Marker[] = L"C:\\Program Files\\UacPcpContextProbe20260910\\observer.ready";
constexpr wchar_t Body[] = L"C:\\Program Files\\UacPcpContextProbe20260910\\probe.txt";
constexpr wchar_t Results[] = L"C:\\Program Files\\UacPcpContextProbe20260910Results";
constexpr wchar_t Result[] = L"C:\\Program Files\\UacPcpContextProbe20260910Results\\result.json";
constexpr wchar_t RawResult[] = L"C:\\Program Files\\UacPcpContextProbe20260910Results\\probe.txt";
constexpr wchar_t DirectoryAcl[] = L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
constexpr wchar_t FileAcl[] = L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)";
constexpr wchar_t ServiceAcl[] = L"O:BAG:BAD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)";
constexpr DWORD MaxBody = 65536;
struct Failure { DWORD code; };
[[noreturn]] void fail(DWORD code = ERROR_INVALID_DATA) { throw Failure{code}; }
void checked(BOOL okay) { if (!okay) fail(GetLastError()); }
struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE raw = nullptr) : value(raw) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete; Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(other.value) { other.value = nullptr; }
    Handle& operator=(Handle&& other) noexcept { if (this != &other) { reset(); value = other.value; other.value = nullptr; } return *this; }
    bool valid() const { return value && value != INVALID_HANDLE_VALUE; }
    void reset() { if (valid()) CloseHandle(value); value = nullptr; }
};
struct Service {
    SC_HANDLE value = nullptr;
    explicit Service(SC_HANDLE raw) : value(raw) { if (!value) fail(GetLastError()); }
    ~Service() { if (value) CloseServiceHandle(value); }
    Service(const Service&) = delete; Service& operator=(const Service&) = delete;
    void close() { if (value) { checked(CloseServiceHandle(value)); value = nullptr; } }
};
struct Local {
    void* value = nullptr;
    ~Local() { if (value) LocalFree(value); }
    Local() = default; Local(const Local&) = delete; Local& operator=(const Local&) = delete;
};
struct Descriptor {
    Local bytes;
    explicit Descriptor(const wchar_t* sddl) { checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &bytes.value, nullptr)); }
    SECURITY_ATTRIBUTES attributes() { return SECURITY_ATTRIBUTES{sizeof(SECURITY_ATTRIBUTES), bytes.value, FALSE}; }
};
bool wellKnown(PSID sid, WELL_KNOWN_SID_TYPE kind) {
    BYTE bytes[SECURITY_MAX_SID_SIZE]{}; DWORD length = sizeof(bytes);
    checked(CreateWellKnownSid(kind, nullptr, bytes, &length));
    return sid && IsValidSid(sid) && EqualSid(sid, bytes);
}
bool trustedSid(PSID sid) {
    if (wellKnown(sid, WinLocalSystemSid) || wellKnown(sid, WinBuiltinAdministratorsSid)) return true;
    Local installer;
    checked(ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &installer.value));
    return sid && EqualSid(sid, installer.value);
}
bool inside(const void* value, const void* base, size_t size, size_t needed) {
    const auto address = reinterpret_cast<std::uintptr_t>(value), start = reinterpret_cast<std::uintptr_t>(base);
    return address >= start && address - start <= size && needed <= size - (address - start);
}
void boundedSid(PSID sid, const void* base, size_t size) {
    if (!inside(sid, base, size, 8)) fail();
    const auto bytes = static_cast<const BYTE*>(sid);
    const size_t count = bytes[1];
    if (bytes[0] != SID_REVISION || count > SID_MAX_SUB_AUTHORITIES || !inside(sid, base, size, 8 + count * 4) || !IsValidSid(sid)) fail();
}
void checkAcl(HANDLE handle, SE_OBJECT_TYPE type, bool strict, bool onlyAdmin = false) {
    PSID owner = nullptr; PACL acl = nullptr; Local sd;
    DWORD error = GetSecurityInfo(handle, type, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &acl, nullptr, &sd.value);
    if (error != ERROR_SUCCESS) fail(error);
    if (!sd.value || !owner || !acl || !IsValidSecurityDescriptor(sd.value)) fail();
    const DWORD sdSize = GetSecurityDescriptorLength(sd.value);
    if (sdSize < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || sdSize > MaxBody || !inside(acl, sd.value, sdSize, sizeof(ACL))) fail();
    boundedSid(owner, sd.value, sdSize);
    if (!trustedSid(owner) || acl->AclSize < sizeof(ACL) || !inside(acl, sd.value, sdSize, acl->AclSize) || acl->AceCount > 256 || !IsValidAcl(acl)) fail();
    if (onlyAdmin && !wellKnown(owner, WinBuiltinAdministratorsSid)) fail();
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* raw = nullptr; checked(GetAce(acl, i, &raw));
        if (!inside(raw, acl, acl->AclSize, sizeof(ACE_HEADER))) fail();
        auto header = static_cast<ACE_HEADER*>(raw);
        if (header->AceSize < sizeof(ACE_HEADER) || !inside(raw, acl, acl->AclSize, header->AceSize)) fail();
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if ((header->AceFlags & ~0x1f) != 0 || (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE)) fail();
        auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if (header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) fail();
        boundedSid(&ace->SidStart, raw, header->AceSize);
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            if (onlyAdmin) { if (!wellKnown(&ace->SidStart, WinLocalSystemSid) && !wellKnown(&ace->SidStart, WinBuiltinAdministratorsSid)) fail(); }
            else if ((ace->Mask & ~0xf01f01ffu) != 0 || (!trustedSid(&ace->SidStart) && (ace->Mask & (strict ? 0x500d0156u : 0x500d0152u)) != 0)) fail();
        }
    }
}
struct Pins {
    std::vector<std::pair<std::wstring, Handle>> held;
    HANDLE add(const std::wstring& path, bool directory, bool trusted, bool strict) {
        for (auto& item : held) if (item.first == path) { if (trusted) checkAcl(item.second.value, SE_FILE_OBJECT, strict); return item.second.value; }
        if (held.size() >= 64 || path.size() >= 1024 || path.size() < 3 || GetDriveTypeW(path.substr(0, 3).c_str()) != DRIVE_FIXED) fail();
        Handle file(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
            directory ? FILE_SHARE_READ | FILE_SHARE_WRITE : FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
        if (!file.valid()) fail(GetLastError());
        BY_HANDLE_FILE_INFORMATION info{}; checked(GetFileInformationByHandle(file.value, &info));
        if (GetFileType(file.value) != FILE_TYPE_DISK || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory || (!directory && info.nNumberOfLinks != 1)) fail();
        wchar_t final[1024]{}; DWORD count = GetFinalPathNameByHandleW(file.value, final, 1024, 0);
        if (!count || count >= 1024 || std::wstring(final) != L"\\\\?\\" + path) fail();
        if (trusted) checkAcl(file.value, SE_FILE_OBJECT, strict);
        HANDLE raw = file.value; held.emplace_back(path, std::move(file)); return raw;
    }
    void chain(const std::wstring& path, bool strictFinal) {
        std::wstring cursor = path.substr(0, 3); add(cursor, true, true, false);
        size_t start = 3;
        while (start < path.size()) {
            size_t end = path.find(L'\\', start); if (end == std::wstring::npos) end = path.size();
            cursor = path.substr(0, end); add(cursor, true, true, strictFinal && end == path.size()); start = end + 1;
        }
    }
    void release(const wchar_t* path) {
        for (auto it = held.begin(); it != held.end(); ++it) if (it->first == path) { held.erase(it); return; }
        fail();
    }
};
std::vector<BYTE> tokenData(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD length = 0; GetTokenInformation(token, kind, nullptr, 0, &length);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || length < 4 || length > MaxBody) fail();
    std::vector<BYTE> bytes(length); checked(GetTokenInformation(token, kind, bytes.data(), length, &length));
    if (length < 4 || length > bytes.size()) fail(); bytes.resize(length); return bytes;
}
void adminOnly() {
    HANDLE raw = nullptr; checked(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)); Handle token(raw);
    auto user = tokenData(token.value, TokenUser); auto session = tokenData(token.value, TokenSessionId);
    auto elevation = tokenData(token.value, TokenElevation); auto type = tokenData(token.value, TokenType);
    if (user.size() < sizeof(TOKEN_USER)) fail();
    boundedSid(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, user.data(), user.size());
    if (wellKnown(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, WinLocalSystemSid) ||
        *reinterpret_cast<DWORD*>(session.data()) == 0 || !reinterpret_cast<TOKEN_ELEVATION*>(elevation.data())->TokenIsElevated ||
        *reinterpret_cast<TOKEN_TYPE*>(type.data()) != TokenPrimary) fail(ERROR_ACCESS_DENIED);
    BYTE sid[SECURITY_MAX_SID_SIZE]{}; DWORD length = sizeof(sid); checked(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &length));
    BOOL member = FALSE; checked(CheckTokenMembership(nullptr, sid, &member)); if (!member) fail(ERROR_ACCESS_DENIED);
}
void absentPath(const wchar_t* path) {
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) fail(ERROR_ALREADY_EXISTS);
    DWORD error = GetLastError(); if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) fail(error);
}
void freshDirectory(const wchar_t* path) { Descriptor sd(DirectoryAcl); auto sa = sd.attributes(); checked(CreateDirectoryW(path, &sa)); }
void writeNew(const wchar_t* path, const BYTE* data, DWORD length) {
    Descriptor sd(FileAcl); auto sa = sd.attributes();
    Handle file(CreateFileW(path, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!file.valid()) fail(GetLastError());
    DWORD written = 0; checked(WriteFile(file.value, data, length, &written, nullptr)); if (written != length) fail(ERROR_WRITE_FAULT);
    checked(FlushFileBuffers(file.value));
}
std::vector<BYTE> readBounded(HANDLE file, DWORD maximum) {
    LARGE_INTEGER size{}, zero{}; checked(GetFileSizeEx(file, &size));
    if (size.QuadPart < 0 || size.QuadPart > maximum) fail();
    checked(SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)); std::vector<BYTE> bytes(static_cast<size_t>(size.QuadPart));
    DWORD read = 0; checked(ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr));
    if (read != bytes.size()) fail(ERROR_READ_FAULT); return bytes;
}
void timely(ULONGLONG start) { if (GetTickCount64() - start > 60000) fail(ERROR_TIMEOUT); }
SERVICE_STATUS_PROCESS query(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{}; DWORD length = 0;
    checked(QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &length));
    if (status.dwServiceType != SERVICE_WIN32_OWN_PROCESS) fail(); return status;
}
ULONGLONG ticks(FILETIME time) { return (static_cast<ULONGLONG>(time.dwHighDateTime) << 32) | time.dwLowDateTime; }
Handle observe(SC_HANDLE service, ULONGLONG start, ULONGLONG bootstrapTime) {
    for (;;) {
        timely(start); auto status = query(service);
        if (status.dwCurrentState == SERVICE_STOPPED) fail(ERROR_SERVICE_NOT_ACTIVE);
        if (status.dwCurrentState == SERVICE_RUNNING && status.dwControlsAccepted == 0 && status.dwProcessId) {
            Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, status.dwProcessId));
            if (!process.valid()) fail(GetLastError());
            wchar_t image[1024]{}; DWORD length = 1024;
            checked(QueryFullProcessImageNameW(process.value, 0, image, &length)); if (std::wstring(image) != Image) fail();
            FILETIME created{}, exited{}, kernel{}, user{}, now{};
            checked(GetProcessTimes(process.value, &created, &exited, &kernel, &user)); GetSystemTimeAsFileTime(&now);
            if (ticks(created) < bootstrapTime || ticks(created) > ticks(now) || WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT) fail();
            auto again = query(service);
            if (again.dwCurrentState != SERVICE_RUNNING || again.dwControlsAccepted != 0 || again.dwProcessId != status.dwProcessId) fail();
            return process;
        }
        if (status.dwCurrentState != SERVICE_START_PENDING && status.dwCurrentState != SERVICE_RUNNING) fail();
        Sleep(20);
    }
}
void verifyConfig(SC_HANDLE service, const std::wstring& command) {
    DWORD length = 0; QueryServiceConfigW(service, nullptr, 0, &length);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || length < sizeof(QUERY_SERVICE_CONFIGW) || length > MaxBody) fail();
    std::vector<BYTE> bytes(length); auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());
    checked(QueryServiceConfigW(service, config, length, &length));
    auto text = [&](const wchar_t* value) {
        if (!value) return std::wstring();
        auto address = reinterpret_cast<const BYTE*>(value);
        if (address < bytes.data() || address >= bytes.data() + bytes.size()) fail();
        const size_t bound = static_cast<size_t>((bytes.data() + bytes.size() - address) / sizeof(wchar_t));
        for (size_t i = 0; i < bound && i < 1024; ++i) if (!value[i]) return std::wstring(value, i);
        fail();
    };
    if (config->dwServiceType != SERVICE_WIN32_OWN_PROCESS || config->dwStartType != SERVICE_DEMAND_START || config->dwErrorControl != SERVICE_ERROR_NORMAL ||
        text(config->lpBinaryPathName) != command || text(config->lpServiceStartName) != L"LocalSystem" || !text(config->lpLoadOrderGroup).empty() ||
        !text(config->lpDependencies).empty() || config->dwTagId != 0) fail();
    SERVICE_SID_INFO sid{}; checked(QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, reinterpret_cast<BYTE*>(&sid), sizeof(sid), &length));
    if (sid.dwServiceSidType != SERVICE_SID_TYPE_UNRESTRICTED) fail();
    checkAcl(service, SE_SERVICE, true, true);
}
std::string quoted(const std::string& value) {
    std::string result = "\"";
    for (unsigned char ch : value) {
        if (ch == '\n') result += "\\n"; else if (ch == '\r') result += "\\r";
        else if (ch == '\\' || ch == '"') { result += '\\'; result += static_cast<char>(ch); }
        else if (ch >= 32 && ch < 127) result += static_cast<char>(ch); else fail();
    }
    return result + "\"";
}
void report(const std::string& body, bool cleanup, bool complete, DWORD error, DWORD exitCode) {
    std::string json = "{\"collection\":\"" + std::string(complete ? "complete" : "incomplete") + "\",\"cleanup\":\"" +
        (cleanup ? "complete" : "pending") + "\",\"bootstrap_error\":" + std::to_string(error) +
        ",\"service_process_exit\":" + std::to_string(exitCode) + ",\"probe\":" + quoted(body) + "}\n";
    if (json.size() > MaxBody) fail();
    writeNew(Result, reinterpret_cast<const BYTE*>(json.data()), static_cast<DWORD>(json.size()));
}
int run() {
    adminOnly();
    wchar_t own[1024]{}, system[1024]{};
    DWORD count = GetModuleFileNameW(nullptr, own, 1024);
    if (!count || count >= 1024 || std::wstring(own) != Stage || GetSystemDirectoryW(system, 1024) == 0 || CompareStringOrdinal(system, -1, L"C:\\Windows\\System32", -1, TRUE) != CSTR_EQUAL) fail();
    checked(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32));
    HMODULE module = GetModuleHandleW(nullptr); HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(101), MAKEINTRESOURCEW(10));
    if (!resource) fail(GetLastError());
    DWORD payloadSize = SizeofResource(module, resource);
    HGLOBAL loaded = LoadResource(module, resource); const BYTE* payload = static_cast<const BYTE*>(LockResource(loaded));
    if (!payload || payloadSize < 1024 || payloadSize > 8 * 1024 * 1024 || payload[0] != 'M' || payload[1] != 'Z') fail();
    const ULONGLONG start = GetTickCount64(); FILETIME created{}, exited{}, kernel{}, user{};
    checked(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user));
    Pins pins; pins.chain(L"C:\\Program Files", true);
    Service scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
    SC_HANDLE found = OpenServiceW(scm.value, Name, SERVICE_QUERY_STATUS);
    if (found) { CloseServiceHandle(found); fail(ERROR_SERVICE_EXISTS); }
    if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) fail(GetLastError());
    absentPath(Install); absentPath(Results);
    bool ownResult = false; bool cleanup = false; std::string body; DWORD serviceExit = STILL_ACTIVE;
    try {
        freshDirectory(Results); ownResult = true; pins.add(Results, true, true, true);
        freshDirectory(Install); pins.add(Install, true, true, true);
        writeNew(Image, payload, payloadSize);
        HANDLE copied = pins.add(Image, false, true, true); auto bytes = readBounded(copied, payloadSize);
        if (bytes.size() != payloadSize || std::memcmp(bytes.data(), payload, payloadSize) != 0) fail();
        std::wstring command = L"\"" + std::wstring(Image) + L"\" service";
        Service service(CreateServiceW(scm.value, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr));
        Descriptor sd(ServiceAcl); checked(SetServiceObjectSecurity(service.value, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd.bytes.value));
        SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED}; checked(ChangeServiceConfig2W(service.value, SERVICE_CONFIG_SERVICE_SID_INFO, &sid));
        verifyConfig(service.value, command); timely(start); checked(StartServiceW(service.value, 0, nullptr));
        Handle process = observe(service.value, start, ticks(created));
        const DWORD pid = GetProcessId(process.value); if (!pid) fail(GetLastError());
        timely(start); writeNew(Marker, reinterpret_cast<const BYTE*>(""), 0); pins.add(Marker, false, true, true);
        for (;;) {
            timely(start); auto status = query(service.value); DWORD wait = WaitForSingleObject(process.value, 0);
            if (wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT) fail(GetLastError());
            if (status.dwCurrentState == SERVICE_STOPPED && wait == WAIT_OBJECT_0) break;
            if (status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != pid) fail();
            Sleep(20);
        }
        checked(GetExitCodeProcess(process.value, &serviceExit));
        auto raw = readBounded(pins.add(Body, false, true, true), MaxBody / 2 + 1024);
        body.assign(raw.begin(), raw.end()); if (body.rfind("probe_version=1\n", 0) != 0) fail();
        quoted(body); // Bounded ASCII metadata only, before any cleanup.
        writeNew(RawResult, raw.data(), static_cast<DWORD>(raw.size()));
        checked(DeleteService(service.value)); service.close();
        for (;;) {
            timely(start); SC_HANDLE remaining = OpenServiceW(scm.value, Name, SERVICE_QUERY_STATUS);
            if (remaining) CloseServiceHandle(remaining);
            else { DWORD error = GetLastError(); if (error == ERROR_SERVICE_DOES_NOT_EXIST) break; if (error != ERROR_SERVICE_MARKED_FOR_DELETE) fail(error); }
            Sleep(20);
        }
        pins.release(Body); checked(DeleteFileW(Body));
        pins.release(Marker); checked(DeleteFileW(Marker));
        pins.release(Image); checked(DeleteFileW(Image));
        pins.release(Install); checked(RemoveDirectoryW(Install)); cleanup = true;
        bool complete = serviceExit == 0 && body.find("payload=complete\n") != std::string::npos && body.find("pcp_open_status=0x") != std::string::npos;
        report(body, cleanup, complete, ERROR_SUCCESS, serviceExit); return complete ? 0 : 3;
    } catch (const Failure& error) {
        if (ownResult) { try { report(body, cleanup, false, error.code, serviceExit); } catch (...) {} }
        return 2;
    } catch (...) {
        if (ownResult) { try { report(body, cleanup, false, ERROR_UNHANDLED_EXCEPTION, serviceExit); } catch (...) {} }
        return 2;
    }
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    try { if (argc != 2 || std::wstring(argv[1]) != L"install-run-remove") fail(); return run(); }
    catch (const Failure& error) { return static_cast<int>(0xE5000000u | (error.code & 0xffffu)); }
    catch (...) { return 1; }
}
