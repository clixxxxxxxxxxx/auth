/**
 * ╔══════════════════════════════════════════════════╗
 * ║           VaultAuth C++ SDK  v1.0               ║
 * ║   Drop-in license authentication for C++ apps   ║
 * ╚══════════════════════════════════════════════════╝
 *
 * REQUIREMENTS:
 *   - libcurl:  sudo apt install libcurl4-openssl-dev   (Linux)
 *               brew install curl                        (macOS)
 *               vcpkg install curl                       (Windows)
 *
 * COMPILE:
 *   g++ main.cpp -lcurl -std=c++17 -o myapp
 *
 * QUICKSTART:
 *   VaultAuth::setServerUrl("https://your-server.com");
 *   auto res = VaultAuth::activate(key, hwid, username, "1.0.0");
 *   if (!res.success) { cerr << res.message; return 1; }
 *
 * Copyright (c) 2024 VaultAuth — MIT License
 */

#pragma once

#include <string>
#include <functional>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <intrin.h>
  #include <iphlpapi.h>
  #pragma comment(lib, "iphlpapi.lib")
#elif __APPLE__
  #include <sys/sysctl.h>
  #include <sys/socket.h>
  #include <net/if.h>
  #include <net/if_dl.h>
  #include <ifaddrs.h>
  #include <unistd.h>
#else // Linux
  #include <sys/utsname.h>
  #include <unistd.h>
  #include <fstream>
#endif

#include <curl/curl.h>

// ─────────────────────────────────────────────────────
//  Minimal JSON helpers (no external dependency)
// ─────────────────────────────────────────────────────
namespace VaultJSON {
    inline std::string escape(const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == '"')  out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c == '\n') out += "\\n";
            else out += c;
        }
        return out;
    }

    inline std::string get(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos = json.find(':', pos);
        if (pos == std::string::npos) return "";
        ++pos;
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
        if (pos >= json.size()) return "";

        if (json[pos] == '"') {
            // String value
            ++pos;
            std::string val;
            while (pos < json.size() && json[pos] != '"') {
                if (json[pos] == '\\' && pos + 1 < json.size()) { ++pos; }
                val += json[pos++];
            }
            return val;
        } else if (json[pos] == 't') return "true";
        else if (json[pos] == 'f') return "false";
        else if (json[pos] == 'n') return "null";
        else {
            // Number
            std::string val;
            while (pos < json.size() && json[pos] != ',' && json[pos] != '}') val += json[pos++];
            return val;
        }
    }
}

// ─────────────────────────────────────────────────────
//  cURL response writer
// ─────────────────────────────────────────────────────
static size_t curlWriteCb(char* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append(ptr, size * nmemb);
    return size * nmemb;
}

// ─────────────────────────────────────────────────────
//  VaultAuth namespace
// ─────────────────────────────────────────────────────
namespace VaultAuth {

// ── Config ────────────────────────────────────────────
static std::string _serverUrl  = "http://localhost:3000";
static std::string _sessionKey;
static std::string _sessionHwid;
static std::string _sessionPayload;
static std::string _sessionToken;
static int         _timeoutMs  = 8000;
static bool        _sslVerify  = true;  // set false for self-signed certs (dev only)

inline void setServerUrl(const std::string& url) {
    _serverUrl = url;
    while (!_serverUrl.empty() && _serverUrl.back() == '/') _serverUrl.pop_back();
}

inline void setTimeout(int milliseconds) { _timeoutMs = milliseconds; }
inline void setSSLVerify(bool verify)    { _sslVerify = verify; }

// ── Result struct ─────────────────────────────────────
struct AuthResult {
    bool        success     = false;
    std::string message;
    std::string username;
    std::string plan;
    std::string expiresAt;    // ISO string or empty = lifetime
    std::string activatedAt;
    std::string sessionToken;
    std::string sessionPayload;
};

// ── HWID Generation ───────────────────────────────────
/**
 * Generates a stable hardware identifier string.
 * Combines CPU info + machine hostname for uniqueness.
 * Feel free to replace with your own fingerprinting logic.
 */
inline std::string getHWID() {
    std::string hwid;

#ifdef _WIN32
    // CPU serial via CPUID
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    char buf[64];
    snprintf(buf, sizeof(buf), "CPU-%08X%08X", cpuInfo[3], cpuInfo[0]);
    hwid += buf;

    // MAC address
    ULONG bufLen = sizeof(IP_ADAPTER_INFO);
    std::vector<char> adapterBuf(bufLen);
    PIP_ADAPTER_INFO pInfo = reinterpret_cast<PIP_ADAPTER_INFO>(adapterBuf.data());
    if (GetAdaptersInfo(pInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        adapterBuf.resize(bufLen);
        pInfo = reinterpret_cast<PIP_ADAPTER_INFO>(adapterBuf.data());
    }
    if (GetAdaptersInfo(pInfo, &bufLen) == NO_ERROR && pInfo) {
        char mac[32];
        snprintf(mac, sizeof(mac), "-MAC-%02X%02X%02X%02X%02X%02X",
            pInfo->Address[0], pInfo->Address[1], pInfo->Address[2],
            pInfo->Address[3], pInfo->Address[4], pInfo->Address[5]);
        hwid += mac;
    }

    // Computer name
    char compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD sz = sizeof(compName);
    if (GetComputerNameA(compName, &sz)) hwid += std::string("-") + compName;

#elif __APPLE__
    // Serial number via IOKit / sysctl
    size_t len = 0;
    sysctlbyname("hw.model", nullptr, &len, nullptr, 0);
    if (len > 0) {
        std::string model(len, '\0');
        sysctlbyname("hw.model", &model[0], &len, nullptr, 0);
        hwid += "MODEL-" + model;
    }
    // MAC address
    struct ifaddrs* ifList;
    if (getifaddrs(&ifList) == 0) {
        for (struct ifaddrs* ifa = ifList; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK &&
                std::string(ifa->ifa_name) == "en0") {
                struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
                unsigned char* mac = (unsigned char*)LLADDR(sdl);
                char macStr[32];
                snprintf(macStr, sizeof(macStr), "-MAC-%02X%02X%02X%02X%02X%02X",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                hwid += macStr;
                break;
            }
        }
        freeifaddrs(ifList);
    }
    // Hostname
    char host[256];
    if (gethostname(host, sizeof(host)) == 0) hwid += std::string("-") + host;

#else // Linux
    // Machine ID
    std::ifstream midFile("/etc/machine-id");
    if (midFile.is_open()) {
        std::string mid;
        std::getline(midFile, mid);
        if (!mid.empty()) hwid += "MID-" + mid.substr(0, 16);
    }
    // Hostname
    char host[256] = {0};
    gethostname(host, sizeof(host));
    hwid += std::string("-HOST-") + host;
    // CPU info
    std::ifstream cpuFile("/proc/cpuinfo");
    if (cpuFile.is_open()) {
        std::string line;
        while (std::getline(cpuFile, line)) {
            if (line.find("Serial") != std::string::npos ||
                line.find("serial") != std::string::npos) {
                hwid += "-" + line.substr(line.find(':') + 2, 16);
                break;
            }
        }
    }
#endif

    // Fallback: use hostname only
    if (hwid.empty()) {
        char fallback[256] = "UNKNOWN";
        gethostname(fallback, sizeof(fallback));
        hwid = std::string("FALLBACK-") + fallback;
    }

    return hwid;
}

// ── HTTP POST helper ──────────────────────────────────
static std::string httpPost(const std::string& endpoint, const std::string& jsonBody) {
    CURL* curl = curl_easy_init();
    if (!curl) return R"({"success":false,"message":"curl init failed"})";

    std::string response;
    std::string url = _serverUrl + endpoint;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, _timeoutMs);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, _sslVerify ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, _sslVerify ? 2L : 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "VaultAuth-CPP/1.0");

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        response = std::string(R"({"success":false,"message":"Network error: ")") +
                   curl_easy_strerror(res) + "\"}";
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

static AuthResult parseResult(const std::string& json) {
    AuthResult r;
    r.success  = (VaultJSON::get(json, "success") == "true");
    r.message  = VaultJSON::get(json, "message");
    r.username = VaultJSON::get(json, "username");
    r.plan     = VaultJSON::get(json, "plan");
    r.expiresAt    = VaultJSON::get(json, "expiresAt");
    r.activatedAt  = VaultJSON::get(json, "activatedAt");
    r.sessionToken   = VaultJSON::get(json, "sessionToken");
    r.sessionPayload = VaultJSON::get(json, "sessionPayload");
    return r;
}

// ── Public API ────────────────────────────────────────

/**
 * activate() — Call on first launch or when user enters their key.
 * Binds the key to this machine's HWID and the provided username.
 *
 * @param key         The license key (e.g. "VAULT-ABC123-...")
 * @param hwid        Machine ID (use getHWID() or provide custom)
 * @param username    User-chosen display name
 * @param appVersion  Your app version string for diagnostics
 * @return AuthResult with success flag and user info
 */
inline AuthResult activate(const std::string& key,
                           const std::string& hwid,
                           const std::string& username,
                           const std::string& appVersion = "1.0.0") {
    std::string body = R"({"key":")" + VaultJSON::escape(key) +
                       R"(","hwid":")" + VaultJSON::escape(hwid) +
                       R"(","username":")" + VaultJSON::escape(username) +
                       R"(","appVersion":")" + VaultJSON::escape(appVersion) + "\"}";

    std::string resp = httpPost("/api/activate", body);
    AuthResult r = parseResult(resp);

    if (r.success) {
        // Save session state for subsequent validate() calls
        _sessionKey     = key;
        _sessionHwid    = hwid;
        _sessionPayload = r.sessionPayload;
        _sessionToken   = r.sessionToken;
    }

    return r;
}

/**
 * validate() — Heartbeat check. Call periodically (e.g. every 5 minutes).
 * Verifies the license hasn't been revoked/expired server-side.
 * Requires activate() to have been called first (or loadSession()).
 */
inline AuthResult validate() {
    if (_sessionKey.empty() || _sessionPayload.empty() || _sessionToken.empty()) {
        AuthResult r;
        r.success = false;
        r.message = "No active session. Call activate() first.";
        return r;
    }

    std::string body = R"({"key":")" + VaultJSON::escape(_sessionKey) +
                       R"(","hwid":")" + VaultJSON::escape(_sessionHwid) +
                       R"(","sessionPayload":")" + VaultJSON::escape(_sessionPayload) +
                       R"(","sessionToken":")" + VaultJSON::escape(_sessionToken) + "\"}";

    std::string resp = httpPost("/api/validate", body);
    return parseResult(resp);
}

/**
 * validate() — Overload with explicit parameters (no saved session required).
 */
inline AuthResult validate(const std::string& key,
                           const std::string& hwid,
                           const std::string& sessionPayload,
                           const std::string& sessionToken) {
    _sessionKey     = key;
    _sessionHwid    = hwid;
    _sessionPayload = sessionPayload;
    _sessionToken   = sessionToken;
    return validate();
}

/**
 * deactivate() — Unbind this machine from the license.
 * Call on clean logout so the user can activate on another machine.
 */
inline AuthResult deactivate() {
    if (_sessionKey.empty()) {
        AuthResult r; r.success = false; r.message = "No session."; return r;
    }

    std::string body = R"({"key":")" + VaultJSON::escape(_sessionKey) +
                       R"(","hwid":")" + VaultJSON::escape(_sessionHwid) +
                       R"(","sessionPayload":")" + VaultJSON::escape(_sessionPayload) +
                       R"(","sessionToken":")" + VaultJSON::escape(_sessionToken) + "\"}";

    std::string resp = httpPost("/api/deactivate", body);
    AuthResult r = parseResult(resp);

    if (r.success) {
        _sessionKey.clear(); _sessionHwid.clear();
        _sessionPayload.clear(); _sessionToken.clear();
    }

    return r;
}

/**
 * saveSession() — Persist session tokens to disk (encrypted with a simple XOR).
 * On next launch, call loadSession() to restore without re-entering the key.
 */
inline void saveSession(const AuthResult& res, const std::string& filePath = ".va_session") {
    // XOR obfuscation key (customize this per-app)
    const uint8_t XOR_KEY = 0xA7;

    std::string data = res.sessionPayload + "\n" + res.sessionToken + "\n" +
                       _sessionKey + "\n" + _sessionHwid;

    std::ofstream f(filePath, std::ios::binary);
    for (char c : data) f.put(c ^ XOR_KEY);
}

/**
 * loadSession() — Restore a saved session from disk.
 * Returns true if session file exists and was loaded.
 * After this, call validate() to verify it's still valid.
 */
inline bool loadSession(const std::string& filePath = ".va_session") {
    std::ifstream f(filePath, std::ios::binary);
    if (!f.is_open()) return false;

    const uint8_t XOR_KEY = 0xA7;
    std::string raw, line;
    char c;
    while (f.get(c)) raw += (char)(c ^ XOR_KEY);

    std::istringstream ss(raw);
    std::string payload, token, key, hwid;
    std::getline(ss, payload);
    std::getline(ss, token);
    std::getline(ss, key);
    std::getline(ss, hwid);

    if (payload.empty() || token.empty() || key.empty()) return false;

    _sessionPayload = payload;
    _sessionToken   = token;
    _sessionKey     = key;
    _sessionHwid    = hwid;
    return true;
}

/**
 * clearSession() — Remove the saved session file.
 */
inline void clearSession(const std::string& filePath = ".va_session") {
    std::remove(filePath.c_str());
    _sessionKey.clear(); _sessionHwid.clear();
    _sessionPayload.clear(); _sessionToken.clear();
}

/**
 * startHeartbeat() — Spawns a background thread that calls validate() every N seconds.
 * If validation fails, calls the provided callback (e.g. to shut down the app).
 *
 * Usage:
 *   VaultAuth::startHeartbeat(300, []() {
 *       std::cerr << "License revoked! Shutting down.\n";
 *       exit(1);
 *   });
 */
inline void startHeartbeat(int intervalSeconds, std::function<void()> onFailure) {
    std::thread([intervalSeconds, onFailure]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
            auto res = validate();
            if (!res.success) {
                onFailure();
                return;
            }
        }
    }).detach();
}

} // namespace VaultAuth

/* ════════════════════════════════════════════════════
   EXAMPLE USAGE (copy to your main.cpp):

   #include "vaultauth.hpp"

   int main() {
       VaultAuth::setServerUrl("https://your-server.com");
       std::string hwid = VaultAuth::getHWID();

       // --- OPTION A: First-time activation ---
       std::string key, username;
       std::cout << "License key: "; std::cin >> key;
       std::cout << "Username: ";    std::cin >> username;

       auto res = VaultAuth::activate(key, hwid, username, "1.0.0");
       if (!res.success) {
           std::cerr << "Error: " << res.message << "\n";
           return 1;
       }
       VaultAuth::saveSession(res);

       // --- OPTION B: Resume from saved session ---
       // if (VaultAuth::loadSession()) {
       //     auto res = VaultAuth::validate();
       //     if (!res.success) { ... prompt for key ... }
       // }

       std::cout << "Welcome, " << res.username << "! (" << res.plan << ")\n";

       // Start heartbeat: check every 5 minutes
       VaultAuth::startHeartbeat(300, []() {
           std::cerr << "\nLicense invalid! Exiting.\n";
           exit(1);
       });

       // Your application logic here...

       // On clean exit:
       VaultAuth::deactivate();
       VaultAuth::clearSession();
       return 0;
   }

   COMPILE:
   g++ main.cpp -lcurl -std=c++17 -O2 -o myapp

════════════════════════════════════════════════════ */
