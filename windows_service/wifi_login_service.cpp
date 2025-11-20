#include <windows.h>
#include <wlanapi.h>
#include <wininet.h>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <atomic>
#include <thread>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

// Service configuration
#define SERVICE_NAME TEXT("VITWiFiLogin")
#define LOG_FILE "C:\\ProgramData\\VITWiFiLogin\\service.log"
#define CONFIG_FILE "C:\\ProgramData\\VITWiFiLogin\\config.ini"

SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

mutex mtx;
bool shouldCheckSSID = false;
HANDLE g_clientHandle = NULL;
atomic<bool> isRunning(true);
ofstream logFile;

// config variables
string g_userId = "";
string g_password = "";

string trim(const string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

void WriteLog(const string& message) {
    time_t t = time(0);
    tm *now = localtime(&t);

    ostringstream oss;
    oss << "[ " << (now->tm_year + 1900) << '-'
         << setw(2) << setfill('0') << (now->tm_mon + 1) << '-'
         << setw(2) << setfill('0') << now->tm_mday << " " 
         << setw(2) << setfill('0') << now->tm_hour << ":" 
         << setw(2) << setfill('0') << now->tm_min << ":" 
         << setw(2) << setfill('0') << now->tm_sec << " ] ";
    
    logFile << oss.str() << message << endl;
    logFile.flush();
}

bool loadConfig() {
    ifstream configFile(CONFIG_FILE);
    if (!configFile.is_open()) {
        WriteLog("Config file not found: " + string(CONFIG_FILE));
        WriteLog("Creating default config file...");
        
        // Create default config
        ofstream newConfig(CONFIG_FILE);
        if (newConfig.is_open()) {
            newConfig << "[Credentials]\n";
            newConfig << "userId=YOUR_USER_ID\n";
            newConfig << "password=YOUR_PASSWORD\n";
            newConfig.close();
            WriteLog("Default config created. Please edit: " + string(CONFIG_FILE));
        }
        return false;
    }

    string line;
    while (getline(configFile, line)) {
        line = trim(line);
        
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#' || line[0] == ';' || line[0] == '[') {
            continue;
        }

        size_t pos = line.find('=');
        if (pos != string::npos) {
            string key = trim(line.substr(0, pos));
            string value = trim(line.substr(pos + 1));

            if (key == "userId") {
                g_userId = value;
            } else if (key == "password") {
                g_password = value;
            }
        }
    }

    configFile.close();

    if (g_userId.empty() || g_password.empty() || 
        g_userId == "YOUR_USER_ID" || g_password == "YOUR_PASSWORD") {
        WriteLog("Invalid credentials in config file");
        return false;
    }

    WriteLog("Configuration loaded successfully");
    return true;
}

string urlEncode(const string& value) {
    ostringstream escaped;
    escaped.fill('0');
    escaped << hex;

    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << uppercase;
            escaped << '%' << setw(2) << int((unsigned char)c);
            escaped << nouppercase;
        }
    }

    return escaped.str();
}

bool loginToVit() {
    HINTERNET hInternet = InternetOpen(
        TEXT("VIT-Login"),
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL, NULL, 0
    );

    if (!hInternet) {
        WriteLog("Failed to initialize internet connection");
        return false;
    }

    HINTERNET hConnect = InternetConnect(
        hInternet,
        TEXT("phc.prontonetworks.com"),
        INTERNET_DEFAULT_HTTP_PORT,
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0
    );

    if (!hConnect) {
        InternetCloseHandle(hInternet);
        WriteLog("Failed to connect to Pronto server");
        return false;
    }

    HINTERNET hRequest = HttpOpenRequest(
        hConnect,
        TEXT("POST"),
        TEXT("/cgi-bin/authlogin?URI=http://example.com"),
        NULL, NULL, NULL, 0, 0
    );

    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        WriteLog("Failed to create HTTP request");
        return false;
    }

    string postData = "userId=" + urlEncode(g_userId) + 
                      "&password=" + urlEncode(g_password) + 
                      "&serviceName=ProntoAuthentication";
    string headers = "Content-Type: application/x-www-form-urlencoded";

    BOOL result = HttpSendRequestA(
        hRequest,
        headers.c_str(),
        headers.length(),
        (LPVOID)postData.c_str(),
        postData.length()
    );

    bool success = false;
    if (result) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        
        if (HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                         &statusCode, &statusSize, NULL)) {
            WriteLog("Login response status: " + to_string(statusCode));
            success = (statusCode == 200 || statusCode == 302);
        }
    } else {
        WriteLog("Failed to send login request");
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return success;
}

string getSSID(HANDLE clientHandle) {
    PWLAN_INTERFACE_INFO_LIST interfaceList = NULL;

    DWORD result = WlanEnumInterfaces(clientHandle, NULL, &interfaceList);
    if (result != ERROR_SUCCESS) {
        return "";
    }

    string ssid = "";
    for (DWORD i=0;i<interfaceList->dwNumberOfItems;i++) {
        PWLAN_INTERFACE_INFO interfaceInfo = &interfaceList->InterfaceInfo[i];
        if (interfaceInfo->isState == wlan_interface_state_connected) {
            PWLAN_CONNECTION_ATTRIBUTES connectionAttributes = NULL;
            DWORD dataSize = 0;
            
            result = WlanQueryInterface(
                clientHandle,
                &interfaceInfo->InterfaceGuid,
                wlan_intf_opcode_current_connection,
                NULL,
                &dataSize,
                (PVOID*)&connectionAttributes,
                NULL
            );
            
            if (result == ERROR_SUCCESS) {
                DOT11_SSID wlanSsid = connectionAttributes->wlanAssociationAttributes.dot11Ssid;
                ssid = string((char*)wlanSsid.ucSSID, wlanSsid.uSSIDLength);
                WlanFreeMemory(connectionAttributes);
                break;
            }
        }
    }

    WlanFreeMemory(interfaceList);
    return ssid;
}

bool needsLogin() {
    HINTERNET hInternet = InternetOpen(TEXT("Test"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return true;

    HINTERNET hFile = InternetOpenUrl(
        hInternet,
        TEXT("http://clients3.google.com/generate_204"),
        NULL, 0, INTERNET_FLAG_RELOAD, 0
    );

    if (!hFile) {
        InternetCloseHandle(hInternet);
        return true;
    }

    DWORD status = 0, length = sizeof(status);
    HttpQueryInfo(hFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &length, NULL);

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    return status != 204;
}

void captivePortalMonitor() {
    const int CHECK_INTERVAL = 30000;

    while (isRunning) {
        Sleep(CHECK_INTERVAL);

        if (!isRunning) break;

        string ssid = getSSID(g_clientHandle);

        if (!ssid.empty() && ssid.find("VIT") != string::npos) {
            if (needsLogin()) {
                WriteLog("Captive portal detected (possible logout)");
                WriteLog("Re-authenticating...");
                
                if (loginToVit()) {
                    WriteLog("Re-authentication successful!");
                } else {
                    WriteLog("Re-authentication failed");
                }
            }
        }
    }
}

VOID WINAPI wlanCallback(PWLAN_NOTIFICATION_DATA data, PVOID context) {
    if (!data) return;

    if (data->NotificationCode == wlan_notification_acm_connection_complete) {
        lock_guard<mutex> lock(mtx);
        shouldCheckSSID = true;
    }
    
    switch (data->NotificationCode) {
    case wlan_notification_acm_connection_complete:
        WriteLog("Connected to wifi");
        break;
    case wlan_notification_acm_disconnected:
        WriteLog("Disconnected");
        break;
    case wlan_notification_acm_connection_start:
        WriteLog("Connecting");
        break;
    default:
        WriteLog("wifi event: " + to_string(data->NotificationCode));
    }
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 4;

        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        isRunning = false;
        SetEvent(g_ServiceStopEvent);
        break;

    default:
        break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    WriteLog("Service worker thread started");

    // Load configuration
    if (!loadConfig()) {
        WriteLog("Failed to load valid configuration. Service cannot continue.");
        return ERROR_EXCEPTION_IN_SERVICE;
    }

    DWORD negotiatedVersion;
    HANDLE clientHandle;

    DWORD result = WlanOpenHandle(2, NULL, &negotiatedVersion, &clientHandle);

    if (result != ERROR_SUCCESS) {
        WriteLog("WlanOpenHandle failed");
        return ERROR_EXCEPTION_IN_SERVICE;
    }

    g_clientHandle = clientHandle;

    result = WlanRegisterNotification(
        clientHandle,
        WLAN_NOTIFICATION_SOURCE_ACM,
        TRUE,
        (WLAN_NOTIFICATION_CALLBACK)wlanCallback,
        NULL, NULL, NULL
    );

    if (result != ERROR_SUCCESS) {
        WriteLog("WlanRegisterNotification failed");
        WlanCloseHandle(clientHandle, NULL);
        return ERROR_EXCEPTION_IN_SERVICE;
    }

    WriteLog("Listening for wifi events...");

    // Initial check
    string ssid = getSSID(g_clientHandle);
    if (!ssid.empty()) {
        WriteLog("Current SSID at startup: " + ssid);

        if (ssid.find("VIT") != string::npos) {
            if (needsLogin()) {
                WriteLog("Login required for network: " + ssid);
                WriteLog("Attempting VIT network login...");
                
                if (loginToVit()) {
                    WriteLog("Login successful!");
                } else {
                    WriteLog("Login failed");
                }
            } else {
                WriteLog("Already authenticated");
            }
        } else {
            WriteLog("Not a VIT network");
        }
    } else {
        WriteLog("Not connected to any network");
    }

    thread monitorThread(captivePortalMonitor);
    WriteLog("Started captive portal monitor");

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
        lock_guard<mutex> lock(mtx);
        if (shouldCheckSSID) {
            shouldCheckSSID = false;
            string ssid = getSSID(g_clientHandle);

            if (!ssid.empty()) {
                WriteLog("Current SSID: " + ssid);

                if (ssid.find("VIT") != string::npos) {
                    if (needsLogin()) {
                        WriteLog("Login required for network: " + ssid);
                        WriteLog("Attempting VIT network login...");
                        
                        if (loginToVit()) {
                            WriteLog("Login successful!");
                        } else {
                            WriteLog("Login failed");
                        }
                    } else {
                        WriteLog("Already authenticated");
                    }
                } else {
                    WriteLog("Not a VIT network, skipping login");
                }
            }
        }
        Sleep(1000);
    }

    isRunning = false;
    monitorThread.join();
    WlanCloseHandle(clientHandle, NULL);

    WriteLog("Service worker thread stopped");
    return ERROR_SUCCESS;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    // 1. FIRST: Register control handler
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == NULL) {
        return;
    }

    // 2. SECOND: Tell SCM we're starting (IMMEDIATELY)
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 10000; // 10 seconds should be enough

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // 3. NOW we can do initialization work
    CreateDirectory(TEXT("C:\\ProgramData\\VITWiFiLogin"), NULL);
    logFile.open(LOG_FILE, ios::app);
    WriteLog("Service starting...");

    // 4. Create the stop event
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        WriteLog("CreateEvent failed");
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        logFile.close();
        return;
    }

    // 5. Create worker thread
    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (hThread == NULL) {
        WriteLog("CreateThread failed");
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        CloseHandle(g_ServiceStopEvent);
        logFile.close();
        return;
    }

    // 6. Tell SCM we're RUNNING (don't wait for thread to finish init)
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    WriteLog("Service running");

    // 7. Wait for stop signal
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(g_ServiceStopEvent);

    // 8. Report stopped status
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    WriteLog("Service stopped");
    logFile.close();
}

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        CreateDirectory(TEXT("C:\\ProgramData\\VITWiFiLogin"), NULL);
        logFile.open("C:\\ProgramData\\VITWiFiLogin\\debug.log", ios::app);
        WriteLog("Running in DEBUG mode, bypassing SCM...");

        // directly run worker thread
        ServiceWorkerThread(nullptr);

        WriteLog("DEBUG mode shutdown");
        logFile.close();
        return 0;
    }

    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        return GetLastError();
    }

    return 0;
}
