#include <windows.h>
#include <wlanapi.h>
#include <wininet.h>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <atomic>
#include <thread>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "wininet.lib")

using namespace std;

mutex mtx;
bool shouldCheckSSID = false;
HANDLE g_clientHandle = NULL;
atomic<bool> isRunning(true);

string getTimestamp() {
    time_t t = time(0);
    tm *now = localtime(&t);

    ostringstream oss;
    oss << "[ " << (now->tm_year + 1900) << '-'
         << setw(2) << setfill('0') << (now->tm_mon + 1) << '-'
         << setw(2) << setfill('0') << now->tm_mday << " " 
         << setw(2) << setfill('0') << now->tm_hour << ":" 
         << setw(2) << setfill('0') << now->tm_min << ":" 
         << setw(2) << setfill('0') << now->tm_sec << " ] ";
    
    return oss.str();
}


bool loginToVit() {
    HINTERNET hInternet = InternetOpen(
        TEXT("VIT-Login"),
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0
    );

    if (!hInternet) {
        cout << getTimestamp() << "Failed to initialize internet connection" << endl;
        return false;
    }

    HINTERNET hConnect = InternetConnect(
        hInternet,
        TEXT("phc.prontonetworks.com"),
        INTERNET_DEFAULT_HTTP_PORT,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        0
    );

    if (!hConnect) {
        InternetCloseHandle(hInternet);
        cout << getTimestamp() << "Failed to connect to Pronto server" << endl;
        return false;
    }

    HINTERNET hRequest = HttpOpenRequest(
        hConnect,
        TEXT("POST"),
        TEXT("/cgi-bin/authlogin?URI=http://example.com"),
        NULL,
        NULL,
        NULL,
        0,
        0
    );

    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        cout << getTimestamp() << "Failed to create HTTP request" << endl;
        return false;
    }

    string postData = "userId=22BCT1234&password=YOUR_URI_ENCODED_PASSWORD&serviceName=ProntoAuthentication";
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
            cout << getTimestamp() << "Login response status: " << statusCode << endl;
            success = (statusCode == 200 || statusCode == 302);
        }
    } else {
        cout << getTimestamp() << "Failed to send login request" << endl;
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

        if (!isRunning) {
            break;
        }

        string ssid = getSSID(g_clientHandle);

        if (!ssid.empty() && ssid.find("VIT") != string::npos) {
            if (needsLogin()) {
                cout << getTimestamp() << "Captive portal detected (possible logout)" << endl;
                cout << getTimestamp() << "Re-authenticating..." << endl;
                
                if (loginToVit()) {
                    cout << getTimestamp() << "Re-authentication successful!" << endl;
                } else {
                    cout << getTimestamp() << "Re-authentication failed" << endl;
                }
            }
        }
    }
}

VOID WINAPI wlanCallback(
        PWLAN_NOTIFICATION_DATA data,
        PVOID context
    ) {
    if (!data) return;
    

    if (data->NotificationCode == wlan_notification_acm_connection_complete) {
        lock_guard<mutex> lock(mtx);
        shouldCheckSSID = true;
    }
    
    switch (data->NotificationCode) {
    case wlan_notification_acm_connection_complete:
        cout << getTimestamp() << "Connected to wifi" << endl;
        break;
    case wlan_notification_acm_disconnected:
        cout << getTimestamp() << "Disconnected" << endl;
        break;
    case wlan_notification_acm_connection_start:
        cout << getTimestamp() << "Connecting" << endl;
        break;
    default:
        cout << getTimestamp() <<"wifi event: " << data->NotificationCode << endl;
    }
}

int main() {
    DWORD negotiatedVersion;
    HANDLE clientHandle;

    DWORD result = WlanOpenHandle(
        2,
        NULL,
        &negotiatedVersion,
        &clientHandle
    );

    if (result != ERROR_SUCCESS) {
        cout << "WlanOpenHandle failed" << endl;
        return 1;
    }

    g_clientHandle = clientHandle;

    result = WlanRegisterNotification(
        clientHandle,
        WLAN_NOTIFICATION_SOURCE_ACM,
        TRUE,
        (WLAN_NOTIFICATION_CALLBACK)wlanCallback,
        NULL,
        NULL,
        NULL
    );

    if (result != ERROR_SUCCESS) {
        cout << "WlanRegisterNotification failed" << endl;
        return 1;
    }

    cout << "Listening for wifi events..." << endl;

    string ssid = getSSID(g_clientHandle);
    if (!ssid.empty()) {
        cout << getTimestamp() << "Current SSID at startup: " << ssid << endl;

        if (ssid.find("VIT") != string::npos) {
            if (needsLogin()) {
                cout << getTimestamp() << "Login required for network: " << ssid << endl;
                cout << getTimestamp() << "Attempting VIT network login..." << endl;
                
                if (loginToVit()) {
                    cout << getTimestamp() << "Login successful!" << endl;
                } else {
                    cout << getTimestamp() << "Login failed" << endl;
                }
            } else {
                cout << getTimestamp() << "Already authenticated" << endl;
            }
        } else {
            cout << getTimestamp() << "Not a VIT network" << endl;
        }
    } else {
        cout << getTimestamp() << "Not connected to any network" << endl;
    }

    thread monitorThread(captivePortalMonitor);
    cout << getTimestamp() << "Started captive portal monitor" << endl;

    while (true) { // main thread
        lock_guard<mutex> lock(mtx);
        if (shouldCheckSSID) {
            
            shouldCheckSSID = false;
            string ssid = getSSID(g_clientHandle);

            if (!ssid.empty()) {
                cout << getTimestamp() << "Current SSID: " << ssid << endl;

                if (ssid.find("VIT") != string::npos) {
                    if (needsLogin()) {
                        cout << getTimestamp() << "Login required for network: " << ssid << endl;
                        cout << getTimestamp() << "Attempting VIT network login..." << endl;
                        
                        if (loginToVit()) {
                            cout << getTimestamp() << "Login successful!" << endl;
                        } else {
                            cout << getTimestamp() << "Login failed" << endl;
                        }
                    } else {
                        cout << getTimestamp() << "Already authenticated" << endl;
                    }
                } else {
                    cout << getTimestamp() << "Not a VIT network, skipping login" << endl;
                }
            }
        }
        Sleep(1000);
    }

    isRunning = false;
    monitorThread.join();
    WlanCloseHandle(clientHandle, NULL);
    return 0;
}