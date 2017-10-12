/* ***************************************************************************
 * Copyright (c) 2017 Google, Inc.  All rights reserved.
 * ***************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <Windows.h>
#include <Wininet.h>
#include <Nspapi.h>
#include <shlobj.h>
#include <atlbase.h>
#include <shlobj.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")

#define MAX_KEY_VALUE_LEN 512
#define TEST_VALUE_TO_CONVERT 1453
#define TEST_STR_TO_CONVERT L"01453"

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

void exit(unsigned int exit_code)
{
    TerminateProcess(GetCurrentProcess(), exit_code);
}

void print_error_and_exit(const char *msg)
{
    printf("%s, GetLastError = %d", msg, GetLastError());
    exit(-1);
}

void call_advapi32()
{
    /* functions from advapi32.dll */
    HKEY hKey;
    WCHAR szBuffer[MAX_KEY_VALUE_LEN];
    DWORD dwBufferSize = sizeof(szBuffer);
    LONG lRes;

    lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                         0, KEY_READ, &hKey);
    if (lRes != ERROR_SUCCESS)
        print_error_and_exit("RegOpenKeyExW failed");

    lRes = RegQueryValueExW(hKey, L"TestKey", 0, NULL,
                            (LPBYTE)szBuffer, &dwBufferSize);
    if (lRes != ERROR_FILE_NOT_FOUND)
        print_error_and_exit("RegQueryValueExW returned unexpected value");

    lRes = RegCloseKey(hKey);
    if (lRes != ERROR_SUCCESS)
        print_error_and_exit("RegCloseKey failed");

    printf("tests for advapi32.dll successfully done\n");
}

void call_gdi32_user32()
{
    /* group of functions from gdi32.dll/user32.dll */
    HWND hwnd;
    RECT rect;
    HGDIOBJ hObj;
    HFONT hFont;
    PAINTSTRUCT ps;
    HDC hdc;
    const wchar_t CLASS_NAME[] = L"Sample Window Class";
    ATOM result = 0;
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = CLASS_NAME;

    if (RegisterClassW(&wc) == NULL)
        print_error_and_exit("RegisterClassW");

    hwnd = CreateWindowW(CLASS_NAME, L"Test Window", WS_OVERLAPPEDWINDOW,
                         CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                         CW_USEDEFAULT, NULL, NULL, wc.hInstance, NULL);
    if (hwnd == NULL)
        print_error_and_exit("CreateWindowW failed");

    hdc = BeginPaint(hwnd, &ps);
    if (hdc == NULL)
        print_error_and_exit("BeginPaint failed");

    hFont = CreateFontA(48, 0, 0, 0, FW_DONTCARE, FALSE, TRUE, FALSE,
                        DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
                        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH,
                        TEXT("Test CreateFont"));
    if (hFont == NULL)
        print_error_and_exit("CreateFontA failed");

    hObj = SelectObject(hdc, hFont);
    if (hObj == NULL || hObj == HGDI_ERROR)
        print_error_and_exit("SelectObject failed");

    /* Sets the coordinates for the rectangle in which the text is to be
     * formatted.
     */
    if (SetRect(&rect, 100, 100, 700, 200) == NULL)
        print_error_and_exit("SetRect failed");

    if (SetTextColor(hdc, RGB(255, 0, 0)) == CLR_INVALID)
        print_error_and_exit("SetTextColor failed");

    if (DrawTextW(hdc, L"Test Text", -1, &rect, DT_NOCLIP) == NULL)
        print_error_and_exit("DrawTextW failed");

    if (DeleteObject(hObj) == false)
        print_error_and_exit("DeleteObject failed");

    if (DestroyWindow(hwnd) == false)
        print_error_and_exit("DestroyWindow failed");

    if (UnregisterClassW(CLASS_NAME, wc.hInstance) == false)
        print_error_and_exit("UnregisterClassW failed");

    printf("tests for user32/gdi32 dlls successfully done\n");
}

void call_wininet()
{
    /* functions from wininet.dll */
    URL_COMPONENTSW url;
    LPWSTR url_created = (LPWSTR)malloc(1024);
    LPWSTR url_canonic = (LPWSTR)malloc(1024);
    DWORD cchBuffer = 1024, cchBuffer2 = 1024;
    url.dwStructSize = sizeof(url);
    url.lpszScheme = NULL;
    url.dwSchemeLength = 0;
    url.nScheme = INTERNET_SCHEME_DEFAULT;
    url.lpszHostName = NULL;
    url.dwHostNameLength = NULL;
    url.lpszUrlPath = L"drmemory.org/ docs";
    url.dwUrlPathLength = wcslen(L"drmemory.org/ docs");
    url.nPort = INTERNET_DEFAULT_HTTP_PORT;
    url.lpszUserName = NULL;
    url.dwUserNameLength = NULL;
    url.lpszPassword = NULL;
    url.dwPasswordLength = NULL;
    url.lpszExtraInfo = NULL;
    url.dwExtraInfoLength = NULL;

    if (!InternetCreateUrlW(&url, 0, url_created, &cchBuffer))
        print_error_and_exit("InternetCreateUrlW failed");

    if (!InternetCanonicalizeUrlW(url_created, url_canonic, &cchBuffer2,
                                  ICU_ESCAPE))
        print_error_and_exit("InternetCanonicalizeUrlW failed");

    printf("created url = %ws\ncanonicalized url = %ws\n", url_created,
           url_canonic);
    free(url_created);
    free(url_canonic);
    printf("tests for wininet.dll successfully done\n");
}

void call_w2_32_wsock32()
{
    /* functions from w2_32.dll and wsock32.dll */
    int error_code;
    GUID guid;

    /* WSAStartup should be called before gethostbyname, so the function below
     * will always fail (to test on machines without Internet access).
     */
    gethostbyname("http://drmemory.org");
    error_code = WSAGetLastError();
    if (error_code != WSANOTINITIALISED) {
        printf("gethostbyname returned unexpected error code = %d", error_code);
        exit(-1);
    }

    error_code = GetTypeByNameA("TEST SERVER", &guid);
    if (error_code != SOCKET_ERROR) {
        printf("GetTypeByNameA returned unexpected error code = %d",
               error_code);
        exit(-1);
    }
    printf("tests for w2_32.dll and wsock32.dll successfully done\n");
}

void call_oleaut32()
{
    /* functions from oleaut32.dll */
    int error_code;
    long value = 0;

    LCID locale = GetThreadLocale();
    error_code = VarI4FromStr(TEST_STR_TO_CONVERT, locale,
                              LOCALE_NOUSEROVERRIDE, &value);
    if (error_code != S_OK)
        print_error_and_exit("VarI4FromStr failed");

    if (value != TEST_VALUE_TO_CONVERT) {
        printf("VarI4FromStr failed to convert the string, error code = %d",
               error_code);
        exit(-1);
    }
    printf("tests for oleaut32.dll successfully done\n");

}

void call_ole32()
{
    /* functions from ole32.dll */
    HRESULT res;

    res = OleInitialize(NULL);
    if (res != S_OK)
        print_error_and_exit("OleInitialize failed");

    CComPtr<IDataObject> spdto;
    res = OleSetClipboard(spdto);
    if (res != S_OK)
        print_error_and_exit("OleSetClipboard failed");

    spdto.Release();
    OleUninitialize();
    printf("tests for ole32.dll successfully done\n");
}

void call_shlwapi_shell32()
{
    /* functions from shlwapi.dll and shell32.dll */
    HRESULT res;

    PARSEDURLW *parsed_url = (PARSEDURLW *)malloc(sizeof(PARSEDURLW));
    parsed_url->cbSize = sizeof(PARSEDURLW);

    if (!PathIsExe(L"C:\\Windows\\System32\\calc.exe"))
        print_error_and_exit("PathIsExe failed");

    res = ParseURLW(L"http://drmemory.org/docs", parsed_url);
    if (res != S_OK)
        print_error_and_exit("ParseURLW failed");

    free(parsed_url);
    printf("tests for shlwapi.dll and shell32.dll successfully done\n");
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int _tmain(int argc, _TCHAR* argv[])
{
    call_advapi32();
    call_gdi32_user32();
    call_wininet();
    call_w2_32_wsock32();
    call_oleaut32();
    call_ole32();
    call_shlwapi_shell32();
    printf("All tests successfully done\n");
    return 0;
}

