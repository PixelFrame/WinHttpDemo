#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>

#pragma comment (lib, "winhttp.lib")

LPWSTR Str2Wstr(LPSTR lpStr)
{
    // !! DELELTE THE RETURNED STRING AFTER USING !!
    int len = MultiByteToWideChar(CP_OEMCP, 0, lpStr, -1, NULL, 0);
    LPWSTR lpwStr = new wchar_t[len];
    MultiByteToWideChar(CP_OEMCP, 0, lpStr, -1, lpwStr, len);
    return lpwStr;
}

LPSTR Wstr2Str(LPWSTR lpwStr)
{
    // !! DELELTE THE RETURNED STRING AFTER USING !!
    int len = WideCharToMultiByte(CP_OEMCP, 0, lpwStr, -1, NULL, 0, NULL, NULL);
    LPSTR lpStr = new char[len];
    WideCharToMultiByte(CP_OEMCP, 0, lpwStr, -1, lpStr, len, NULL, NULL);
    return lpStr;
}

void PrintDebug(LPSTR function, LPSTR additionInfo)
{
    std::cout << "Entering " << std::left << std::setw(25) << function << additionInfo << "\n";
}

void PrintProxyInfo(WINHTTP_PROXY_INFO proxyInfo)
{
    LPSTR lpStr;

    std::string strAccessType = "Internet accessed through a direct connection.";
    std::string strProxy = "Not Configured";
    std::string strProxyBypass = "Not Configured";

    switch (proxyInfo.dwAccessType)
    {
    case WINHTTP_ACCESS_TYPE_DEFAULT_PROXY:
        strAccessType = "Applies only when setting proxy information."; break;
    case WINHTTP_ACCESS_TYPE_NAMED_PROXY:
        strAccessType = "Internet accessed using a proxy."; break;
    default:
        break;
    }
    if (proxyInfo.lpszProxy)
    {
        lpStr = Wstr2Str(proxyInfo.lpszProxy);
        strProxy = lpStr;
        delete[] lpStr;
    }
    if (proxyInfo.lpszProxyBypass)
    {
        lpStr = Wstr2Str(proxyInfo.lpszProxyBypass);
        strProxyBypass = lpStr;
        delete[] lpStr;
    }
    std::cout << std::left << std::setw(25) << "    Access Type:" << strAccessType << '\n'
        << std::left << std::setw(25) << "    Proxy Server:" << strProxy << '\n'
        << std::left << std::setw(25) << "    Proxy Bypass:" << strProxyBypass << "\n\n";
}

void PrintIEProxyConfig(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG IEProxyConfig)
{
    std::string strAutoDetect = "false";
    std::string strAutoConfigUrl = "Not Configured";
    std::string strProxy = "Not Configured";
    std::string strProxyBypass = "Not Configured";
    LPSTR lpStr;

    if (IEProxyConfig.fAutoDetect)
    {
        strAutoDetect = "true";
    }
    if (IEProxyConfig.lpszAutoConfigUrl)
    {
        lpStr = Wstr2Str(IEProxyConfig.lpszAutoConfigUrl);
        strAutoConfigUrl = lpStr;
        delete[] lpStr;
    }
    if (IEProxyConfig.lpszProxy)
    {
        lpStr = Wstr2Str(IEProxyConfig.lpszProxy);
        strProxy = lpStr;
        delete[] lpStr;
    }
    if (IEProxyConfig.lpszProxyBypass)
    {
        lpStr = Wstr2Str(IEProxyConfig.lpszProxyBypass);
        strProxyBypass = lpStr;
        delete[] lpStr;
    }
    std::cout << "\rIE Proxy:                        \n"
        << std::left << std::setw(25) << "    Auto Detect:" << strAutoDetect << '\n'
        << std::left << std::setw(25) << "    Auto Config URL:" << strAutoConfigUrl << '\n'
        << std::left << std::setw(25) << "    Proxy Server:" << strProxy << '\n'
        << std::left << std::setw(25) << "    Proxy Bypass:" << strProxyBypass << "\n\n";
}

void WriteResponse(std::string strResponse)
{
    struct tm ltm;
    time_t now = time(0);
    localtime_s(&ltm, &now);
    std::stringstream ssOutFile;
    ssOutFile << ".\\WinHttpResponse-" << (ltm.tm_year + 1900) << "-" 
        << std::setw(2) << std::setfill('0') << std::right << ltm.tm_mon << "-"
        << std::setw(2) << std::setfill('0') << std::right << ltm.tm_mday << "_"
        << std::setw(2) << std::setfill('0') << std::right << ltm.tm_hour 
        << std::setw(2) << std::setfill('0') << std::right << ltm.tm_min 
        << std::setw(2) << std::setfill('0') << std::right << ltm.tm_sec
        << ".txt";

    std::cout << "Writing Response to file: " << ssOutFile.str() << "\n";
    std::ofstream fsOutput(ssOutFile.str());
    fsOutput << strResponse;
    fsOutput.close();
}

void DoRequest(LPTSTR pszHost, INTERNET_PORT nPort, LPTSTR pszPath, BOOL isHttps, DWORD dwAccessType, LPTSTR pszProxyServer, LPTSTR pszBypassList)
{
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    WINHTTP_PROXY_INFO proxyInfo;
    DWORD dwInfoSize = sizeof(WINHTTP_PROXY_INFO);
    std::string strResponse;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        dwAccessType,
        pszProxyServer,
        pszBypassList, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, pszHost,
            nPort, 0);

    // Create an HTTP request handle.
    if (isHttps)
    {
        if (hConnect)
            hRequest = WinHttpOpenRequest(hConnect, L"GET", pszPath,
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE);
    }
    else
    {
        if (hConnect)
            hRequest = WinHttpOpenRequest(hConnect, L"GET", pszPath,
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                NULL);
    }

    // Send a request.
    if (hRequest)
    {
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    }

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep checking for data until there is nothing left.
    if (bResults)
    {
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                std::cout << "Error " << GetLastError() << " in WinHttpQueryDataAvailable.\n";

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                std::cout << "Out of memory\n";
                dwSize = 0;
            }
            else
            {
                // Read the data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    std::cout << "Error " << GetLastError() << " in WinHttpReadData.\n";
                else
                    strResponse += pszOutBuffer;

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }
        } while (dwSize > 0);
    }

    // Report any errors.
    if (!bResults)
        std::cout << "Error " << GetLastError() << " has occurred.\n";

    // Print Response.
    if (!strResponse.empty())
    {
        std::cout << "Got Response From Server\n";
        WriteResponse(strResponse);
    }

    // Print Proxy Info
    std::cout << "Print Request Proxy Info:\n";
    ZeroMemory(&proxyInfo, sizeof(proxyInfo));
    if (WinHttpQueryOption(hRequest,
        WINHTTP_OPTION_PROXY,
        &proxyInfo, &dwInfoSize))
    {
        PrintProxyInfo(proxyInfo);
    }
    else
    {
        std::cout << "Unable to retrieve proxy info. Error: " << GetLastError() << "\n\n";
    }

    // Clean Up
    if (proxyInfo.lpszProxy != NULL)
        GlobalFree(proxyInfo.lpszProxy);
    if (proxyInfo.lpszProxyBypass != NULL)
        GlobalFree(proxyInfo.lpszProxyBypass);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}

void CrackUrl(LPTSTR pszUrl, std::wstring* pwstrHostname, std::wstring* pwstrPath, INTERNET_PORT* pnPort, BOOL* pisHttps)
{
    URL_COMPONENTS urlComp;
    DWORD dwUrlLen = 0;
    std::wstring wstrHostname;

    // Initialize the URL_COMPONENTS structure.
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    // Set required component lengths to non-zero, 
    // so that they are cracked.
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;

    // Crack the URL.
    if (!WinHttpCrackUrl(pszUrl, (DWORD)wcslen(pszUrl), 0, &urlComp))
    {
        std::cout << "Error " << GetLastError() << " in WinHttpCrackUrl.\n";
    }

    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS)
    {
        *pisHttps = TRUE;
    }
    *pwstrHostname = std::wstring(urlComp.lpszHostName, urlComp.dwHostNameLength);
    *pwstrPath = std::wstring(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    *pnPort = urlComp.nPort;
}

void RefreshProxy(HINTERNET hSession)
{
    std::string strConfirm = "";
    while (strConfirm != "Y" && strConfirm != "N")
    {
        std::cout << "Refresh AutoProxy? Y/N ";
        std::cin >> strConfirm;
    }
    if (strConfirm == "Y")
    {
        DWORD dwFlags = WINHTTP_RESET_ALL | WINHTTP_RESET_OUT_OF_PROC | WINHTTP_RESET_NOTIFY_NETWORK_CHANGED;
        DWORD dwRes = WinHttpResetAutoProxy(hSession, dwFlags);
        if (dwRes == ERROR_SUCCESS)
        {
            std::cout << "Refreshed AutoProxy\n\n";
        }
        else
        {
            std::cout << "Refresh Failed: " << dwRes << "\n\n";
        }
    }
}

void WebRequestDefaultProxy(LPTSTR pszUrl)
{
    BOOL isHttps = FALSE;
    INTERNET_PORT nPort;
    std::wstring wstrHostname;
    std::wstring wstrPath;

    CrackUrl(pszUrl, &wstrHostname, &wstrPath, &nPort, &isHttps);

    DoRequest(&wstrHostname[0], 
              nPort, 
              &wstrPath[0],
              isHttps,
              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
              WINHTTP_NO_PROXY_NAME, 
              WINHTTP_NO_PROXY_BYPASS);
}

void WebRequestNamedProxy(LPTSTR pszUrl, LPTSTR pszProxyServer, LPTSTR pszBypassList)
{
    BOOL isHttps = FALSE;
    INTERNET_PORT nPort;
    std::wstring wstrHostname;
    std::wstring wstrPath;

    CrackUrl(pszUrl, &wstrHostname, &wstrPath, &nPort, &isHttps);

    DoRequest(&wstrHostname[0],
        nPort,
        &wstrPath[0],
        isHttps,
        WINHTTP_ACCESS_TYPE_NAMED_PROXY,
        pszProxyServer,
        pszBypassList);
}

void WebRequestConfigUrl(LPTSTR pszUrl, LPTSTR pszConfigUrl)
{
    BOOL isHttps = FALSE;
    INTERNET_PORT nPort;
    std::wstring wstrHostname;
    std::wstring wstrPath;

    HINTERNET hSession = NULL;
    WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions;
    WINHTTP_PROXY_INFO proxyInfo;

    ZeroMemory(&autoProxyOptions, sizeof(WINHTTP_AUTOPROXY_OPTIONS));

    autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
    autoProxyOptions.lpszAutoConfigUrl = pszConfigUrl;
    autoProxyOptions.fAutoLogonIfChallenged = true;

    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (hSession)
    {
        std::cout << "Calling WinHttpGetProxyForUrl to Download Proxy Script and Resolve Host\n";
        if (WinHttpGetProxyForUrl(hSession, pszUrl, &autoProxyOptions, &proxyInfo))
        {
            CrackUrl(pszUrl, &wstrHostname, &wstrPath, &nPort, &isHttps);
            DoRequest(&wstrHostname[0],
                nPort,
                &wstrPath[0],
                isHttps,
                proxyInfo.dwAccessType,
                proxyInfo.lpszProxy,
                proxyInfo.lpszProxyBypass);
        }
        else
            std::cout << "\rWinHttpGetProxyForUrl Failed                                                         \n"
                << std::left << std::setw(25) << "    Error Code: " << GetLastError();
    }
}

void WebRequestAutoProxy(LPTSTR pszUrl)
{
    BOOL isHttps = FALSE;
    INTERNET_PORT nPort;
    std::wstring wstrHostname;
    std::wstring wstrPath;

    CrackUrl(pszUrl, &wstrHostname, &wstrPath, &nPort, &isHttps);

    DoRequest(&wstrHostname[0],
        nPort,
        &wstrPath[0],
        isHttps,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS);
}

void WebRequestDirect(LPTSTR pszUrl)
{
    BOOL isHttps = FALSE;
    INTERNET_PORT nPort;
    std::wstring wstrHostname;
    std::wstring wstrPath;

    CrackUrl(pszUrl, &wstrHostname, &wstrPath, &nPort, &isHttps);

    DoRequest(&wstrHostname[0],
        nPort,
        &wstrPath[0],
        isHttps,
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS);
}

void WebRequestIEProxy(LPTSTR pszUrl)
{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG IEProxyConfig;
    if (WinHttpGetIEProxyConfigForCurrentUser(&IEProxyConfig))
    {
        if (IEProxyConfig.fAutoDetect)
        {
            std::cout << "Auto Detect is Set. Calling Auto Proxy Web Request...\n";
            WebRequestAutoProxy(pszUrl);
        }
        else
        {
            if (IEProxyConfig.lpszAutoConfigUrl != NULL)
            {
                std::cout << "Auto Proxy URL is Set. Calling Auto Config URL Web Request...\n";
                WebRequestConfigUrl(pszUrl, IEProxyConfig.lpszAutoConfigUrl);
                return;
            }
            if (IEProxyConfig.lpszProxy != NULL)
            {
                std::cout << "Static Proxy is Set. Calling Named Proxy Web Request...\n";
                WebRequestNamedProxy(pszUrl, IEProxyConfig.lpszProxy, IEProxyConfig.lpszAutoConfigUrl);
                return;
            }
            std::cout << "No Proxy is Set. Calling Direct Access Web Request...\n";
            WebRequestDirect(pszUrl);
        }
    }
    else
    {
        std::cout << "IE Proxy Not Found. Error: " << GetLastError() << "\n";
    }
}

void WebRequestProxyCheck(LPTSTR pszUrl)
{
    BOOL isHttps = FALSE;
    INTERNET_PORT nPort;
    std::wstring wstrHostname;
    std::wstring wstrPath;
    LPWSTR pwszAutoConfigUrl;
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG IEProxyConfig;
    WINHTTP_PROXY_INFO proxyInfo;

    HINTERNET hSession;
    WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions;

    LPSTR lpStr;

    CrackUrl(pszUrl, &wstrHostname, &wstrPath, &nPort, &isHttps);
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    RefreshProxy(hSession);

    std::cout << "Detecting Auto Proxy...";
    if (WinHttpDetectAutoProxyConfigUrl(
        WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A,
        &pwszAutoConfigUrl
    ))
    {
        lpStr = Wstr2Str(pwszAutoConfigUrl);
        std::string strAutoConfigUrl = lpStr;
        std::cout << "\rAuto Proxy:                        \n"
            << std::left << std::setw(25) << "    Script URL: " << strAutoConfigUrl << "\n\n";
        delete[] lpStr;
    }
    else
        std::cout << "\rAuto Proxy:                        \n    Not Detected\n\n";

    std::cout << "Detecting IE Proxy...";
    if (WinHttpGetIEProxyConfigForCurrentUser(&IEProxyConfig))
    {
        PrintIEProxyConfig(IEProxyConfig);
    }
    else
        std::cout << "\rIE Proxy:                        \n    Not Detected\n\n";

    std::cout << "Detecting WinHTTP default proxy...";
    if (WinHttpGetDefaultProxyConfiguration(&proxyInfo))
    {
        std::cout << "\rWinHTTP Proxy:                         \n";
        PrintProxyInfo(proxyInfo);
    }

    std::cout << "Calling WinHttpGetProxyForUrl...";
    ZeroMemory(&proxyInfo, sizeof(proxyInfo));
    ZeroMemory(&autoProxyOptions, sizeof(autoProxyOptions));
    
    autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
    autoProxyOptions.dwAutoDetectFlags =
        WINHTTP_AUTO_DETECT_TYPE_DHCP |
        WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    autoProxyOptions.fAutoLogonIfChallenged = TRUE;

    if (WinHttpGetProxyForUrl(hSession, pszUrl, &autoProxyOptions, &proxyInfo))
    {
        std::cout << "\rWinHttpGetProxyForUrl Succeeded                      \n";
        PrintProxyInfo(proxyInfo);
    }
    else
        std::cout << "\rWinHttpGetProxyForUrl Failed:                        \n"
            << "    Error Code: " << GetLastError();
    
    if (IEProxyConfig.lpszAutoConfigUrl != NULL)
        GlobalFree(IEProxyConfig.lpszAutoConfigUrl);
    if (IEProxyConfig.lpszProxy != NULL)
        GlobalFree(IEProxyConfig.lpszProxy);
    if (IEProxyConfig.lpszProxyBypass != NULL)
        GlobalFree(IEProxyConfig.lpszProxyBypass);
    if (proxyInfo.lpszProxy != NULL)
        GlobalFree(proxyInfo.lpszProxy);
    if (proxyInfo.lpszProxyBypass != NULL)
        GlobalFree(proxyInfo.lpszProxyBypass);
    if (hSession) WinHttpCloseHandle(hSession);
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cout << "Usage: " << argv[0] << " <URL>\n";
        return 1;
    }
    
    LPWSTR pwszUrl = Str2Wstr(argv[1]);
    std::wstring wstrProxyServer;
    std::wstring wstrBypassList;
    std::wstring wstrConfigUrl;

    int AccessType = 0;
    while (AccessType > 7 || AccessType < 1)
    {
        std::cout << "WinHTTP Proxy and Connection Test Demo Program\n"
            << "----------------------------------------------\n"
            << "Choose Proxy Type:\n"
            << "    1: Auto Proxy" << "\n"
            << "    2: Default(WinHTTP) Proxy" << "\n"
            << "    3: Proxy Configuration URL" << "\n"
            << "    4: Named Proxy" << "\n"
            << "    5: Direct Access" << "\n"
            << "    6: IE(WinINET) Proxy" << "\n"
            << "    7: Proxy Check" << "\n";
        std::cin >> AccessType;
        std::cin.clear();
        std::cin.ignore(1);
    }

    switch (AccessType)
    {
    case 1:
        std::cout << "\nUsing Auto Proxy\n";
        WebRequestAutoProxy(pwszUrl);
        break;
    case 2:
        std::cout << "\nUsing WinHTTP Default Proxy\n";
        WebRequestDefaultProxy(pwszUrl);
        break;
    case 3:
        std::cout << "\nInput Configuration URL:\n";
        std::wcin >> wstrConfigUrl;
        std::wcin.clear();
        std::cout << "\nUsing Specified Configuration URL\n";
        WebRequestConfigUrl(pwszUrl, &wstrConfigUrl[0]);
        break;
    case 4:
        std::cout << "\nInput Proxy Server Address:\n";
        std::wcin >> wstrProxyServer;
        std::wcin.clear();
        std::cout << "Input Bypass List (Semicolon Delimited, * for null):\n";
        std::wcin >> wstrBypassList;
        std::wcin.clear();
        std::cout << "\nUsing Specified Proxy Server\n";
        if (wstrBypassList == L"*")
            WebRequestNamedProxy(pwszUrl, &wstrProxyServer[0], &wstrBypassList[0]);
        else
            WebRequestNamedProxy(pwszUrl, &wstrProxyServer[0], WINHTTP_NO_PROXY_BYPASS);
        break;
    case 5:
        std::cout << "\nDirect Access\n";
        WebRequestDirect(pwszUrl);
        break;
    case 6:
        std::cout << "\nUsing IE Proxy\n";
        WebRequestIEProxy(pwszUrl);
        break;
    case 7:
        std::cout << "\nTest Proxy Configuration for the Target URL\n";
        WebRequestProxyCheck(pwszUrl);
    default:
        break;
    }

    delete[] pwszUrl;

    return 0;
}