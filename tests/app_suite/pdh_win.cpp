/* The code in this file is based on sample code from Microsoft.
 *
 *   Coypright (c) 2010 Microsoft Corporation.  All rights reserved.
 *
 * It is included here under the MICROSOFT LIMITED PUBLIC LICENSE:
 *
 * This license governs use of code marked as "sample" or "example"
 * available on this web site without a license agreement, as provided
 * under the section above titled "NOTICE SPECIFIC TO SOFTWARE AVAILABLE
 * ON THIS WEB SITE." If you use such code (the "software"), you accept
 * this license. If you do not accept the license, do not use the
 * software.
 *
 * 1. Definitions
 *
 * The terms "reproduce," "reproduction," "derivative works," and
 * "distribution" have the same meaning here as under U.S. copyright law.
 *
 * A "contribution" is the original software, or any additions or changes
 * to the software.
 *
 * A "contributor" is any person that distributes its contribution under
 * this license.
 *
 * "Licensed patents" are a contributor's patent claims that read
 * directly on its contribution.
 *
 * 2. Grant of Rights
 *
 * (A) Copyright Grant - Subject to the terms of this license, including
 * the license conditions and limitations in section 3, each contributor
 * grants you a non-exclusive, worldwide, royalty-free copyright license
 * to reproduce its contribution, prepare derivative works of its
 * contribution, and distribute its contribution or any derivative works
 * that you create.
 *
 * (B) Patent Grant - Subject to the terms of this license, including the
 * license conditions and limitations in section 3, each contributor
 * grants you a non-exclusive, worldwide, royalty-free license under its
 * licensed patents to make, have made, use, sell, offer for sale,
 * import, and/or otherwise dispose of its contribution in the software
 * or derivative works of the contribution in the software.
 *
 * 3. Conditions and Limitations
 *
 * (A) No Trademark License- This license does not grant you rights to
 * use any contributors' name, logo, or trademarks.
 *
 * (B) If you bring a patent claim against any contributor over patents
 * that you claim are infringed by the software, your patent license from
 * such contributor to the software ends automatically.
 *
 * (C) If you distribute any portion of the software, you must retain all
 * copyright, patent, trademark, and attribution notices that are present
 * in the software.
 *
 * (D) If you distribute any portion of the software in source code form,
 * you may do so only under this license by including a complete copy of
 * this license with your distribution.  If you distribute any portion of
 * the software in compiled or object code form, you may only do so under
 * a license that complies with this license.
 *
 * (E) The software is licensed "as-is." You bear the risk of using
 * it. The contributors give no express warranties, guarantees or
 * conditions.  You may have additional consumer rights under your local
 * laws which this license cannot change. To the extent permitted under
 * your local laws, the contributors exclude the implied warranties of
 * merchantability, fitness for a particular purpose and
 * non-infringement.
 *
 * (F) Platform Limitation - The licenses granted in sections 2(A) and
 * 2(B) extend only to the software or derivative works that you create
 * that run on a Microsoft Windows operating system product.
 */

/* PDH (Performance Data Helper) example */

#define UNICODE

#include <windows.h>
#include <stdio.h>
#include <pdh.h>
#include <pdhmsg.h>
#include "gtest/gtest.h"

#pragma comment(lib, "pdh.lib")

CONST PWSTR COUNTER_PATH    = L"\\Processor(0)\\% Processor Time";
CONST ULONG SAMPLE_INTERVAL_MS = 50;
CONST ULONG SAMPLE_COUNT = 2;
CONST PWSTR LOG_FILE = L"PerfDataLog.log";

TEST(PDH, PerfDataLog)
{
    HQUERY hQuery = NULL;
    HLOG hLog = NULL;
    PDH_STATUS pdhStatus;
    DWORD dwLogType = PDH_LOG_TYPE_CSV;
    HCOUNTER hCounter;
    DWORD dwCount;

    // Open a query object.
    pdhStatus = PdhOpenQuery(NULL, 0, &hQuery);

    if (pdhStatus != ERROR_SUCCESS)
    {
        wprintf(L"PdhOpenQuery failed with 0x%x\n", pdhStatus);
        goto cleanup;
    }

    // Add one counter that will provide the data.
    pdhStatus = PdhAddCounter(hQuery,
        COUNTER_PATH,
        0,
        &hCounter);

    if (pdhStatus != ERROR_SUCCESS)
    {
        wprintf(L"PdhAddCounter failed with 0x%x\n", pdhStatus);
        goto cleanup;
    }

    // Open the log file for write access.
    pdhStatus = PdhOpenLog(LOG_FILE,
        PDH_LOG_WRITE_ACCESS | PDH_LOG_CREATE_ALWAYS,
        &dwLogType,
        hQuery,
        0,
        NULL,
        &hLog);

    if (pdhStatus != ERROR_SUCCESS)
    {
        wprintf(L"PdhOpenLog failed with 0x%x\n", pdhStatus);
        goto cleanup;
    }

    // Write some records to the log file.
    for (dwCount = 0; dwCount < SAMPLE_COUNT; dwCount++)
    {
        wprintf(L"Writing record %d\n", dwCount);

        pdhStatus = PdhUpdateLog (hLog, NULL);
        if (ERROR_SUCCESS != pdhStatus)
        {
            wprintf(L"PdhUpdateLog failed with 0x%x\n", pdhStatus);
            goto cleanup;
        }

        // Wait between samples for a counter update.
        Sleep(SAMPLE_INTERVAL_MS);
    }

cleanup:

    // Close the log file.
    if (hLog)
        PdhCloseLog (hLog, 0);

    // Close the query object.
    if (hQuery)
        PdhCloseQuery (hQuery);
}
