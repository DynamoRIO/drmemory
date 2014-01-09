/* **********************************************************
 * Copyright (c) 2013 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* i#1317: we exclude this test if MFC is not available */
#ifdef MFC_SUPPORTED /* around whole file */

#include "gtest/gtest.h"

#define UNICODE 1
#include <atlbase.h>
#include <atlwin.h>

/* These hardcoded constants are pulled out of auto-generated files in an
 * ATL project, to make a self-contained test here.
 */
DEFINE_GUID(LIBID_ATL_exampleLib,0x85AD8018,0xBEFA,0x4795,0x84,0xC0,0x15,0x36,0xC5,0x3B,0x82,0x13);
const IID LIBID_ATL_exampleLib;
#define IDR_ATL_EXAMPLE  101

class CATL_exampleModule : public ATL::CAtlExeModuleT< CATL_exampleModule > {
public:
    DECLARE_LIBID(LIBID_ATL_exampleLib)
    DECLARE_REGISTRY_APPID_RESOURCEID(IDR_ATL_EXAMPLE, "{FBC169A6-284F-4774-BDAA-B0F9457B4A31}")
};

CATL_exampleModule _AtlModule;

class MyWindow
    : public ATL::CWindowImpl<MyWindow, ATL::CWindow, ATL::CFrameWinTraits> {
public:
    DECLARE_WND_CLASS(L"MyWindow")

    MyWindow() {
        RECT rect = { 0, 0, 40, 50 };
        Create(NULL, rect, NULL);
    }
    ~MyWindow() { DestroyWindow(); }

private:
    BEGIN_MSG_MAP(MyWindow)
    MESSAGE_HANDLER(WM_CREATE, OnCreate)
    END_MSG_MAP()

    LRESULT OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled) {
        /* Test i#1303: create a CAxWindow */
        ATL::CAxWindow2 activex_window;
        RECT rect = { 0, 0, 40, 50 };
        activex_window.Create(m_hWnd, rect, NULL, WS_CHILD | WS_VISIBLE | WS_BORDER);
        if (activex_window.m_hWnd == NULL) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        return 0;
    }
};

TEST(ATLTests, CAxWindowTest) {
    /* Just create the window and it will end up hitting i#1303 */
    MyWindow window;
}

#endif /* MFC_SUPPORTED: around whole file */
