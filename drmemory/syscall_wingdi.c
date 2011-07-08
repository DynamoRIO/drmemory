/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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

/* If we set this to _WIN32_WINNT_NT4 we miss types like DESIGNVECTOR in wingdi.h */
#define _WIN32_WINNT 0x0500 /* == _WIN32_WINNT_2K */
#define WINVER _WIN32_WINNT

#include "dr_api.h"
#include "drmemory.h"
#include "syscall.h"
#include "syscall_os.h"
#include "readwrite.h"
#include <stddef.h> /* offsetof */

/* for win32k.sys syscalls */
#include <wingdi.h> /* usually from windows.h; required by winddi.h + ENUMLOGFONTEXDVW */
#define NT_BUILD_ENVIRONMENT 1 /* for d3dnthal.h */
#include <d3dnthal.h>
#include <winddi.h> /* required by ntgdityp.h and prntfont.h */
#include <prntfont.h>
#include "../wininc/ntgdityp.h"
#include <ntgdi.h>
#include <winspool.h> /* for DRIVER_INFO_2W */
#include <dxgiformat.h> /* for DXGI_FORMAT */

#define OK true
#define UNKNOWN false
#define W (SYSARG_WRITE)
#define R (SYSARG_READ)
#define WI (SYSARG_WRITE | SYSARG_LENGTH_INOUT)
#define IB (SYSARG_INLINED_BOOLEAN)
#define RET (SYSARG_POST_SIZE_RETVAL)

/* System calls with wrappers in kernel32.dll (on win7 these are duplicated
 * in kernelbase.dll as well but w/ the same syscall number)
 * Not all wrappers are exported: xref i#388.
 */
syscall_info_t syscall_kernel32_info[] = {
    /* wchar_t *locale OUT, size_t locale_sz */
    {0,"NtWow64CsrBasepNlsGetUserInfo", OK, 8, {{0,-1,W|SYSARG_CSTRING_WIDE}, }},

    /* Takes a single param that's a pointer to a struct that has a PHANDLE at offset
     * 0x7c where the base of a new mmap is stored by the kernel.  We handle that by
     * waiting for RtlCreateActivationContext (i#352).  We don't know of any written
     * values in the rest of the struct or its total size so we ignore it for now and
     * use this entry to avoid "unknown syscall" warnings.
     *
     * XXX: there are 4+ wchar_t* input strings in the struct: should check them.
     */
    {0,"NtWow64CsrBasepCreateActCtx", OK, 4, },
};
#define NUM_KERNEL32_SYSCALLS \
    (sizeof(syscall_kernel32_info)/sizeof(syscall_kernel32_info[0]))

size_t
num_kernel32_syscalls(void)
{
    return NUM_KERNEL32_SYSCALLS;
}

/* System calls with wrappers in user32.dll.
 * Not all wrappers are exported: xref i#388.
 *
 * When adding new entries, use the NtUser prefix.
 * When we try to find the wrapper via symbol lookup we try with
 * and without the prefix.
 */
syscall_info_t syscall_user32_info[] = {
    {0,"NtUserGetObjectInformation", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(DWORD),W}, }},
    {0,"NtUserGetProp", OK, 8, },
    {0,"NtUserQueryWindow", OK, 8, },
    {0,"NtUserUserConnectToServer", OK, 12, {{0,0,R|SYSARG_CSTRING_WIDE}, {1,-2,WI}, }},
};
#define NUM_USER32_SYSCALLS \
    (sizeof(syscall_user32_info)/sizeof(syscall_user32_info[0]))

size_t
num_user32_syscalls(void)
{
    return NUM_USER32_SYSCALLS;
}

/* System calls with wrappers in gdi32.dll.
 * Not all wrappers are exported: xref i#388.
 *
 * When adding new entries, use the NtGdi prefix.
 * When we try to find the wrapper via symbol lookup we try with
 * and without the prefix.
 *
 * Initially obtained via mksystable.pl on VS2008 ntgdi.h.
 * That version was checked in separately to track manual changes.
 */

static int sysnum_GdiCreatePaletteInternal = -1;
static int sysnum_GdiCheckBitmapBits = -1;
static int sysnum_GdiCreateDIBSection = -1;
static int sysnum_GdiHfontCreate = -1;
static int sysnum_GdiDoPalette = -1;

syscall_info_t syscall_gdi32_info[] = {
    {0,"NtGdiInit", OK, 0, },
    {0,"NtGdiSetDIBitsToDeviceInternal", OK, 64, {{9,-12,R,}, {10,sizeof(BITMAPINFO),R,}, }},
    {0,"NtGdiGetFontResourceInfoInternalW", OK, 28, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {4,sizeof(DWORD),W,}, {5,-3,W,}, }},
    {0,"NtGdiGetGlyphIndicesW", OK, 20, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {3,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(WORD)}, }},
    {0,"NtGdiGetGlyphIndicesWInternal", OK, 24, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {3,sizeof(WORD),W,}, }},
    {0,"NtGdiCreatePaletteInternal", OK, 8, {{0,},}/*too complex: special-cased*/, &sysnum_GdiCreatePaletteInternal},
    {0,"NtGdiArcInternal", OK, 40, },
    {0,"NtGdiGetOutlineTextMetricsInternalW", OK, 16, {{2,-1,W,}, {3,sizeof(TMDIFF),W,}, }},
    {0,"NtGdiGetAndSetDCDword", OK, 16, {{3,sizeof(DWORD),W,}, }},
    {0,"NtGdiGetDCObject", OK, 8, },
    {0,"NtGdiGetDCforBitmap", OK, 4, },
    {0,"NtGdiGetMonitorID", OK, 12, {{2,-1,W,}, }},
    {0,"NtGdiGetLinkedUFIs", OK, 12, {{1,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(UNIVERSAL_FONT_ID)}, }},
    {0,"NtGdiSetLinkedUFIs", OK, 12, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(UNIVERSAL_FONT_ID)}, }},
    {0,"NtGdiGetUFI", OK, 24, {{1,sizeof(UNIVERSAL_FONT_ID),W,}, {2,sizeof(DESIGNVECTOR),W,}, {3,sizeof(ULONG),W,}, {4,sizeof(ULONG),W,}, {5,sizeof(FLONG),W,}, }},
    {0,"NtGdiForceUFIMapping", OK, 8, {{1,sizeof(UNIVERSAL_FONT_ID),R,}, }},
    {0,"NtGdiGetUFIPathname", OK, 40, {{0,sizeof(UNIVERSAL_FONT_ID),R,}, {1,sizeof(ULONG),W,}, {2,MAX_PATH * 3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {2,-1,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {3,sizeof(ULONG),W,}, {5,sizeof(BOOL),W,}, {6,sizeof(ULONG),W,}, {7,sizeof(PVOID),W,}, {8,sizeof(BOOL),W,}, {9,sizeof(ULONG),W,}, }},
    {0,"NtGdiAddRemoteFontToDC", OK, 16, {{3,sizeof(UNIVERSAL_FONT_ID),R,}, }},
    {0,"NtGdiAddFontMemResourceEx", OK, 20, {{2,-3,R,}, {4,sizeof(DWORD),W,}, }},
    {0,"NtGdiRemoveFontMemResourceEx", OK, 4, },
    {0,"NtGdiUnmapMemFont", OK, 4, },
    {0,"NtGdiRemoveMergeFont", OK, 8, {{1,sizeof(UNIVERSAL_FONT_ID),R,}, }},
    {0,"NtGdiAnyLinkedFonts", OK, 0, },
    {0,"NtGdiGetEmbUFI", OK, 28, {{1,sizeof(UNIVERSAL_FONT_ID),W,}, {2,sizeof(DESIGNVECTOR),W,}, {3,sizeof(ULONG),W,}, {4,sizeof(ULONG),W,}, {5,sizeof(FLONG),W,}, {6,sizeof(KERNEL_PVOID),W,}, }},
    {0,"NtGdiGetEmbedFonts", OK, 0, },
    {0,"NtGdiChangeGhostFont", OK, 8, {{0,sizeof(KERNEL_PVOID),R,}, }},
    {0,"NtGdiAddEmbFontToDC", OK, 8, {{1,sizeof(PVOID),R,}, }},
    {0,"NtGdiFontIsLinked", OK, 4, },
    {0,"NtGdiPolyPolyDraw", OK, 20, {{1,sizeof(POINT),R,}, {2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, }},
    {0,"NtGdiDoPalette", OK, 24, {{0,},},/*special-cased: R or W depending*/ &sysnum_GdiDoPalette},
    {0,"NtGdiComputeXformCoefficients", OK, 4, },
    {0,"NtGdiGetWidthTable", OK, 28, {{2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {4,-3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(USHORT)}, {5,sizeof(WIDTHDATA),W,}, {6,sizeof(FLONG),W,}, }},
    {0,"NtGdiDescribePixelFormat", OK, 16, {{3,-2,W,}, }},
    {0,"NtGdiSetPixelFormat", OK, 8, },
    {0,"NtGdiSwapBuffers", OK, 4, },
    {0,"NtGdiDxgGenericThunk", OK, 24, {{2,sizeof(SIZE_T),R|W,}, {3,sizeof(PVOID),R|W,}, {4,sizeof(SIZE_T),R|W,}, {5,sizeof(PVOID),R|W,}, }},
    {0,"NtGdiDdAddAttachedSurface", OK, 12, {{2,sizeof(DD_ADDATTACHEDSURFACEDATA),R|W,}, }},
    {0,"NtGdiDdAttachSurface", OK, 8, },
    {0,"NtGdiDdBlt", OK, 12, {{2,sizeof(DD_BLTDATA),R|W,}, }},
    {0,"NtGdiDdCanCreateSurface", OK, 8, {{1,sizeof(DD_CANCREATESURFACEDATA),R|W,}, }},
    {0,"NtGdiDdColorControl", OK, 8, {{1,sizeof(DD_COLORCONTROLDATA),R|W,}, }},
    {0,"NtGdiDdCreateDirectDrawObject", OK, 4, },
    {0,"NtGdiDdCreateSurface", OK, 32, {{1,sizeof(HANDLE),R,}, {2,sizeof(DDSURFACEDESC),R|W,}, {3,sizeof(DD_SURFACE_GLOBAL),R|W,}, {4,sizeof(DD_SURFACE_LOCAL),R|W,}, {5,sizeof(DD_SURFACE_MORE),R|W,}, {6,sizeof(DD_CREATESURFACEDATA),R|W,}, {7,sizeof(HANDLE),W,}, }},
    {0,"NtGdiDdChangeSurfacePointer", OK, 8, },
    {0,"NtGdiDdCreateSurfaceObject", OK, 24, {{2,sizeof(DD_SURFACE_LOCAL),R,}, {3,sizeof(DD_SURFACE_MORE),R,}, {4,sizeof(DD_SURFACE_GLOBAL),R,}, }},
    {0,"NtGdiDdDeleteSurfaceObject", OK, 4, },
    {0,"NtGdiDdDeleteDirectDrawObject", OK, 4, },
    {0,"NtGdiDdDestroySurface", OK, 8, },
    {0,"NtGdiDdFlip", OK, 20, {{4,sizeof(DD_FLIPDATA),R|W,}, }},
    {0,"NtGdiDdGetAvailDriverMemory", OK, 8, {{1,sizeof(DD_GETAVAILDRIVERMEMORYDATA),R|W,}, }},
    {0,"NtGdiDdGetBltStatus", OK, 8, {{1,sizeof(DD_GETBLTSTATUSDATA),R|W,}, }},
    {0,"NtGdiDdGetDC", OK, 8, {{1,sizeof(PALETTEENTRY),R,}, }},
    {0,"NtGdiDdGetDriverInfo", OK, 8, {{1,sizeof(DD_GETDRIVERINFODATA),R|W,}, }},
    {0,"NtGdiDdGetFlipStatus", OK, 8, {{1,sizeof(DD_GETFLIPSTATUSDATA),R|W,}, }},
    {0,"NtGdiDdGetScanLine", OK, 8, {{1,sizeof(DD_GETSCANLINEDATA),R|W,}, }},
    {0,"NtGdiDdSetExclusiveMode", OK, 8, {{1,sizeof(DD_SETEXCLUSIVEMODEDATA),R|W,}, }},
    {0,"NtGdiDdFlipToGDISurface", OK, 8, {{1,sizeof(DD_FLIPTOGDISURFACEDATA),R|W,}, }},
    {0,"NtGdiDdLock", OK, 12, {{1,sizeof(DD_LOCKDATA),R|W,}, }},
    {0,"NtGdiDdQueryDirectDrawObject", OK, 44, {{1,sizeof(DD_HALINFO),W,}, {2,3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(DWORD)}, {3,sizeof(D3DNTHAL_CALLBACKS),W,}, {4,sizeof(D3DNTHAL_GLOBALDRIVERDATA),W,}, {5,sizeof(DD_D3DBUFCALLBACKS),W,}, {6,sizeof(DDSURFACEDESC),W,}, {7,sizeof(DWORD),W,}, {8,sizeof(VIDEOMEMORY),W,}, {9,sizeof(DWORD),W,}, {10,sizeof(DWORD),W,}, }},
    {0,"NtGdiDdReenableDirectDrawObject", OK, 8, {{1,sizeof(BOOL),R|W,}, }},
    {0,"NtGdiDdReleaseDC", OK, 4, },
    {0,"NtGdiDdResetVisrgn", OK, 8, },
    {0,"NtGdiDdSetColorKey", OK, 8, {{1,sizeof(DD_SETCOLORKEYDATA),R|W,}, }},
    {0,"NtGdiDdSetOverlayPosition", OK, 12, {{2,sizeof(DD_SETOVERLAYPOSITIONDATA),R|W,}, }},
    {0,"NtGdiDdUnattachSurface", OK, 8, },
    {0,"NtGdiDdUnlock", OK, 8, {{1,sizeof(DD_UNLOCKDATA),R|W,}, }},
    {0,"NtGdiDdUpdateOverlay", OK, 12, {{2,sizeof(DD_UPDATEOVERLAYDATA),R|W,}, }},
    {0,"NtGdiDdWaitForVerticalBlank", OK, 8, {{1,sizeof(DD_WAITFORVERTICALBLANKDATA),R|W,}, }},
    {0,"NtGdiDdGetDxHandle", OK, 12, },
    {0,"NtGdiDdSetGammaRamp", OK, 12, },
    {0,"NtGdiDdLockD3D", OK, 8, {{1,sizeof(DD_LOCKDATA),R|W,}, }},
    {0,"NtGdiDdUnlockD3D", OK, 8, {{1,sizeof(DD_UNLOCKDATA),R|W,}, }},
    {0,"NtGdiDdCreateD3DBuffer", OK, 32, {{1,sizeof(HANDLE),R|W,}, {2,sizeof(DDSURFACEDESC),R|W,}, {3,sizeof(DD_SURFACE_GLOBAL),R|W,}, {4,sizeof(DD_SURFACE_LOCAL),R|W,}, {5,sizeof(DD_SURFACE_MORE),R|W,}, {6,sizeof(DD_CREATESURFACEDATA),R|W,}, {7,sizeof(HANDLE),R|W,}, }},
    {0,"NtGdiDdCanCreateD3DBuffer", OK, 8, {{1,sizeof(DD_CANCREATESURFACEDATA),R|W,}, }},
    {0,"NtGdiDdDestroyD3DBuffer", OK, 4, },
    {0,"NtGdiD3dContextCreate", OK, 16, {{3,sizeof(D3DNTHAL_CONTEXTCREATEI),R|W,}, }},
    {0,"NtGdiD3dContextDestroy", OK, 4, {{0,sizeof(D3DNTHAL_CONTEXTDESTROYDATA),R,}, }},
    {0,"NtGdiD3dContextDestroyAll", OK, 4, {{0,sizeof(D3DNTHAL_CONTEXTDESTROYALLDATA),W,}, }},
    {0,"NtGdiD3dValidateTextureStageState", OK, 4, {{0,sizeof(D3DNTHAL_VALIDATETEXTURESTAGESTATEDATA),R|W,}, }},
    {0,"NtGdiD3dDrawPrimitives2", OK, 28, {{2,sizeof(D3DNTHAL_DRAWPRIMITIVES2DATA),R|W,}, {3,sizeof(FLATPTR),R|W,}, {4,sizeof(DWORD),R|W,}, {5,sizeof(FLATPTR),R|W,}, {6,sizeof(DWORD),R|W,}, }},
    {0,"NtGdiDdGetDriverState", OK, 4, {{0,sizeof(DD_GETDRIVERSTATEDATA),R|W,}, }},
    {0,"NtGdiDdCreateSurfaceEx", OK, 12, },
    {0,"NtGdiDvpCanCreateVideoPort", OK, 8, {{1,sizeof(DD_CANCREATEVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpColorControl", OK, 8, {{1,sizeof(DD_VPORTCOLORDATA),R|W,}, }},
    {0,"NtGdiDvpCreateVideoPort", OK, 8, {{1,sizeof(DD_CREATEVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpDestroyVideoPort", OK, 8, {{1,sizeof(DD_DESTROYVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpFlipVideoPort", OK, 16, {{3,sizeof(DD_FLIPVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortBandwidth", OK, 8, {{1,sizeof(DD_GETVPORTBANDWIDTHDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortField", OK, 8, {{1,sizeof(DD_GETVPORTFIELDDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortFlipStatus", OK, 8, {{1,sizeof(DD_GETVPORTFLIPSTATUSDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortInputFormats", OK, 8, {{1,sizeof(DD_GETVPORTINPUTFORMATDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortLine", OK, 8, {{1,sizeof(DD_GETVPORTLINEDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortOutputFormats", OK, 8, {{1,sizeof(DD_GETVPORTOUTPUTFORMATDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortConnectInfo", OK, 8, {{1,sizeof(DD_GETVPORTCONNECTDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoSignalStatus", OK, 8, {{1,sizeof(DD_GETVPORTSIGNALDATA),R|W,}, }},
    {0,"NtGdiDvpUpdateVideoPort", OK, 16, {{1,sizeof(HANDLE),R,}, {2,sizeof(HANDLE),R,}, {3,sizeof(DD_UPDATEVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpWaitForVideoPortSync", OK, 8, {{1,sizeof(DD_WAITFORVPORTSYNCDATA),R|W,}, }},
    {0,"NtGdiDvpAcquireNotification", OK, 12, {{1,sizeof(HANDLE),R|W,}, {2,sizeof(DDVIDEOPORTNOTIFY),R,}, }},
    {0,"NtGdiDvpReleaseNotification", OK, 8, },
    {0,"NtGdiDdGetMoCompGuids", OK, 8, {{1,sizeof(DD_GETMOCOMPGUIDSDATA),R|W,}, }},
    {0,"NtGdiDdGetMoCompFormats", OK, 8, {{1,sizeof(DD_GETMOCOMPFORMATSDATA),R|W,}, }},
    {0,"NtGdiDdGetMoCompBuffInfo", OK, 8, {{1,sizeof(DD_GETMOCOMPCOMPBUFFDATA),R|W,}, }},
    {0,"NtGdiDdGetInternalMoCompInfo", OK, 8, {{1,sizeof(DD_GETINTERNALMOCOMPDATA),R|W,}, }},
    {0,"NtGdiDdCreateMoComp", OK, 8, {{1,sizeof(DD_CREATEMOCOMPDATA),R|W,}, }},
    {0,"NtGdiDdDestroyMoComp", OK, 8, {{1,sizeof(DD_DESTROYMOCOMPDATA),R|W,}, }},
    {0,"NtGdiDdBeginMoCompFrame", OK, 8, {{1,sizeof(DD_BEGINMOCOMPFRAMEDATA),R|W,}, }},
    {0,"NtGdiDdEndMoCompFrame", OK, 8, {{1,sizeof(DD_ENDMOCOMPFRAMEDATA),R|W,}, }},
    {0,"NtGdiDdRenderMoComp", OK, 8, {{1,sizeof(DD_RENDERMOCOMPDATA),R|W,}, }},
    {0,"NtGdiDdQueryMoCompStatus", OK, 8, {{1,sizeof(DD_QUERYMOCOMPSTATUSDATA),R|W,}, }},
    {0,"NtGdiDdAlphaBlt", OK, 12, {{2,sizeof(DD_BLTDATA),R|W,}, }},
    {0,"NtGdiAlphaBlend", OK, 48, },
    {0,"NtGdiGradientFill", OK, 24, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(TRIVERTEX)}, }},
    {0,"NtGdiSetIcmMode", OK, 12, },
    {0,"NtGdiCreateColorSpace", OK, 4, {{0,sizeof(LOGCOLORSPACEEXW),R,}, }},
    {0,"NtGdiDeleteColorSpace", OK, 4, },
    {0,"NtGdiSetColorSpace", OK, 8, },
    {0,"NtGdiCreateColorTransform", OK, 32, {{1,sizeof(LOGCOLORSPACEW),R,}, }},
    {0,"NtGdiDeleteColorTransform", OK, 8, },
    {0,"NtGdiCheckBitmapBits", OK, 32, {{0,}/*too complex: special-cased*/, }, &sysnum_GdiCheckBitmapBits},
    {0,"NtGdiColorCorrectPalette", OK, 24, {{4,-3,R|W|SYSARG_SIZE_IN_ELEMENTS,sizeof(PALETTEENTRY)}, }},
    {0,"NtGdiGetColorSpaceforBitmap", OK, 4, },
    {0,"NtGdiGetDeviceGammaRamp", OK, 8, {{1,256*2*3,W,}, }},
    {0,"NtGdiSetDeviceGammaRamp", OK, 8, },
    {0,"NtGdiIcmBrushInfo", OK, 32, {{2,sizeof(BITMAPINFO) + ((/*MAX_COLORTABLE*/256 - 1) * sizeof(RGBQUAD)),R|W,}, {3,-4,R|SYSARG_LENGTH_INOUT,}, {4,sizeof(ULONG),R|W,}, {5,sizeof(DWORD),W,}, {6,sizeof(BOOL),W,}, }},
    {0,"NtGdiFlush", OK, 0, },
    {0,"NtGdiCreateMetafileDC", OK, 4, },
    {0,"NtGdiMakeInfoDC", OK, 8, },
    {0,"NtGdiCreateClientObj", OK, 4, },
    {0,"NtGdiDeleteClientObj", OK, 4, },
    {0,"NtGdiGetBitmapBits", OK, 12, {{2,-1,W,}, }},
    {0,"NtGdiDeleteObjectApp", OK, 4, },
    {0,"NtGdiGetPath", OK, 16, {{1,-3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, {2,-3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(BYTE)}, }},
    {0,"NtGdiCreateCompatibleDC", OK, 4, },
    {0,"NtGdiCreateDIBitmapInternal", OK, 44, {{4,-8,R,}, {5,-7,R,}, }},
    {0,"NtGdiCreateDIBSection", OK, 36, {{3,-5,R,}, {8,sizeof(PVOID),W,}, }, &sysnum_GdiCreateDIBSection},
    {0,"NtGdiCreateSolidBrush", OK, 8, },
    {0,"NtGdiCreateDIBBrush", OK, 24, },
    {0,"NtGdiCreatePatternBrushInternal", OK, 12, },
    {0,"NtGdiCreateHatchBrushInternal", OK, 12, },
    {0,"NtGdiExtCreatePen", OK, 44, {{7,-6,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, }},
    {0,"NtGdiCreateEllipticRgn", OK, 16, },
    {0,"NtGdiCreateRoundRectRgn", OK, 24, },
    {0,"NtGdiCreateServerMetaFile", OK, 24, {{2,-1,R,}, }},
    {0,"NtGdiExtCreateRegion", OK, 12, {{0,sizeof(XFORM),R,}, {2,-1,R,}, }},
    {0,"NtGdiMakeFontDir", OK, 20, {{1,-2,W,}, {3,-4,R,}, }},
    {0,"NtGdiPolyDraw", OK, 16, {{1,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, {2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(BYTE)}, }},
    {0,"NtGdiPolyTextOutW", OK, 16, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POLYTEXTW)}, }},
    {0,"NtGdiGetServerMetaFileBits", OK, 28, {{2,-1,W,}, {3,sizeof(DWORD),W,}, {4,sizeof(DWORD),W,}, {5,sizeof(DWORD),W,}, {6,sizeof(DWORD),W,}, }},
    {0,"NtGdiEqualRgn", OK, 8, },
    {0,"NtGdiGetBitmapDimension", OK, 8, {{1,sizeof(SIZE),W,}, }},
    {0,"NtGdiGetNearestPaletteIndex", OK, 8, },
    {0,"NtGdiPtVisible", OK, 12, },
    {0,"NtGdiRectVisible", OK, 8, {{1,sizeof(RECT),R,}, }},
    {0,"NtGdiRemoveFontResourceW", OK, 24, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {5,sizeof(DESIGNVECTOR),R,}, }},
    {0,"NtGdiResizePalette", OK, 8, },
    {0,"NtGdiSetBitmapDimension", OK, 16, {{3,sizeof(SIZE),W,}, }},
    {0,"NtGdiOffsetClipRgn", OK, 12, },
    {0,"NtGdiSetMetaRgn", OK, 4, },
    {0,"NtGdiSetTextJustification", OK, 12, },
    {0,"NtGdiGetAppClipBox", OK, 8, {{1,sizeof(RECT),W,}, }},
    {0,"NtGdiGetTextExtentExW", OK, 32, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {4,sizeof(ULONG),W,}, {5,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, {5,-4,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, {6,sizeof(SIZE),W,}, }},
    {0,"NtGdiGetCharABCWidthsW", OK, 24, {{3,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {5,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(ABC)}, }},
    {0,"NtGdiGetCharacterPlacementW", OK, 24, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {4,sizeof(GCP_RESULTSW),R|W,}, }},
    {0,"NtGdiAngleArc", OK, 24, },
    {0,"NtGdiBeginPath", OK, 4, },
    {0,"NtGdiSelectClipPath", OK, 8, },
    {0,"NtGdiCloseFigure", OK, 4, },
    {0,"NtGdiEndPath", OK, 4, },
    {0,"NtGdiAbortPath", OK, 4, },
    {0,"NtGdiFillPath", OK, 4, },
    {0,"NtGdiStrokeAndFillPath", OK, 4, },
    {0,"NtGdiStrokePath", OK, 4, },
    {0,"NtGdiWidenPath", OK, 4, },
    {0,"NtGdiFlattenPath", OK, 4, },
    {0,"NtGdiPathToRegion", OK, 4, },
    {0,"NtGdiSetMiterLimit", OK, 12, {{2,sizeof(DWORD),R|W,}, }},
    {0,"NtGdiSetFontXform", OK, 12, },
    {0,"NtGdiGetMiterLimit", OK, 8, {{1,sizeof(DWORD),W,}, }},
    {0,"NtGdiEllipse", OK, 20, },
    {0,"NtGdiRectangle", OK, 20, },
    {0,"NtGdiRoundRect", OK, 28, },
    {0,"NtGdiPlgBlt", OK, 44, {{1,3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, }},
    {0,"NtGdiMaskBlt", OK, 52, },
    {0,"NtGdiExtFloodFill", OK, 20, },
    {0,"NtGdiFillRgn", OK, 12, },
    {0,"NtGdiFrameRgn", OK, 20, },
    {0,"NtGdiSetPixel", OK, 16, },
    {0,"NtGdiGetPixel", OK, 12, },
    {0,"NtGdiStartPage", OK, 4, },
    {0,"NtGdiEndPage", OK, 4, },
    {0,"NtGdiStartDoc", OK, 16, {{1,sizeof(DOCINFOW),R,}, {2,sizeof(BOOL),W,}, }},
    {0,"NtGdiEndDoc", OK, 4, },
    {0,"NtGdiAbortDoc", OK, 4, },
    {0,"NtGdiUpdateColors", OK, 4, },
    {0,"NtGdiGetCharWidthW", OK, 24, {{3,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {5,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, }},
    {0,"NtGdiGetCharWidthInfo", OK, 8, {{1,sizeof(CHWIDTHINFO),W,}, }},
    {0,"NtGdiDrawEscape", OK, 16, {{3,-2,R,}, }},
    {0,"NtGdiExtEscape", OK, 32, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {5,-4,R,}, {7,-6,W,}, }},
    {0,"NtGdiGetFontData", OK, 20, {{3,-4,W,}, {3,RET,W,}, }},
    {0,"NtGdiGetFontFileData", OK, 20, {{2,sizeof(ULONGLONG),R,}, {3,-4,W,}, }},
    {0,"NtGdiGetFontFileInfo", OK, 20, {{2,-3,W,}, {4,sizeof(SIZE_T),W,}, }},
    {0,"NtGdiGetGlyphOutline", OK, 32, {{3,sizeof(GLYPHMETRICS),W,}, {5,-4,W,}, {6,sizeof(MAT2),R,}, }},
    {0,"NtGdiGetETM", OK, 8, {{1,sizeof(EXTTEXTMETRIC),W,}, }},
    {0,"NtGdiGetRasterizerCaps", OK, 8, {{0,-1,W,}, }},
    {0,"NtGdiGetKerningPairs", OK, 12, {{2,-1,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(KERNINGPAIR)}, {2,RET,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(KERNINGPAIR)}, }},
    {0,"NtGdiMonoBitmap", OK, 4, },
    {0,"NtGdiGetObjectBitmapHandle", OK, 8, {{1,sizeof(UINT),W,}, }},
    {0,"NtGdiEnumObjects", OK, 16, {{3,-2,W,}, }},
    {0,"NtGdiResetDC", OK, 20, {{1,sizeof(DEVMODEW),R,}, {2,sizeof(BOOL),W,}, {3,sizeof(DRIVER_INFO_2W),R,}, {4,sizeof(PUMDHPDEV *),W,}, }},
    {0,"NtGdiSetBoundsRect", OK, 12, {{1,sizeof(RECT),R,}, }},
    {0,"NtGdiGetColorAdjustment", OK, 8, {{1,sizeof(COLORADJUSTMENT),W,}, }},
    {0,"NtGdiSetColorAdjustment", OK, 8, {{1,sizeof(COLORADJUSTMENT),R,}, }},
    {0,"NtGdiCancelDC", OK, 4, },
    {0,"NtGdiOpenDCW", OK, 32, {{0,sizeof(UNICODE_STRING),R,}, {1,sizeof(DEVMODEW),R,}, {2,sizeof(UNICODE_STRING),R,}, {6,sizeof(DRIVER_INFO_2W),R,}, {7,sizeof(PUMDHPDEV *),W,}, }},
    {0,"NtGdiGetDCDword", OK, 12, {{2,sizeof(DWORD),W,}, }},
    {0,"NtGdiGetDCPoint", OK, 12, {{2,sizeof(POINTL),W,}, }},
    {0,"NtGdiScaleViewportExtEx", OK, 24, {{5,sizeof(SIZE),W,}, }},
    {0,"NtGdiScaleWindowExtEx", OK, 24, {{5,sizeof(SIZE),W,}, }},
    {0,"NtGdiSetVirtualResolution", OK, 20, },
    {0,"NtGdiSetSizeDevice", OK, 12, },
    {0,"NtGdiGetTransform", OK, 12, {{2,sizeof(XFORM),W,}, }},
    {0,"NtGdiModifyWorldTransform", OK, 12, {{1,sizeof(XFORM),R,}, }},
    {0,"NtGdiCombineTransform", OK, 12, {{0,sizeof(XFORM),W,}, {1,sizeof(XFORM),R,}, {2,sizeof(XFORM),R,}, }},
    {0,"NtGdiTransformPoints", OK, 20, {{1,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, {2,-3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, }},
    {0,"NtGdiConvertMetafileRect", OK, 8, {{1,sizeof(RECTL),R|W,}, }},
    {0,"NtGdiGetTextCharsetInfo", OK, 12, {{1,sizeof(FONTSIGNATURE),W,}, }},
    {0,"NtGdiDoBanding", OK, 16, {{2,sizeof(POINTL),W,}, {3,sizeof(SIZE),W,}, }},
    {0,"NtGdiGetPerBandInfo", OK, 8, {{1,sizeof(PERBANDINFO),R|W,}, }},
    {0,"NtGdiGetStats", OK, 20, {{3,-4,W,}, }},
    {0,"NtGdiSetMagicColors", OK, 12, },
    {0,"NtGdiSelectBrush", OK, 8, },
    {0,"NtGdiSelectPen", OK, 8, },
    {0,"NtGdiSelectBitmap", OK, 8, },
    {0,"NtGdiSelectFont", OK, 8, },
    {0,"NtGdiExtSelectClipRgn", OK, 12, },
    {0,"NtGdiCreatePen", OK, 16, },
    {0,"NtGdiBitBlt", OK, 44, },
    {0,"NtGdiTileBitBlt", OK, 28, {{1,sizeof(RECTL),R,}, {3,sizeof(RECTL),R,}, {4,sizeof(POINTL),R,}, }},
    {0,"NtGdiTransparentBlt", OK, 44, },
    {0,"NtGdiGetTextExtent", OK, 20, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {3,sizeof(SIZE),W,}, }},
    {0,"NtGdiGetTextMetricsW", OK, 12, {{1,-2,W,}, }},
    {0,"NtGdiGetTextFaceW", OK, 16, {{2,-1,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {2,RET,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, }},
    {0,"NtGdiGetRandomRgn", OK, 12, },
    {0,"NtGdiExtTextOutW", OK, 36, {{4,sizeof(RECT),R,}, {5,-6,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {7,-6,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(INT)/*FIXME size can be larger*/}, }},
    {0,"NtGdiIntersectClipRect", OK, 20, },
    {0,"NtGdiCreateRectRgn", OK, 16, },
    {0,"NtGdiPatBlt", OK, 24, },
    {0,"NtGdiPolyPatBlt", OK, 20, {{2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POLYPATBLT)}, }},
    {0,"NtGdiUnrealizeObject", OK, 4, },
    {0,"NtGdiGetStockObject", OK, 4, },
    {0,"NtGdiCreateCompatibleBitmap", OK, 12, },
    {0,"NtGdiCreateBitmapFromDxSurface", OK, 20, },
    {0,"NtGdiBeginGdiRendering", OK, 8, },
    {0,"NtGdiEndGdiRendering", OK, 12, {{2,sizeof(BOOL),W,}, }},
    {0,"NtGdiLineTo", OK, 12, },
    {0,"NtGdiMoveTo", OK, 16, {{3,sizeof(POINT),W,}, }},
    {0,"NtGdiExtGetObjectW", OK, 12, {{2,-1,W}, {2,RET,W,}, }},
    {0,"NtGdiGetDeviceCaps", OK, 8, },
    {0,"NtGdiGetDeviceCapsAll", OK, 8, {{1,sizeof(DEVCAPS),W,}, }},
    {0,"NtGdiStretchBlt", OK, 48, },
    {0,"NtGdiSetBrushOrg", OK, 16, {{3,sizeof(POINT),W,}, }},
    {0,"NtGdiCreateBitmap", OK, 20, {{4,sizeof(BYTE),R,}, }},
    {0,"NtGdiCreateHalftonePalette", OK, 4, },
    {0,"NtGdiRestoreDC", OK, 8, },
    {0,"NtGdiExcludeClipRect", OK, 20, },
    {0,"NtGdiSaveDC", OK, 4, },
    {0,"NtGdiCombineRgn", OK, 16, },
    {0,"NtGdiSetRectRgn", OK, 20, },
    {0,"NtGdiSetBitmapBits", OK, 12, {{2,-1,R,}, }},
    {0,"NtGdiGetDIBitsInternal", OK, 36, {{4,-7,W,}, {5,sizeof(BITMAPINFO),R|W,}, }},
    {0,"NtGdiOffsetRgn", OK, 12, },
    {0,"NtGdiGetRgnBox", OK, 8, {{1,sizeof(RECT),W,}, }},
    {0,"NtGdiRectInRegion", OK, 8, {{1,sizeof(RECT),R|W,}, }},
    {0,"NtGdiGetBoundsRect", OK, 12, {{1,sizeof(RECT),W,}, }},
    {0,"NtGdiPtInRegion", OK, 12, },
    {0,"NtGdiGetNearestColor", OK, 8, },
    {0,"NtGdiGetSystemPaletteUse", OK, 4, },
    {0,"NtGdiSetSystemPaletteUse", OK, 8, },
    {0,"NtGdiGetRegionData", OK, 12, {{2,-1,W,}, {2,RET,W,}, }},
    {0,"NtGdiInvertRgn", OK, 8, },
    {0,"NtGdiHfontCreate", OK, 20, {{0,}, },/*special-cased*/ &sysnum_GdiHfontCreate},
#if 0 /* for _WIN32_WINNT < 0x0500 == NT which we ignore for now */
    {0,"NtGdiHfontCreate", OK, 20, {{0,sizeof(EXTLOGFONTW),R,}, }},
#endif
    {0,"NtGdiSetFontEnumeration", OK, 4, },
    {0,"NtGdiEnumFonts", OK, 32, {{4,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {6,sizeof(ULONG),R|W,}, {7,-6,WI,}, }},
    {0,"NtGdiQueryFonts", OK, 12, {{0,-1,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(UNIVERSAL_FONT_ID)}, {2,sizeof(LARGE_INTEGER),W,}, }},
    {0,"NtGdiGetCharSet", OK, 4, },
    {0,"NtGdiEnableEudc", OK, 4, },
    {0,"NtGdiEudcLoadUnloadLink", OK, 28, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, }},
    {0,"NtGdiGetStringBitmapW", OK, 20, {{1,sizeof(wchar_t),R,}, {4,-3,W,}, }},
    {0,"NtGdiGetEudcTimeStampEx", OK, 12, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, }},
    {0,"NtGdiQueryFontAssocInfo", OK, 4, },
    {0,"NtGdiGetFontUnicodeRanges", OK, 8, {{1,0,W,/*FIXME pre size from prior syscall ret*//*FIXME size from retval so earlier call*/}, }},
    {0,"NtGdiGetRealizationInfo", OK, 8, {{1,sizeof(REALIZATION_INFO),W,}, }},
    {0,"NtGdiAddRemoteMMInstanceToDC", OK, 12, {{1,-2,R,}, }},
    {0,"NtGdiUnloadPrinterDriver", OK, 8, {{0,-1,R,}, }},
    {0,"NtGdiEngAssociateSurface", OK, 12, },
    {0,"NtGdiEngEraseSurface", OK, 12, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(RECTL),R,}, }},
    {0,"NtGdiEngCreateBitmap", OK, 20, },
    {0,"NtGdiEngDeleteSurface", OK, 4, },
    {0,"NtGdiEngLockSurface", OK, 4, },
    {0,"NtGdiEngUnlockSurface", OK, 4, {{0,sizeof(SURFOBJ),R,}, }},
    {0,"NtGdiEngMarkBandingSurface", OK, 4, },
    {0,"NtGdiEngCreateDeviceSurface", OK, 12, },
    {0,"NtGdiEngCreateDeviceBitmap", OK, 12, },
    {0,"NtGdiEngCopyBits", OK, 24, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XLATEOBJ),R,}, {4,sizeof(RECTL),R,}, {5,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngStretchBlt", OK, 44, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(XLATEOBJ),R,}, {5,sizeof(COLORADJUSTMENT),R,}, {6,sizeof(POINTL),R,}, {7,sizeof(RECTL),R,}, {8,sizeof(RECTL),R,}, {9,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngBitBlt", OK, 44, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(XLATEOBJ),R,}, {5,sizeof(RECTL),R,}, {6,sizeof(POINTL),R,}, {7,sizeof(POINTL),R,}, {8,sizeof(BRUSHOBJ),R,}, {9,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngPlgBlt", OK, 44, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(XLATEOBJ),R,}, {5,sizeof(COLORADJUSTMENT),R,}, {6,sizeof(POINTL),R,}, {7,sizeof(POINTFIX),R,}, {8,sizeof(RECTL),R,}, {9,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngCreatePalette", OK, 24, {{2,sizeof(ULONG),R,}, }},
    {0,"NtGdiEngDeletePalette", OK, 4, },
    {0,"NtGdiEngStrokePath", OK, 32, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(PATHOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XFORMOBJ),R,}, {4,sizeof(BRUSHOBJ),R,}, {5,sizeof(POINTL),R,}, {6,sizeof(LINEATTRS),R,}, }},
    {0,"NtGdiEngFillPath", OK, 28, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(PATHOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(BRUSHOBJ),R,}, {4,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngStrokeAndFillPath", OK, 40, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(PATHOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XFORMOBJ),R,}, {4,sizeof(BRUSHOBJ),R,}, {5,sizeof(LINEATTRS),R,}, {6,sizeof(BRUSHOBJ),R,}, {7,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngPaint", OK, 20, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(CLIPOBJ),R,}, {2,sizeof(BRUSHOBJ),R,}, {3,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngLineTo", OK, 36, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(CLIPOBJ),R,}, {2,sizeof(BRUSHOBJ),R,}, {7,sizeof(RECTL),R,}, }},
    {0,"NtGdiEngAlphaBlend", OK, 28, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XLATEOBJ),R,}, {4,sizeof(RECTL),R,}, {5,sizeof(RECTL),R,}, {6,sizeof(BLENDOBJ),R,}, }},
    {0,"NtGdiEngGradientFill", OK, 40, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(CLIPOBJ),R,}, {2,sizeof(XLATEOBJ),R,}, {3,-4,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(TRIVERTEX)}, {7,sizeof(RECTL),R,}, {8,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngTransparentBlt", OK, 32, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XLATEOBJ),R,}, {4,sizeof(RECTL),R,}, {5,sizeof(RECTL),R,}, }},
    {0,"NtGdiEngTextOut", OK, 40, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(STROBJ),R,}, {2,sizeof(FONTOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(RECTL),R,}, {5,sizeof(RECTL),R,}, {6,sizeof(BRUSHOBJ),R,}, {7,sizeof(BRUSHOBJ),R,}, {8,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngStretchBltROP", OK, 52, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(XLATEOBJ),R,}, {5,sizeof(COLORADJUSTMENT),R,}, {6,sizeof(POINTL),R,}, {7,sizeof(RECTL),R,}, {8,sizeof(RECTL),R,}, {9,sizeof(POINTL),R,}, {11,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiXLATEOBJ_cGetPalette", OK, 16, {{0,sizeof(XLATEOBJ),R,}, {3,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, }},
    {0,"NtGdiCLIPOBJ_cEnumStart", OK, 20, {{0,sizeof(CLIPOBJ),R,}, }},
    {0,"NtGdiCLIPOBJ_bEnum", OK, 12, {{0,sizeof(CLIPOBJ),R,}, {2,-1,W,}, }},
    {0,"NtGdiCLIPOBJ_ppoGetPath", OK, 4, {{0,sizeof(CLIPOBJ),R,}, }},
    {0,"NtGdiEngCreateClip", OK, 0, },
    {0,"NtGdiEngDeleteClip", OK, 4, {{0,sizeof(CLIPOBJ),R,}, }},
    {0,"NtGdiBRUSHOBJ_pvAllocRbrush", OK, 8, {{0,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiBRUSHOBJ_pvGetRbrush", OK, 4, {{0,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiBRUSHOBJ_ulGetBrushColor", OK, 4, {{0,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiBRUSHOBJ_hGetColorTransform", OK, 4, {{0,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiXFORMOBJ_bApplyXform", OK, 20, {{0,sizeof(XFORMOBJ),R,}, {3,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINTL)}, {4,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINTL)}, }},
    {0,"NtGdiXFORMOBJ_iGetXform", OK, 8, {{0,sizeof(XFORMOBJ),R,}, {1,sizeof(XFORML),W,}, }},
    {0,"NtGdiFONTOBJ_vGetInfo", OK, 12, {{0,sizeof(FONTOBJ),R,}, {2,-1,W,}, }},
    {0,"NtGdiFONTOBJ_cGetGlyphs", OK, 20, {{0,sizeof(FONTOBJ),R,}, {3,sizeof(HGLYPH),R,}, {4,sizeof(GLYPHDATA **),W,}, }},
    {0,"NtGdiFONTOBJ_pxoGetXform", OK, 4, {{0,sizeof(FONTOBJ),R,}, }},
    {0,"NtGdiFONTOBJ_pifi", OK, 4, {{0,sizeof(FONTOBJ),R,}, }},
    {0,"NtGdiFONTOBJ_pfdg", OK, 4, {{0,sizeof(FONTOBJ),R,}, }},
    {0,"NtGdiFONTOBJ_cGetAllGlyphHandles", OK, 8, {{0,sizeof(FONTOBJ),R,}, {1,0,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(HGLYPH)/*FIXME pre size from prior syscall ret*//*FIXME size from retval so earlier call*/}, }},
    {0,"NtGdiFONTOBJ_pvTrueTypeFontFile", OK, 8, {{0,sizeof(FONTOBJ),R,}, {1,sizeof(ULONG),W,}, }},
    {0,"NtGdiFONTOBJ_pQueryGlyphAttrs", OK, 8, {{0,sizeof(FONTOBJ),R,}, }},
    {0,"NtGdiSTROBJ_bEnum", OK, 12, {{0,sizeof(STROBJ),R,}, {1,sizeof(ULONG),W,}, {2,-1,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(PGLYPHPOS)}, }},
    {0,"NtGdiSTROBJ_bEnumPositionsOnly", OK, 12, {{0,sizeof(STROBJ),R,}, {1,sizeof(ULONG),W,}, {2,-1,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(PGLYPHPOS)}, }},
    {0,"NtGdiSTROBJ_vEnumStart", OK, 4, {{0,sizeof(STROBJ),R,}, }},
    {0,"NtGdiSTROBJ_dwGetCodePage", OK, 4, {{0,sizeof(STROBJ),R,}, }},
    {0,"NtGdiSTROBJ_bGetAdvanceWidths", OK, 16, {{0,sizeof(STROBJ),R,}, {3,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINTQF)}, }},
    {0,"NtGdiEngComputeGlyphSet", OK, 12, },
    {0,"NtGdiXLATEOBJ_iXlate", OK, 8, {{0,sizeof(XLATEOBJ),R,}, }},
    {0,"NtGdiXLATEOBJ_hGetColorTransform", OK, 4, {{0,sizeof(XLATEOBJ),R,}, }},
    {0,"NtGdiPATHOBJ_vGetBounds", OK, 8, {{0,sizeof(PATHOBJ),R,}, {1,sizeof(RECTFX),W,}, }},
    {0,"NtGdiPATHOBJ_bEnum", OK, 8, {{0,sizeof(PATHOBJ),R,}, {1,sizeof(PATHDATA),W,}, }},
    {0,"NtGdiPATHOBJ_vEnumStart", OK, 4, {{0,sizeof(PATHOBJ),R,}, }},
    {0,"NtGdiEngDeletePath", OK, 4, {{0,sizeof(PATHOBJ),R,}, }},
    {0,"NtGdiPATHOBJ_vEnumStartClipLines", OK, 16, {{0,sizeof(PATHOBJ),R,}, {1,sizeof(CLIPOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(LINEATTRS),R,}, }},
    {0,"NtGdiPATHOBJ_bEnumClipLines", OK, 12, {{0,sizeof(PATHOBJ),R,}, {2,-1,W,}, }},
    {0,"NtGdiEngCheckAbort", OK, 4, {{0,sizeof(SURFOBJ),R,}, }},
    {0,"NtGdiGetDhpdev", OK, 4, },
    {0,"NtGdiHT_Get8BPPFormatPalette", OK, 16, {{0,0,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(PALETTEENTRY)/*FIXME pre size from prior syscall ret*//*FIXME size from retval so earlier call*/}, }},
    {0,"NtGdiHT_Get8BPPMaskPalette", OK, 24, {{0,0,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(PALETTEENTRY)/*FIXME pre size from prior syscall ret*//*FIXME size from retval so earlier call*/}, }},
    {0,"NtGdiUpdateTransform", OK, 4, },
    {0,"NtGdiSetLayout", OK, 12, },
    {0,"NtGdiMirrorWindowOrg", OK, 4, },
    {0,"NtGdiGetDeviceWidth", OK, 4, },
    {0,"NtGdiSetPUMPDOBJ", OK, 16, {{2,sizeof(HUMPD),R|W,}, {3,sizeof(BOOL),W,}, }},
    {0,"NtGdiBRUSHOBJ_DeleteRbrush", OK, 8, {{0,sizeof(BRUSHOBJ),R,}, {1,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiUMPDEngFreeUserMem", OK, 4, {{0,sizeof(KERNEL_PVOID),R,}, }},
    {0,"NtGdiSetBitmapAttributes", OK, 8, },
    {0,"NtGdiClearBitmapAttributes", OK, 8, },
    {0,"NtGdiSetBrushAttributes", OK, 8, },
    {0,"NtGdiClearBrushAttributes", OK, 8, },
    {0,"NtGdiDrawStream", OK, 12, },
    {0,"NtGdiMakeObjectXferable", OK, 8, },
    {0,"NtGdiMakeObjectUnXferable", OK, 4, },
    {0,"NtGdiSfmGetNotificationTokens", OK, 12, {{1,sizeof(UINT),W,}, {2,-0,W,}, }},
    {0,"NtGdiSfmRegisterLogicalSurfaceForSignaling", OK, 8, },
    {0,"NtGdiDwmGetHighColorMode", OK, 4, {{0,sizeof(DXGI_FORMAT),W,}, }},
    {0,"NtGdiDwmSetHighColorMode", OK, 4, },
    {0,"NtGdiDwmCaptureScreen", OK, 8, {{0,sizeof(RECT),R,}, }},
    {0,"NtGdiDdCreateFullscreenSprite", OK, 16, {{2,sizeof(HANDLE),W,}, {3,sizeof(HDC),W,}, }},
    {0,"NtGdiDdNotifyFullscreenSpriteUpdate", OK, 8, },
    {0,"NtGdiDdDestroyFullscreenSprite", OK, 8, },
    {0,"NtGdiDdQueryVisRgnUniqueness", OK, 0, },

};
#define NUM_GDI32_SYSCALLS \
    (sizeof(syscall_gdi32_info)/sizeof(syscall_gdi32_info[0]))

size_t
num_gdi32_syscalls(void)
{
    return NUM_GDI32_SYSCALLS;
}

#undef OK
#undef UNKNOWN
#undef W
#undef R
#undef WI
#undef IB
#undef RET

/***************************************************************************
 * CUSTOM SYSCALL HANDLING
 */

static bool
handle_GdiCreateDIBSection(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                           dr_mcontext_t *mc)
{
    byte *dib;
    if (!pre && safe_read((byte *) pt->sysarg[8], sizeof(dib), &dib)) {
        /* XXX: move this into common/alloc.c since that's currently
         * driving all the known allocs, heap and otherwise
         */
        byte *dib_base;
        size_t dib_size;
        if (dr_query_memory(dib, &dib_base, &dib_size, NULL)) {
            client_handle_mmap(pt, dib_base, dib_size,
                               /* XXX: may not be file-backed but treating as
                                * all-defined and non-heap which is what this param
                                * does today.  could do dr_virtual_query().
                                */
                               true/*file-backed*/);
        } else
            WARN("WARNING: unable to query DIB section "PFX"\n", dib);
    } else if (!pre)
        WARN("WARNING: unable to read NtGdiCreateDIBSection param\n");
    return true;
}

static bool
handle_GdiHfontCreate(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                      dr_mcontext_t *mc)
{
    ENUMLOGFONTEXDVW dvw;
    ENUMLOGFONTEXDVW *real_dvw = (ENUMLOGFONTEXDVW *) pt->sysarg[0];
    if (pre && safe_read((byte *) pt->sysarg[0], sizeof(dvw), &dvw)) {
        uint i;
        byte *start = (byte *) pt->sysarg[0];
        ULONG total_size = (ULONG) pt->sysarg[1];
        /* Would be: {0,-1,R,}
         * Except not all fields need to be defined.
         * If any other syscall turns out to have this param type should
         * turn this into a type handler and not a syscall handler.
         */
        check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum, start,
                     total_size, mc, "ENUMLOGFONTEXDVW");

        ASSERT(offsetof(ENUMLOGFONTEXDVW, elfEnumLogfontEx) == 0 &&
               offsetof(ENUMLOGFONTEXW, elfLogFont) == 0, "logfont structs changed");
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     offsetof(LOGFONTW, lfFaceName), mc, "LOGFONTW");
        /* Could share w/ handle_cstring_wide_access but we already safe_read
         * as we have a max size
         */
        start = (byte *) &real_dvw->elfEnumLogfontEx.elfLogFont.lfFaceName;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfLogFont.lfFaceName)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfLogFont.lfFaceName[i] != L'\0';
             i++)
            ; /* nothing */
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     i * sizeof(wchar_t), mc, "LOGFONTW.lfFaceName");

        start = (byte *) &real_dvw->elfEnumLogfontEx.elfFullName;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfFullName)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfFullName[i] != L'\0';
             i++)
            ; /* nothing */
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     i * sizeof(wchar_t), mc, "ENUMLOGFONTEXW.elfFullName");

        start = (byte *) &real_dvw->elfEnumLogfontEx.elfStyle;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfStyle)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfStyle[i] != L'\0';
             i++)
            ; /* nothing */
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     i * sizeof(wchar_t), mc, "ENUMLOGFONTEXW.elfStyle");

        start = (byte *) &real_dvw->elfEnumLogfontEx.elfScript;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfScript)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfScript[i] != L'\0';
             i++)
            ; /* nothing */
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     i * sizeof(wchar_t), mc, "ENUMLOGFONTEXW.elfScript");

        /* the dvValues of DESIGNVECTOR are optional: from 0 to 64 bytes */
        start = (byte *) &real_dvw->elfDesignVector;
        if (dvw.elfDesignVector.dvNumAxes > MM_MAX_NUMAXES) {
            dvw.elfDesignVector.dvNumAxes = MM_MAX_NUMAXES;
            WARN("WARNING: NtGdiHfontCreate design vector larger than max\n");
        }
        if ((start + offsetof(DESIGNVECTOR, dvValues) +
             dvw.elfDesignVector.dvNumAxes * sizeof(LONG)) -
            (byte*) pt->sysarg[0] != total_size) {
            WARN("WARNING: NtGdiHfontCreate total size doesn't match\n");
        }
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     offsetof(DESIGNVECTOR, dvValues) +
                     dvw.elfDesignVector.dvNumAxes * sizeof(LONG),
                     mc, "DESIGNVECTOR");
    } else if (pre)
        WARN("WARNING: unable to read NtGdiHfontCreate param\n");
    return true;
}

static bool
handle_GdiDoPalette(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                    dr_mcontext_t *mc)
{
    /* Entry would read: {3,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(PALETTEENTRY)}
     * But pPalEntries is an OUT param if !bInbound.
     * It's a convenient arg: else would have to look at iFunc.
     */
    WORD cEntries = (WORD) pt->sysarg[2];
    PALETTEENTRY *pPalEntries = (PALETTEENTRY *) pt->sysarg[3];
    bool bInbound = (bool) pt->sysarg[5];
    if (bInbound && pre) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *) pPalEntries,
                     cEntries * sizeof(PALETTEENTRY), mc, "pPalEntries");
    } else if (!bInbound) {
        check_sysmem(pre ? MEMREF_CHECK_ADDRESSABLE : MEMREF_WRITE, sysnum,
                     (byte *) pPalEntries,
                     cEntries * sizeof(PALETTEENTRY), mc, "pPalEntries");
    }
    return true;
}

bool
wingdi_process_syscall(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                       dr_mcontext_t *mc)
{
    if (sysnum == sysnum_GdiCreatePaletteInternal) {
        /* Entry would read: {0,cEntries * 4  + 4,R,} but see comment in ntgdi.h */
        if (pre) {
            UINT cEntries = (UINT) pt->sysarg[1];
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *)pt->sysarg[0],
                         sizeof(LOGPALETTE) - sizeof(PALETTEENTRY) +
                         sizeof(PALETTEENTRY) * cEntries, mc, "pLogPal");
        }
    } else if (sysnum == sysnum_GdiCheckBitmapBits) {
        /* Entry would read: {7,dwWidth * dwHeight,W,} */
        DWORD dwWidth = (DWORD) pt->sysarg[4];
        DWORD dwHeight = (DWORD) pt->sysarg[5];
        check_sysmem(pre ? MEMREF_CHECK_ADDRESSABLE : MEMREF_WRITE, sysnum,
                     (byte *)pt->sysarg[7], dwWidth * dwHeight, mc, "paResults");
    } else if (sysnum == sysnum_GdiCreateDIBSection) {
        return handle_GdiCreateDIBSection(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_GdiHfontCreate) {
        return handle_GdiHfontCreate(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_GdiDoPalette) {
        return handle_GdiDoPalette(pre, drcontext, sysnum, pt, mc);
    }

    return true; /* execute syscall */
}

