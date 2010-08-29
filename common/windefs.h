/* **********************************************************
 * Copyright (c) 2008-2009 VMware, Inc.  All rights reserved.
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

#ifndef _WINDEFS_H_
#define _WINDEFS_H_ 1

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define WIN_ALLOC_SIZE (64*1024)

/* we statically link with ntdll.lib from DDK */
#define GET_NTDLL(NtFunction, signature) NTSYSAPI NTSTATUS NTAPI NtFunction signature

#define CBRET_INTERRUPT_NUM 0x2b

/***************************************************************************
 * from ntdef.h
 */

typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

/***************************************************************************
 * from ntddk.h
 */

typedef struct _RTL_BITMAP {
    ULONG SizeOfBitMap;                     // Number of bits in bit map
    PULONG Buffer;                          // Pointer to the bit map itself
} RTL_BITMAP;
typedef RTL_BITMAP *PRTL_BITMAP;

#define PROCESSOR_FEATURE_MAX 64

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign,                 // None == 0 == standard design
    NEC98x86,                       // NEC PC98xx series on X86
    EndAlternatives                 // past end of known alternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef struct _KUSER_SHARED_DATA {

    //
    // Current low 32-bit of tick count and tick count multiplier.
    //
    // N.B. The tick count is updated each time the clock ticks.
    //

    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;

    //
    // Current 64-bit interrupt time in 100ns units.
    //

    volatile KSYSTEM_TIME InterruptTime;

    //
    // Current 64-bit system time in 100ns units.
    //

    volatile KSYSTEM_TIME SystemTime;

    //
    // Current 64-bit time zone bias.
    //

    volatile KSYSTEM_TIME TimeZoneBias;

    //
    // Support image magic number range for the host system.
    //
    // N.B. This is an inclusive range.
    //

    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;

    //
    // Copy of system root in Unicode
    //

    WCHAR NtSystemRoot[ 260 ];

    //
    // Maximum stack trace depth if tracing enabled.
    //

    ULONG MaxStackTraceDepth;

    //
    // Crypto Exponent
    //

    ULONG CryptoExponent;

    //
    // TimeZoneId
    //

    ULONG TimeZoneId;

    ULONG LargePageMinimum;
    ULONG Reserved2[ 7 ];

    //
    // product type
    //

    NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;

    //
    // NT Version. Note that each process sees a version from its PEB, but
    // if the process is running with an altered view of the system version,
    // the following two fields are used to correctly identify the version
    //

    ULONG NtMajorVersion;
    ULONG NtMinorVersion;

    //
    // Processor Feature Bits
    //

    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];

    //
    // Reserved fields - do not use
    //
    ULONG Reserved1;
    ULONG Reserved3;

    //
    // Time slippage while in debugger
    //

    volatile ULONG TimeSlip;

    //
    // Alternative system architecture.  Example: NEC PC98xx on x86
    //

    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;

    //
    // If the system is an evaluation unit, the following field contains the
    // date and time that the evaluation unit expires. A value of 0 indicates
    // that there is no expiration. A non-zero value is the UTC absolute time
    // that the system expires.
    //

    LARGE_INTEGER SystemExpirationDate;

    //
    // Suite Support
    //

    ULONG SuiteMask;

    //
    // TRUE if a kernel debugger is connected/enabled
    //

    BOOLEAN KdDebuggerEnabled;


    //
    // Current console session Id. Always zero on non-TS systems
    //
    volatile ULONG ActiveConsoleId;

    //
    // Force-dismounts cause handles to become invalid. Rather than
    // always probe handles, we maintain a serial number of
    // dismounts that clients can use to see if they need to probe
    // handles.
    //

    volatile ULONG DismountCount;

    //
    // This field indicates the status of the 64-bit COM+ package on the system.
    // It indicates whether the Itermediate Language (IL) COM+ images need to
    // use the 64-bit COM+ runtime or the 32-bit COM+ runtime.
    //

    ULONG ComPlusPackage;

    //
    // Time in tick count for system-wide last user input across all
    // terminal sessions. For MP performance, it is not updated all
    // the time (e.g. once a minute per session). It is used for idle
    // detection.
    //

    ULONG LastSystemRITEventTickCount;

    //
    // Number of physical pages in the system.  This can dynamically
    // change as physical memory can be added or removed from a running
    // system.
    //

    ULONG NumberOfPhysicalPages;

    //
    // True if the system was booted in safe boot mode.
    //

    BOOLEAN SafeBootMode;

    //
    // The following field is used for Heap  and  CritSec Tracing
    // The last bit is set for Critical Sec Collision tracing and
    // second Last bit is for Heap Tracing
    // Also the first 16 bits are used as counter.
    //

    ULONG TraceLogging;

    //
    // Depending on the processor, the code for fast system call
    // will differ, the following buffer is filled with the appropriate
    // code sequence and user mode code will branch through it.
    //
    // (32 bytes, using ULONGLONG for alignment).
    //
    // N.B. The following two fields are only used on 32-bit systems.
    //

    ULONGLONG   Fill0;          // alignment
    ULONGLONG   SystemCall[4];

    //
    // The 64-bit tick count.
    //

    union {
        volatile KSYSTEM_TIME TickCount;
        volatile ULONG64 TickCountQuad;
    };

    /********************* below here is Vista-only ********************
     * FIXME: should we avoid false pos by having Windows-version-specific
     * struct defs?  Not bothering for now.
     */

    //
    // Cookie for encoding pointers system wide.
    //

    ULONG Cookie;

    //
    // Client id of the process having the focus in the current
    // active console session id.
    //

    LONGLONG ConsoleSessionForegroundProcessId;

    //
    // Shared information for Wow64 processes.
    //

#define MAX_WOW64_SHARED_ENTRIES 16
    ULONG Wow64SharedInformation[MAX_WOW64_SHARED_ENTRIES];

    //
    // The following field is used for ETW user mode global logging
    // (UMGL).
    //

    USHORT UserModeGlobalLogger[8];
    ULONG HeapTracingPid[2];
    ULONG CritSecTracingPid[2];

    //
    // Settings that can enable the use of Image File Execution Options
    // from HKCU in addition to the original HKLM.
    //

    ULONG ImageFileExecutionOptions;

    //
    // This represents the affinity of active processors in the system.
    // This is updated by the kernel as processors are added\removed from
    // the system.
    //

    union {
        ULONGLONG AffinityPad;
        KAFFINITY ActiveProcessorAffinity;
    };

    //
    // Current 64-bit interrupt time bias in 100ns units.
    //

    volatile ULONG64 InterruptTimeBias;

} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

/***************************************************************************
 * from winternl.h and pdb files
 */

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((ptr_int_t)(Status)) >= 0)
#define NT_CURRENT_PROCESS ( (HANDLE) -1 )

typedef struct _UNICODE_STRING {
    /* Length field is size in bytes not counting final 0 */
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  } StatusPointer;
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StdInputHandle;
    HANDLE StdOutputHandle;
    HANDLE StdErrorHandle;
    UNICODE_STRING CurrentDirectoryPath;
    HANDLE CurrentDirectoryHandle;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingPositionLeft;
    ULONG StartingPositionTop;
    ULONG Width;
    ULONG Height;
    ULONG CharWidth;
    ULONG CharHeight;
    ULONG ConsoleTextAttributes;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopName;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    // RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20]
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define TLS_EXPANSION_BITMAP_SLOTS 1024


/* The layout here is from ntdll pdb on x64 xpsp2, though we
 * changed some PVOID types to more specific types.
 */
typedef struct _PEB {                                     /* offset: 32bit / 64bit */
    BOOLEAN                      InheritedAddressSpace;           /* 0x000 / 0x000 */
    BOOLEAN                      ReadImageFileExecOptions;        /* 0x001 / 0x001 */
    BOOLEAN                      BeingDebugged;                   /* 0x002 / 0x002 */
#if 0
    /* x64 xpsp2 lists this as a bitfield but compiler only accepts int bitfields: */
    BOOLEAN                      ImageUsesLargePages:1;           /* 0x003 / 0x003 */
    BOOLEAN                      SpareBits:7;                     /* 0x003 / 0x003 */
#else
    BOOLEAN                      ImageUsesLargePages;             /* 0x003 / 0x003 */
#endif
    HANDLE                       Mutant;                          /* 0x004 / 0x008 */
    PVOID                        ImageBaseAddress;                /* 0x008 / 0x010 */
    PVOID /* PPEB_LDR_DATA */    LoaderData;                      /* 0x00c / 0x018 */
    PVOID /* PRTL_USER_PROCESS_PARAMETERS */ ProcessParameters;   /* 0x010 / 0x020 */
    PVOID                        SubSystemData;                   /* 0x014 / 0x028 */
    PVOID                        ProcessHeap;                     /* 0x018 / 0x030 */
    PVOID /* PRTL_CRITICAL_SECTION */ FastPebLock;                /* 0x01c / 0x038 */
#if 0
    /* x64 xpsp2 lists these fields as: */
    PVOID                        AtlThunkSListPtr;                /* 0x020 / 0x040 */
    PVOID                        SparePtr2;                       /* 0x024 / 0x048 */
#else
    /* xpsp2 and earlier */
    PVOID /* PPEBLOCKROUTINE */  FastPebLockRoutine;              /* 0x020 / 0x040 */
    PVOID /* PPEBLOCKROUTINE */  FastPebUnlockRoutine;            /* 0x024 / 0x048 */
#endif
    DWORD                        EnvironmentUpdateCount;          /* 0x028 / 0x050 */
    PVOID                        KernelCallbackTable;             /* 0x02c / 0x058 */
#if 0
    /* x64 xpsp2 lists these fields as: */
    DWORD                        SystemReserved[1];               /* 0x030 / 0x060 */
    DWORD                        SpareUlong;                      /* 0x034 / 0x064 */
#else
    /* xpsp2 and earlier */
    DWORD                        EvengLogSection;                 /* 0x030 / 0x060 */
    DWORD                        EventLog;                        /* 0x034 / 0x064 */
#endif
    PVOID /* PPEB_FREE_BLOCK */  FreeList;                        /* 0x038 / 0x068 */
    DWORD                        TlsExpansionCounter;             /* 0x03c / 0x070 */
    PRTL_BITMAP                  TlsBitmap;                       /* 0x040 / 0x078 */
    DWORD                        TlsBitmapBits[2];                /* 0x044 / 0x080 */
    PVOID                        ReadOnlySharedMemoryBase;        /* 0x04c / 0x088 */
    PVOID                        ReadOnlySharedMemoryHeap;        /* 0x050 / 0x090 */
    PVOID /* PPVOID */           ReadOnlyStaticServerData;        /* 0x054 / 0x098 */
    PVOID                        AnsiCodePageData;                /* 0x058 / 0x0a0 */
    PVOID                        OemCodePageData;                 /* 0x05c / 0x0a8 */
    PVOID                        UnicodeCaseTableData;            /* 0x060 / 0x0b0 */
    DWORD                        NumberOfProcessors;              /* 0x064 / 0x0b8 */
    DWORD                        NtGlobalFlag;                    /* 0x068 / 0x0bc */
    LARGE_INTEGER                CriticalSectionTimeout;          /* 0x070 / 0x0c0 */
    UINT_PTR                     HeapSegmentReserve;              /* 0x078 / 0x0c8 */
    UINT_PTR                     HeapSegmentCommit;               /* 0x07c / 0x0d0 */
    UINT_PTR                     HeapDeCommitTotalFreeThreshold;  /* 0x080 / 0x0d8 */
    UINT_PTR                     HeapDeCommitFreeBlockThreshold;  /* 0x084 / 0x0e0 */
    DWORD                        NumberOfHeaps;                   /* 0x088 / 0x0e8 */
    DWORD                        MaximumNumberOfHeaps;            /* 0x08c / 0x0ec */
    PVOID /* PPVOID */           ProcessHeaps;                    /* 0x090 / 0x0f0 */
    PVOID                        GdiSharedHandleTable;            /* 0x094 / 0x0f8 */
    PVOID                        ProcessStarterHelper;            /* 0x098 / 0x100 */
    DWORD                        GdiDCAttributeList;              /* 0x09c / 0x108 */
    PVOID /* PRTL_CRITICAL_SECTION */ LoaderLock;                 /* 0x0a0 / 0x110 */
    DWORD                        OSMajorVersion;                  /* 0x0a4 / 0x118 */
    DWORD                        OSMinorVersion;                  /* 0x0a8 / 0x11c */
    WORD                         OSBuildNumber;                   /* 0x0ac / 0x120 */
    WORD                         OSCSDVersion;                    /* 0x0ae / 0x122 */
    DWORD                        OSPlatformId;                    /* 0x0b0 / 0x124 */
    DWORD                        ImageSubsystem;                  /* 0x0b4 / 0x128 */
    DWORD                        ImageSubsystemMajorVersion;      /* 0x0b8 / 0x12c */
    DWORD                        ImageSubsystemMinorVersion;      /* 0x0bc / 0x130 */
    UINT_PTR                     ImageProcessAffinityMask;        /* 0x0c0 / 0x138 */
#ifdef X64
    DWORD                        GdiHandleBuffer[60];             /* 0x0c4 / 0x140 */
#else
    DWORD                        GdiHandleBuffer[34];             /* 0x0c4 / 0x140 */
#endif
    PVOID                        PostProcessInitRoutine;          /* 0x14c / 0x230 */
    PRTL_BITMAP                  TlsExpansionBitmap;              /* 0x150 / 0x238 */
    DWORD                        TlsExpansionBitmapBits[32];      /* 0x154 / 0x240 */
    DWORD                        SessionId;                       /* 0x1d4 / 0x2c0 */
    ULARGE_INTEGER               AppCompatFlags;                  /* 0x1d8 / 0x2c8 */
    ULARGE_INTEGER               AppCompatFlagsUser;              /* 0x1e0 / 0x2d0 */
    PVOID                        pShimData;                       /* 0x1e8 / 0x2d8 */
    PVOID                        AppCompatInfo;                   /* 0x1ec / 0x2e0 */
    UNICODE_STRING               CSDVersion;                      /* 0x1f0 / 0x2e8 */
    PVOID                        ActivationContextData;           /* 0x1f8 / 0x2f8 */
    PVOID                        ProcessAssemblyStorageMap;       /* 0x1fc / 0x300 */
    PVOID                        SystemDefaultActivationContextData;/* 0x200 / 0x308 */
    PVOID                        SystemAssemblyStorageMap;        /* 0x204 / 0x310 */
    UINT_PTR                     MinimumStackCommit;              /* 0x208 / 0x318 */
    PVOID /* PPVOID */           FlsCallback;                     /* 0x20c / 0x320 */
    LIST_ENTRY                   FlsListHead;                     /* 0x210 / 0x328 */
    PVOID                        FlsBitmap;                       /* 0x218 / 0x338 */
    DWORD                        FlsBitmapBits[4];                /* 0x21c / 0x340 */
    DWORD                        FlsHighIndex;                    /* 0x22c / 0x350 */
} PEB, *PPEB;

typedef struct _CLIENT_ID {
    /* These are numeric ids */
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _GDI_TEB_BATCH
{
    ULONG  Offset;
    HANDLE HDC;
    ULONG  Buffer[0x136];
} GDI_TEB_BATCH;

/* The layout here is from ntdll pdb on x64 xpsp2 */
typedef struct _TEB {                               /* offset: 32bit / 64bit */
    /* We lay out NT_TIB, which is declared in winnt.h */    
    PVOID /* PEXCEPTION_REGISTRATION_RECORD */ExceptionList;/* 0x000 / 0x000 */
    PVOID                     StackBase;                    /* 0x004 / 0x008 */
    PVOID                     StackLimit;                   /* 0x008 / 0x010 */
    PVOID                     SubSystemTib;                 /* 0x00c / 0x018 */
    union {
        PVOID                 FiberData;                    /* 0x010 / 0x020 */
        DWORD                 Version;                      /* 0x010 / 0x020 */
    };
    PVOID                     ArbitraryUserPointer;         /* 0x014 / 0x028 */
    struct _TEB*              Self;                         /* 0x018 / 0x030 */
    PVOID                     EnvironmentPointer;           /* 0x01c / 0x038 */
    CLIENT_ID                 ClientId;                     /* 0x020 / 0x040 */
    PVOID                     ActiveRpcHandle;              /* 0x028 / 0x050 */
    PVOID                     ThreadLocalStoragePointer;    /* 0x02c / 0x058 */
    PEB*                      ProcessEnvironmentBlock;      /* 0x030 / 0x060 */
    DWORD                     LastErrorValue;               /* 0x034 / 0x068 */
    DWORD                     CountOfOwnedCriticalSections; /* 0x038 / 0x06c */
    PVOID                     CsrClientThread;              /* 0x03c / 0x070 */
    PVOID                     Win32ThreadInfo;              /* 0x040 / 0x078 */
    DWORD                     User32Reserved[26];           /* 0x044 / 0x080 */
    DWORD                     UserReserved[5];              /* 0x0ac / 0x0e8 */
    PVOID                     WOW32Reserved;                /* 0x0c0 / 0x100 */
    DWORD                     CurrentLocale;                /* 0x0c4 / 0x108 */
    DWORD                     FpSoftwareStatusRegister;     /* 0x0c8 / 0x10c */
    PVOID /* kernel32 data */ SystemReserved1[54];          /* 0x0cc / 0x110 */
    LONG                      ExceptionCode;                /* 0x1a4 / 0x2c0 */
    PVOID                     ActivationContextStackPointer;/* 0x1a8 / 0x2c8 */
#ifdef X64
    byte                      SpareBytes1[28];              /* 0x1ac / 0x2d0 */
#else
    byte                      SpareBytes1[40];              /* 0x1ac / 0x2d0 */
#endif
    GDI_TEB_BATCH             GdiTebBatch;                  /* 0x1d4 / 0x2f0 */
    CLIENT_ID                 RealClientId;                 /* 0x6b4 / 0x7d8 */
    PVOID                     GdiCachedProcessHandle;       /* 0x6bc / 0x7e8 */
    DWORD                     GdiClientPID;                 /* 0x6c0 / 0x7f0 */
    DWORD                     GdiClientTID;                 /* 0x6c4 / 0x7f4 */
    PVOID                     GdiThreadLocalInfo;           /* 0x6c8 / 0x7f8 */
    UINT_PTR                  Win32ClientInfo[62];          /* 0x6cc / 0x800 */
    PVOID                     glDispatchTable[233];         /* 0x7c4 / 0x9f0 */
    UINT_PTR                  glReserved1[29];              /* 0xb68 / 0x1138 */
    PVOID                     glReserved2;                  /* 0xbdc / 0x1220 */
    PVOID                     glSectionInfo;                /* 0xbe0 / 0x1228 */
    PVOID                     glSection;                    /* 0xbe4 / 0x1230 */
    PVOID                     glTable;                      /* 0xbe8 / 0x1238 */
    PVOID                     glCurrentRC;                  /* 0xbec / 0x1240 */
    PVOID                     glContext;                    /* 0xbf0 / 0x1248 */
    DWORD                     LastStatusValue;              /* 0xbf4 / 0x1250 */
    UNICODE_STRING            StaticUnicodeString;          /* 0xbf8 / 0x1258 */
    WORD                      StaticUnicodeBuffer[261];     /* 0xc00 / 0x1268 */
    PVOID                     DeallocationStack;            /* 0xe0c / 0x1478 */
    PVOID                     TlsSlots[64];                 /* 0xe10 / 0x1480 */
    LIST_ENTRY                TlsLinks;                     /* 0xf10 / 0x1680 */
    PVOID                     Vdm;                          /* 0xf18 / 0x1690 */
    PVOID                     ReservedForNtRpc;             /* 0xf1c / 0x1698 */
    PVOID                     DbgSsReserved[2];             /* 0xf20 / 0x16a0 */
    DWORD                     HardErrorMode;                /* 0xf28 / 0x16b0 */
    PVOID                     Instrumentation[14];          /* 0xf2c / 0x16b8 */
    PVOID                     SubProcessTag;                /* 0xf64 / 0x1728 */
    PVOID                     EtwTraceData;                 /* 0xf68 / 0x1730 */
    PVOID                     WinSockData;                  /* 0xf6c / 0x1738 */
    DWORD                     GdiBatchCount;                /* 0xf70 / 0x1740 */
    byte                      InDbgPrint;                   /* 0xf74 / 0x1744 */
    byte                      FreeStackOnTermination;       /* 0xf75 / 0x1745 */
    byte                      HasFiberData;                 /* 0xf76 / 0x1746 */
    byte                      IdealProcessor;               /* 0xf77 / 0x1747 */
    DWORD                     GuaranteedStackBytes;         /* 0xf78 / 0x1748 */
    PVOID                     ReservedForPerf;              /* 0xf7c / 0x1750 */
    PVOID                     ReservedForOle;               /* 0xf80 / 0x1758 */
    DWORD                     WaitingOnLoaderLock;          /* 0xf84 / 0x1760 */
    UINT_PTR                  SparePointer1;                /* 0xf88 / 0x1768 */
    UINT_PTR                  SoftPatchPtr1;                /* 0xf8c / 0x1770 */
    UINT_PTR                  SoftPatchPtr2;                /* 0xf90 / 0x1778 */
    PVOID /* PPVOID */        TlsExpansionSlots;            /* 0xf94 / 0x1780 */
#ifdef X64
    PVOID                     DeallocationBStore;           /* ----- / 0x1788 */
    PVOID                     BStoreLimit;                  /* ----- / 0x1790 */
#endif
    DWORD                     ImpersonationLocale;          /* 0xf98 / 0x1798 */
    DWORD                     IsImpersonating;              /* 0xf9c / 0x179c */
    PVOID                     NlsCache;                     /* 0xfa0 / 0x17a0 */
    PVOID                     pShimData;                    /* 0xfa4 / 0x17a8 */
    DWORD                     HeapVirtualAffinity;          /* 0xfa8 / 0x17b0 */
    PVOID                     CurrentTransactionHandle;     /* 0xfac / 0x17b8 */
    PVOID                     ActiveFrame;                  /* 0xfb0 / 0x17c0 */
    PVOID                     FlsData;                      /* 0xfb4 / 0x17c8 */
    byte                      SafeThunkCall;                /* 0xfb8 / 0x17d0 */
    byte                      BooleanSpare[3];              /* 0xfb9 / 0x17d1 */
    /* in Vista: not verified */
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    WORD CrossTebFlags;
    ULONG SpareCrossTebBits: 16;
    WORD SameTebFlags;
    ULONG DbgSafeThunkCall: 1;
    ULONG DbgInDebugPrint: 1;
    ULONG DbgHasFiberData: 1;
    ULONG DbgSkipThreadAttach: 1;
    ULONG DbgWerInShipAssertCode: 1;
    ULONG DbgRanProcessInit: 1;
    ULONG DbgClonedThread: 1;
    ULONG DbgSuppressDebugMsg: 1;
    ULONG SpareSameTebBits: 8;
    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG ProcessRundown;
    UINT64 LastSwitchTime;
    UINT64 TotalSwitchOutTime;
    LARGE_INTEGER WaitReasonBitMap;
} TEB;

typedef struct _PORT_SECTION_WRITE {
    ULONG Length;
    HANDLE SectionHandle;
    ULONG SectionOffset;
    ULONG ViewSize;
    PVOID ViewBase;
    PVOID TargetViewBase;
} PORT_SECTION_WRITE, *PPORT_SECTION_WRITE;

typedef struct _PORT_SECTION_READ {
    ULONG Length;
    ULONG ViewSize;
    ULONG ViewBase;
} PORT_SECTION_READ, *PPORT_SECTION_READ;

typedef struct _FILE_USER_QUOTA_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER QuotaUsed;
    LARGE_INTEGER QuotaThreshold;
    LARGE_INTEGER QuotaLimit;
    SID Sid[1];
} FILE_USER_QUOTA_INFORMATION, *PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    SID Sid[1];
} FILE_QUOTA_LIST_INFORMATION, *PFILE_QUOTA_LIST_INFORMATION;

typedef struct _USER_STACK {
    PVOID FixedStackBase;
    PVOID FixedStackLimit;
    PVOID ExpandableStackBase;
    PVOID ExpandableStackLimit;
    PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef
VOID
(*PTIMER_APC_ROUTINE) (
    __in PVOID TimerContext,
    __in ULONG TimerLowValue,
    __in LONG TimerHighValue
    );

/***************************************************************************
 * from wdm.h
 */

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _KEY_VALUE_ENTRY {
    PUNICODE_STRING ValueName;
    ULONG           DataLength;
    ULONG           DataOffset;
    ULONG           Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef
VOID
(*PKNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    );

typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );

#ifdef X64
# define PORT_MAXIMUM_MESSAGE_LENGTH 512
#else
# define PORT_MAXIMUM_MESSAGE_LENGTH 256
#endif

/***************************************************************************
 * from ntifs.h
 */

typedef short CSHORT;
#define LPC_SIZE_T SIZE_T
#define LPC_CLIENT_ID CLIENT_ID

typedef struct _PORT_MESSAGE {
    union {
        struct {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        LPC_CLIENT_ID ClientId;
        double DoNotUseThisField;       // Force quadword alignment
    };
    ULONG MessageId;
    union {
        LPC_SIZE_T ClientViewSize;          // Only valid on LPC_CONNECTION_REQUEST message
        ULONG CallbackId;                   // Only valid on LPC_REQUEST message
    } u3;
//  UCHAR Data[];
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _FILE_GET_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR EaNameLength;
    CHAR EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

#if defined(USE_LPC6432)
#define LPC_CLIENT_ID CLIENT_ID64
#define LPC_SIZE_T ULONGLONG
#define LPC_PVOID ULONGLONG
#define LPC_HANDLE ULONGLONG
#else
#define LPC_CLIENT_ID CLIENT_ID
#define LPC_SIZE_T SIZE_T
#define LPC_PVOID PVOID
#define LPC_HANDLE HANDLE
#endif

typedef struct _PORT_VIEW {
    ULONG Length;
    LPC_HANDLE SectionHandle;
    ULONG SectionOffset;
    LPC_SIZE_T ViewSize;
    LPC_PVOID ViewBase;
    LPC_PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW {
    ULONG Length;
    LPC_SIZE_T ViewSize;
    LPC_PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;


/***************************************************************************
 * from ReactOS include/ndk/dbgktypes.h
 */

//
// Debug States
//
typedef enum _DBG_STATE
{
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

//
// Debug Message Structures
//
typedef struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

//
// User-Mode Debug State Change Structure
//
typedef struct _DBGUI_WAIT_STATE_CHANGE
{
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union
    {
        struct
        {
            HANDLE HandleToThread;
            DBGKM_CREATE_THREAD NewThread;
        } CreateThread;
        struct
        {
            HANDLE HandleToProcess;
            HANDLE HandleToThread;
            DBGKM_CREATE_PROCESS NewProcess;
        } CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_EXCEPTION Exception;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;


/***************************************************************************
 * from ReactOS include/ndk/iotypes.h
 */

//
// Firmware Boot File Path
//
typedef struct _FILE_PATH
{
    ULONG Version;
    ULONG Length;
    ULONG Type;
    CHAR FilePath[1];
} FILE_PATH, *PFILE_PATH;

//
// Firmware Boot Options
//
typedef struct _BOOT_OPTIONS
{
    ULONG Version;
    ULONG Length;
    ULONG Timeout;
    ULONG CurrentBootEntryId;
    ULONG NextBootEntryId;
    WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, *PBOOT_OPTIONS;


/***************************************************************************
 * from winsdk-6.1.6000/Include/Evntrace.h (issues including it directly)
 */

//
// Trace header for all legacy events. 
//

typedef struct _EVENT_TRACE_HEADER {        // overlays WNODE_HEADER
    USHORT          Size;                   // Size of entire record
    union {
        USHORT      FieldTypeFlags;         // Indicates valid fields
        struct {
            UCHAR   HeaderType;             // Header type - internal use only
            UCHAR   MarkerFlags;            // Marker - internal use only
        };
    };
    union {
        ULONG       Version;
        struct {
            UCHAR   Type;                   // event type
            UCHAR   Level;                  // trace instrumentation level
            USHORT  Version;                // version of trace record
        } Class;
    };
    ULONG           ThreadId;               // Thread Id
    ULONG           ProcessId;              // Process Id
    LARGE_INTEGER   TimeStamp;              // time when event happens
    union {
        GUID        Guid;                   // Guid that identifies event
        ULONGLONG   GuidPtr;                // use with WNODE_FLAG_USE_GUID_PTR
    };
    union {
        struct {
            ULONG   KernelTime;             // Kernel Mode CPU ticks
            ULONG   UserTime;               // User mode CPU ticks
        };
        ULONG64     ProcessorTime;          // Processor Clock
        struct {
            ULONG   ClientContext;          // Reserved
            ULONG   Flags;                  // Event Flags
        };
    };
} EVENT_TRACE_HEADER, *PEVENT_TRACE_HEADER;


/***************************************************************************
 * UNKNOWN
 * Can't find these anywhere
 */

typedef struct _CHANNEL_MESSAGE {
    ULONG unknown;
} CHANNEL_MESSAGE, *PCHANNEL_MESSAGE;

#endif /* _WINDEFS_H_ */
