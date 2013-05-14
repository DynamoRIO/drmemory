/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was created to make information necessary for userspace
 ***   to call into the Windows kernel available to Dr. Memory.  It contains 
 ***   only constants, structures, and macros, and thus, contains no 
 ***   copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/

#ifndef _NTUSER_WIN8_
#define _NTUSER_WIN8_ 1

/* Observed called from IMM32!IsLegacyIMEDisabled.  Both fields are written
 * with 0 in all observed instances.
 */
typedef struct _PROCESS_UI_CONTEXT
{
    DWORD Unknown1;
    DWORD Unknown2;
} PROCESS_UI_CONTEXT, *PPROCESS_UI_CONTEXT;

BOOL
NTAPI
NtUserGetProcessUIContextInformation(
    __in  HANDLE              ProcessHandle,
    __out PROCESS_UI_CONTEXT  *ContextInformation
    );


#endif /* _NTUSER_WIN8_ */

