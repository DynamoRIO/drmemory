/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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

#ifndef WINDOWS
# error Windows-only
#endif

#include "dr_api.h"
#include "drmemory.h"
#include "utils.h"
#include "shadow.h"
#include "syscall_driver.h"
#include "drmemory/driver/drmemory.h" /* off of SYSCALL_DRIVER_SRCDIR */

/***************************************************************************
 * SYSTEM CALL PARAMETER INFO FROM KERNEL DRIVER
 */

/* No syscall should have more than a few writes, but in case some get queued
 * up or drmem syscalls get in there we have a big max for now.
 */
#define MAX_WRITES_TO_RECORD 64

GET_NTDLL(NtDeviceIoControlFile, (IN HANDLE FileHandle,
                                  IN HANDLE Event OPTIONAL,
                                  IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
                                  IN PVOID ApcContext OPTIONAL,
                                  OUT PIO_STATUS_BLOCK IoStatusBlock,
                                  IN ULONG IoControlCode,
                                  IN PVOID InputBuffer OPTIONAL,
                                  IN ULONG InputBufferLength,
                                  OUT PVOID OutputBuffer OPTIONAL,
                                  IN ULONG OutputBufferLength));

/* from winioctl.h */
#define FILE_ANY_ACCESS                 0
#define METHOD_BUFFERED                 0
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

static file_t f_driver;

/* we process interrupted data on a callback so we need the parent's
 * values which we store in TLS
 */
static int tls_idx_driver = -1;

typedef struct _tls_driver_t {
    void *driver_buffer;
    int sysnum;
} tls_driver_t;

void
driver_init(void)
{
    /* XXX: this needs DRi#499 fixed to convert this device path */
    f_driver = dr_open_file("\\\\.\\DrMemory", DR_FILE_READ);
    if (f_driver == INVALID_FILE)
        WARN("WARNING: unable to open driver file\n");

    /* our driver_buffer is cross-callback so we use a TLS slot */
    tls_idx_driver = drmgr_register_tls_field();
    ASSERT(tls_idx_driver > -1, "unable to reserve TLS slot");
}

void
driver_exit(void)
{
    if (f_driver != INVALID_FILE)
        dr_close_file(f_driver);
}

/* The driver supports a per-thread buffer */
void
driver_thread_init(void *drcontext)
{
    NTSTATUS res;
    IO_STATUS_BLOCK iob = {0,0};
    WritesBufferRegistration registration;
    WritesBuffer *writes;
    tls_driver_t *pt = (tls_driver_t *)
        thread_alloc(drcontext, sizeof(*pt), HEAPSTAT_MISC);
    drmgr_set_tls_field(drcontext, tls_idx_driver, (void *) pt);
    if (f_driver == INVALID_FILE)
        return;
    /* Note: we use the same buffer across callbacks (see driver_handle_callback()) */
    registration.buffer_size = sizeof(WritesBuffer) +
        sizeof(WrittenSection)*(MAX_WRITES_TO_RECORD - 1/*1 already in struct*/);
    pt->driver_buffer = thread_alloc(drcontext, registration.buffer_size, HEAPSTAT_MISC);
    writes = (WritesBuffer *) pt->driver_buffer;
    writes->num_writes = MAX_WRITES_TO_RECORD;
    registration.buffer = pt->driver_buffer;

    res = NtDeviceIoControlFile(f_driver, NULL, NULL, NULL, &iob,
                                IOCTL_DRMEMORY_REGISTER_THREAD_BUFFER,
                                &registration, sizeof(registration),
                                NULL, 0);
    if (!NT_SUCCESS(res)) {
        DO_ONCE({ WARN("WARNING: failed to register w/ syscall driver: "PFX"\n", res); });
        LOG(1, "Failed to register w/ syscall driver: "PFX"\n", res);
    } else {
        LOG(1, "Syscall driver reg for thread "TIDFMT" succeeded: buffer "PFX"-"PFX"\n",
            dr_get_thread_id(drcontext), pt->driver_buffer,
            (byte*)pt->driver_buffer + registration.buffer_size);
        ASSERT(iob.Information == 0, "we didn't ask for prior reg");
    }
}

void
driver_thread_exit(void *drcontext)
{
    NTSTATUS res;
    IO_STATUS_BLOCK iob = {0,0};
    WritesBufferRegistration registration = {NULL, 0};
    tls_driver_t *pt = (tls_driver_t *) drmgr_get_tls_field(drcontext, tls_idx_driver);
    size_t sz = sizeof(WritesBuffer) +
        sizeof(WrittenSection)*(MAX_WRITES_TO_RECORD - 1/*1 already in struct*/);
    if (f_driver == INVALID_FILE)
        return;
    res = NtDeviceIoControlFile(f_global, NULL, NULL, NULL, &iob,
                                IOCTL_DRMEMORY_REGISTER_THREAD_BUFFER,
                                NULL, 0, NULL, 0);
    if (!NT_SUCCESS(res))
        LOG(1, "Failed to unregister thread buffer: "PFX"\n", res);
    thread_free(drcontext, pt->driver_buffer, sz, HEAPSTAT_MISC);
    drmgr_set_tls_field(drcontext, tls_idx_driver, NULL);
    thread_free(drcontext, pt, sizeof(*pt), HEAPSTAT_MISC);
}

void
driver_handle_callback(void *drcontext)
{
    /* Callback strategy: use same kernel write buffer.  We process any kernel writes
     * that were already made by the interrupted syscall here.
     * XXX: DR or drmem cb-handling code could have made syscalls before getting
     * to here!
     */
    tls_driver_t *pt = (tls_driver_t *) drmgr_get_tls_field(drcontext, tls_idx_driver);
    driver_process_writes(drcontext, pt->sysnum);
}

void
driver_handle_cbret(void *drcontext)
{
    /* Reset buffer */
    tls_driver_t *pt = (tls_driver_t *) drmgr_get_tls_field(drcontext, tls_idx_driver);
    driver_pre_syscall(drcontext, pt->sysnum);
}

void
driver_pre_syscall(void *drcontext, int sysnum)
{
    tls_driver_t *pt = (tls_driver_t *) drmgr_get_tls_field(drcontext, tls_idx_driver);
    WritesBuffer *writes = (WritesBuffer *) pt->driver_buffer;
    size_t i;

    /* remember for syscall_handle_cbret */
    pt->sysnum = sysnum;

    if (f_driver == INVALID_FILE || writes == NULL)
        return;
    /* reset */
    writes->num_used = 0;
}

bool
driver_process_writes(void *drcontext, int sysnum)
{
    tls_driver_t *pt = (tls_driver_t *) drmgr_get_tls_field(drcontext, tls_idx_driver);
    WritesBuffer *writes = (WritesBuffer *) pt->driver_buffer;
    size_t i, num;
    if (f_driver == INVALID_FILE)
        return false;
    if (writes == NULL)
        return false;
    ASSERT(writes->num_writes == MAX_WRITES_TO_RECORD, "num_writes tampered with");
    if (writes->num_used == -1) {
        num = writes->num_writes;
        LOG(2, "driver writes buffer is full\n");
    } else
        num = writes->num_used;
    for (i = 0; i < num; i++) {
        LOG(2, "driver info: syscall #0x%x write %d: "PFX"-"PFX"\n",
            sysnum, i, writes->writes[i].start,
            (byte*)writes->writes[i].start + writes->writes[i].length);
        shadow_set_range(writes->writes[i].start,
                         (byte*)writes->writes[i].start + writes->writes[i].length,
                         SHADOW_DEFINED);
    }
    writes->num_used = 0;
    return true;
}

