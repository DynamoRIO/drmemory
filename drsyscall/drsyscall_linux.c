/* **********************************************************
 * Copyright (c) 2010-2012 Google, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "drsyscall.h"
#include "drsyscall_os.h"
#include "sysnum_linux.h"
#include "heap.h"
#include "asm_utils.h"
#include <string.h> /* for strcmp */
#include <stddef.h> /* for offsetof */

/* for linux-specific types/defines for fcntl and ipc */
#define __USE_GNU 1

#ifdef HAVE_ASM_I386
/* tying them all to this one header for now */
# define GLIBC_2_3_2 1
#endif

#include <sys/types.h>
#ifdef GLIBC_2_3_2
# include <asm-i386/stat.h>
#else
# include <asm/stat.h>
# include <sys/ustat.h>
# include <sys/statfs.h>
#endif
#include <utime.h> /* struct utimbuf */
#include <sys/times.h> /* struct tms */
#include <sys/resource.h> /* struct rlimit */
#include <sys/time.h> /* struct timezone */
#include <sys/sysinfo.h> /* struct sysinfo */
#include <sys/timex.h> /* struct timex */
#include <linux/utsname.h> /* struct new_utsname */
#include <sched.h> /* struct sched_param */

/* Avoid conflicts w/ DR's REG_* enum w/ more recent distros
 * by directly getting siginfo_t instead of including "<signal.h>".
 * Xref DRi#34.  We could instead update to use DR_REG_* and unset
 * DynamoRIO_REG_COMPATIBILITY.
 */
#define __need_siginfo_t
#define __need_sigevent_t
#include <bits/siginfo.h>

#include <linux/capability.h> /* cap_user_header_t */
/* capability.h conflicts with and is superset of these:
 * #include <sys/ustat.h> (struct ustat)
 * #include <sys/statfs.h> (struct statfs)
 */
#include <poll.h>
#include <sys/epoll.h> /* struct epoll_event */
#include <time.h> /* struct itimerspec */
#include <errno.h> /* for EBADF */
#include <linux/sysctl.h> /* struct __sysctl_args */

/* block bits/stat.h which is included from fcntl.h on FC16 (glibc 2.14) */
#define _BITS_STAT_H	1
#include <fcntl.h> /* F_GETFD, etc. */

#include <asm/ldt.h> /* struct user_desc */
#include <linux/futex.h>
#include <linux/mman.h> /* MREMAP_FIXED */

/* ipc */
#ifdef GLIBC_2_3_2
# include <sys/ipc.h>
# include <asm/ipc.h>
# include <sys/sem.h>
# include <sys/shm.h>
# include <sys/msg.h>
#else
# include <linux/ipc.h>
# include <linux/sem.h>
# include <linux/shm.h>
# include <linux/msg.h>
#endif

/* socket */
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/netlink.h>

#ifndef SYS_ACCEPT4
# define SYS_ACCEPT4 18
#endif

/* ioctl */
#include <sys/ioctl.h>
#include <asm/ioctls.h>
#include <termios.h>
#include <linux/serial.h>
#include <linux/ax25.h>
#include <linux/cdk.h>
#include <linux/cdrom.h>
#include <linux/cyclades.h>
#include <linux/fs.h>

/* i#911: linux/ext2_fs.h references a now-removed type umode_t in
 * FC16 (in flux apparently) so we define on our own:
 */
#ifndef EXT2_IOC_GETFLAGS
# define EXT2_IOC_GETFLAGS               FS_IOC_GETFLAGS
# define EXT2_IOC_SETFLAGS               FS_IOC_SETFLAGS
# define EXT2_IOC_GETVERSION             FS_IOC_GETVERSION
# define EXT2_IOC_SETVERSION             FS_IOC_SETVERSION
#endif

#include <linux/fd.h>
#include <linux/hdreg.h>
#include <linux/if.h>
#include <linux/if_plip.h>
#include <linux/ipx.h>
#include <linux/kd.h>
#include <linux/lp.h>
#include <linux/mroute.h>
#ifdef GLIBC_2_3_2
# include <linux/mtio.h>
#else
# include <sys/mtio.h>
#endif
#include <linux/netrom.h>
#include <linux/scc.h>

/* i#911: linux/smb_fs.h is missing on FC16 so we define on our own */
#define SMB_IOC_GETMOUNTUID             _IOR('u', 1, __kernel_old_uid_t)

#include <linux/sockios.h>
#include <linux/route.h>
#include <linux/if_arp.h>
#include <linux/soundcard.h>
#if 0 /* XXX: header not avail: ioctl code below disabled as well */
# include <linux/umsdos_fs.h>
#endif
#include <linux/vt.h>
#include <linux/ipmi.h> /* PR 531644 */
#ifndef GLIBC_2_3_2
# include <linux/net.h>
#endif

/* prctl */
#include <sys/prctl.h>
/* may not be building w/ most recent headers */
#ifndef PR_GET_FPEMU
# define PR_GET_FPEMU  9
# define PR_SET_FPEMU 10
#endif
#ifndef PR_GET_FPEXC
# define PR_GET_FPEXC    11
# define PR_SET_FPEXC    12
#endif
#ifndef PR_GET_TIMING
# define PR_GET_TIMING   13
# define PR_SET_TIMING   14
#endif
#ifndef PR_GET_NAME
# define PR_SET_NAME    15
# define PR_GET_NAME    16
#endif
#ifndef PR_GET_ENDIAN
# define PR_GET_ENDIAN   19
# define PR_SET_ENDIAN   20
#endif
#ifndef PR_GET_SECCOMP
# define PR_GET_SECCOMP  21
# define PR_SET_SECCOMP  22
#endif
#ifndef PR_CAPBSET_READ
# define PR_CAPBSET_READ 23
# define PR_CAPBSET_DROP 24
#endif
#ifndef PR_GET_TSC
# define PR_GET_TSC 25
# define PR_SET_TSC 26
#endif
#ifndef PR_GET_SECUREBITS
# define PR_GET_SECUREBITS 27
# define PR_SET_SECUREBITS 28
#endif
#ifndef PR_GET_TIMERSLACK
# define PR_SET_TIMERSLACK 29
# define PR_GET_TIMERSLACK 30
#endif

/* kernel's sigset_t packs info into bits, while glibc's uses a short for
 * each (-> 8 bytes vs. 128 bytes)
 */
#define MAX_SIGNUM  64
#define _NSIG_WORDS (MAX_SIGNUM / sizeof(unsigned long))
typedef struct _kernel_sigset_t {
    unsigned long sig[_NSIG_WORDS];
} kernel_sigset_t;

/* differs from libc sigaction.  we do not support 2.1.20 version of this. */
typedef struct _kernel_sigaction_t {
    void *handler;
    unsigned long flags;
    void (*restorer)(void);
    kernel_sigset_t mask;
} kernel_sigaction_t;
/* not in main defines */
#define SA_RESTORER 0x04000000

#ifdef GLIBC_2_3_2
union semun {
    int val; /* value for SETVAL */
    struct semid_ds *buf; /* buffer for IPC_STAT, IPC_SET */
    unsigned short *array; /* array for GETALL, SETALL */
    struct seminfo *__buf; /* buffer for IPC_INFO */
};

/* not in older defines: version flag or-ed in for semctl, msgctl, shmctl */
# define IPC_64  0x0100  
#endif

/* used to read entire ioctl arg at once */
union ioctl_data {
    struct ipmi_req req;
    struct ipmi_req_settime reqs;
    struct ipmi_recv recv;
};

static size_t
safe_strnlen(const char *str, size_t max)
{
    register char *s = (char *) str;
    if (str == NULL)
        return 0;
    /* FIXME PR 408539: use safe_read(), in a general routine that can be used
     * for SYSARG_SIZE_CSTRING in process_syscall_reads_and_writes()
     */
    while ((s - str) < max && *s != '\0')
        s++;
    return (s - str);
}

#if DEBUG
extern void
report_callstack(void *drcontext, dr_mcontext_t *mc);
#endif /* DEBUG */

/***************************************************************************
 * SYSTEM CALLS FOR LINUX
 */

/* 64-bit vs 32-bit and mixed-mode strategy:
 *
 * We could avoid a hashtable lookup and always use an array deref in
 * syscall_lookup() while still sharing data for syscalls that are
 * identical between the two modes if we generated a static table from
 * macros.  But macros are a little ugly with commas which our nested
 * structs are full of.  So we go ahead and pay the cost of a
 * hashtable lookup.  We could list in x86 order and avoid the
 * hashtable lookup there except we want to eventually support
 * mixed-mode and thus we want both x64 and x86 entries in the same
 * list.  We assume syscall numbers easily fit in 16 bits and pack the
 * numbers for the two platforms together via PACKNUM.
 *
 * For mixed-mode, the plan is to have the static table be x64 and to copy
 * it into the heap for x86.  While walking it we'll construct a table
 * mapping x64 numbers to their equivalent x86 numbers, allowing us to
 * use something like is_sysnum(num, SYS_mmap) (where SYS_mmap is the x64
 * number from sysnum_linux.h) in syscall dispatch (we'll have to replace
 * the switch statements with if-else).
 * XXX i#1013: for all the sizeof(struct) entries we'll have to make two entries
 * and define our own 32-bit version of the struct.
 */
#define PACKNUM(x64,x86) (((x64) << 16) | (x86 & 0xffff))
/* the cast is for sign extension for -1 sentinel */
#define UNPACK_X64(packed) ((int)(short)((packed) >> 16))
#define UNPACK_X86(packed) ((int)(short)((packed) & 0xffff))

/* Table that maps system call number to a syscall_info_t* */
#define SYSTABLE_HASH_BITS 9 /* ~2x the # of entries */
hashtable_t systable;

/* Created from ./mksystable_linux.pl
 * And then manually:
 * - filling in params for those marked "Missing prototype"
 * - filling in params for those marked "special-case"
 * - replacing U with W or R
 * - updating sizeof(char) and sizeof(void)
 *
 * FIXME i#92: still a lot of missing details below!
 */
#define OK (SYSINFO_ALL_PARAMS_KNOWN)
#define UNKNOWN 0
#define W (SYSARG_WRITE)
#define R (SYSARG_READ)
#define WI (SYSARG_WRITE | SYSARG_LENGTH_INOUT)
#define CT (SYSARG_COMPLEX_TYPE)
#define CSTRING (SYSARG_TYPE_CSTRING)
#define RET (SYSARG_POST_SIZE_RETVAL)
#define RLONG (DRSYS_TYPE_SIGNED_INT) /* they all return type "long" */
static syscall_info_t syscall_info[] = {
    {{PACKNUM(219,0),0},"restart_syscall", OK, RLONG, 0,},
    {{PACKNUM(60,1),0},"exit", OK, RLONG, 1,},
    {{PACKNUM(57,2),0},"fork", OK, RLONG, 0,},
    {{PACKNUM(0,3),0},"read", OK, RLONG, 3,{{1,-2,W},{1,RET,W},}},
    {{PACKNUM(1,4),0},"write", OK, RLONG, 3,{{1,-2,R},}},
    {{PACKNUM(2,5),0},"open", OK, RLONG, 2,{{0,0,R|CT,CSTRING},}}, /*special-cased: 3rd arg not always required*/
    {{PACKNUM(3,6),0},"close", OK, RLONG, 1,},
    {{PACKNUM(-1,7),0},"waitpid", OK, RLONG, 3,{{1,sizeof(int),W},}},
    {{PACKNUM(85,8),0},"creat", OK, RLONG, 2,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(86,9),0},"link", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},}},
    {{PACKNUM(87,10),0},"unlink", OK, RLONG, 1,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(59,11),0},"execve", OK, RLONG, 3,{{0,0,R|CT,CSTRING},/* FIXME: char** argv and envp */}},
    {{PACKNUM(80,12),0},"chdir", OK, RLONG, 1,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(36,13),0},"time", OK, RLONG, 1,{{0,sizeof(time_t),W},}},
    {{PACKNUM(133,14),0},"mknod", OK, RLONG, 3,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(90,15),0},"chmod", OK, RLONG, 2,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(-1,16),0},"lchown16", OK, RLONG, 3,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(-1,17),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,18),0},"stat", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct __old_kernel_stat),W},}},
    {{PACKNUM(4,-1),0},"stat", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct stat),W},}},
    {{PACKNUM(8,19),0},"lseek", OK, RLONG, 3,},
    {{PACKNUM(39,20),0},"getpid", OK, RLONG, 0,},
    {{PACKNUM(165,21),0},"mount", OK, RLONG, 5,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},{2,0,R|CT,CSTRING},/*FIXME: 4 varies: ignore for now*/}},
    {{PACKNUM(-1,22),0},"oldumount", OK, RLONG, 1,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(-1,23),0},"setuid16", OK, RLONG, 1,},
    {{PACKNUM(-1,24),0},"getuid16", OK, RLONG, 0,},
    {{PACKNUM(-1,25),0},"stime", OK, RLONG, 1,{{0,sizeof(time_t),R},}},
    {{PACKNUM(101,26),0},"ptrace", OK, RLONG, 4,},
    {{PACKNUM(37,27),0},"alarm", OK, RLONG, 1,},
    {{PACKNUM(-1,28),0},"fstat", OK, RLONG, 2,{{1,sizeof(struct __old_kernel_stat),W},}},
    {{PACKNUM(5,-1),0},"fstat", OK, RLONG, 2,{{1,sizeof(struct stat),W},}},
    {{PACKNUM(34,29),0},"pause", OK, RLONG, 0,},
    {{PACKNUM(132,30),0},"utime", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct utimbuf),R},}},
    {{PACKNUM(-1,31),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,32),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(21,33),0},"access", OK, RLONG, 2,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(-1,34),0},"nice", OK, RLONG, 1,},
    {{PACKNUM(-1,35),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(26,36),0},"sync", OK, RLONG, 0,},
    {{PACKNUM(62,37),0},"kill", OK, RLONG, 2,},
    {{PACKNUM(82,38),0},"rename", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},}},
    {{PACKNUM(83,39),0},"mkdir", OK, RLONG, 2,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(84,40),0},"rmdir", OK, RLONG, 1,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(32,41),0},"dup", OK, RLONG, 1,},
    {{PACKNUM(22,42),0},"pipe", OK, RLONG, 1,{{0,2*sizeof(int),W},}},
    {{PACKNUM(100,43),0},"times", OK, RLONG, 1,{{0,sizeof(struct tms),W},}},
    {{PACKNUM(-1,44),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(12,45),0},"brk", OK, RLONG, 1,},
    {{PACKNUM(-1,46),0},"setgid16", OK, RLONG, 1,},
    {{PACKNUM(-1,47),0},"getgid16", OK, RLONG, 0,},
    {{PACKNUM(282,48),0},"signal", OK, RLONG, 2,},
    {{PACKNUM(-1,49),0},"geteuid16", OK, RLONG, 0,},
    {{PACKNUM(-1,50),0},"getegid16", OK, RLONG, 0,},
    {{PACKNUM(163,51),0},"acct", OK, RLONG, 1,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(166,52),0},"umount", OK, RLONG, 2,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(-1,53),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(16,54),0},"ioctl", OK, RLONG, 3,}, /* varies: special-cased below */
    {{PACKNUM(72,55),0},"fcntl", OK, RLONG, 2,}, /*special-cased: 3rd arg not always required*/
    {{PACKNUM(-1,56),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(109,57),0},"setpgid", OK, RLONG, 2,},
    {{PACKNUM(-1,58),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,59),0},"olduname", OK, RLONG, 1, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(95,60),0},"umask", OK, RLONG, 1,},
    {{PACKNUM(161,61),0},"chroot", OK, RLONG, 1,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(136,62),0},"ustat", OK, RLONG, 2,{{1,sizeof(struct ustat),W},}},
    {{PACKNUM(33,63),0},"dup2", OK, RLONG, 2,},
    {{PACKNUM(110,64),0},"getppid", OK, RLONG, 0,},
    {{PACKNUM(111,65),0},"getpgrp", OK, RLONG, 0,},
    {{PACKNUM(112,66),0},"setsid", OK, RLONG, 0,},
    {{PACKNUM(13,67),0},"sigaction", OK, RLONG, 3,/*FIXME type: {{1,sizeof(struct old_sigaction),W},{2,sizeof(struct old_sigaction),R},}*/},
    {{PACKNUM(-1,68),0},"sgetmask", OK, RLONG, 0,},
    {{PACKNUM(-1,69),0},"ssetmask", OK, RLONG, 1,},
    {{PACKNUM(-1,70),0},"setreuid16", OK, RLONG, 2,},
    {{PACKNUM(-1,71),0},"setregid16", OK, RLONG, 2,},
    {{PACKNUM(130,72),0},"sigsuspend", OK, RLONG, 3,},
    {{PACKNUM(127,73),0},"sigpending", OK, RLONG, 1,/*FIXME type: {{0,sizeof(old_sigset_t),W},}*/},
    {{PACKNUM(170,74),0},"sethostname", OK, RLONG, 2,{{0,-1,R},}},
    {{PACKNUM(160,75),0},"setrlimit", OK, RLONG, 2,{{1,sizeof(struct rlimit),R},}},
    {{PACKNUM(-1,76),0},"old_getrlimit", OK, RLONG, 2,{{1,sizeof(struct rlimit),W},}},
    {{PACKNUM(98,77),0},"getrusage", OK, RLONG, 2,{{1,sizeof(struct rusage),W},}},
    {{PACKNUM(96,78),0},"gettimeofday", OK, RLONG, 2,{{0,sizeof(struct timeval),W},{1,sizeof(struct timezone),W},}},
    {{PACKNUM(164,79),0},"settimeofday", OK, RLONG, 2,{{0,sizeof(struct timeval),R},{1,sizeof(struct timezone),R},}},
    {{PACKNUM(-1,80),0},"getgroups16", OK, RLONG, 2,/* FIXME how encode these: {{1,ARG1 * sizeof(vki_old_gid_t),W},{1,RES * sizeof(vki_old_gid_t),W},}*/},
    {{PACKNUM(-1,81),0},"setgroups16", OK, RLONG, 2,/* FIXME how encode these:{{1,ARG1 * sizeof(vki_old_gid_t),R},}*/},
    {{PACKNUM(-1,82),0},"old_select", OK, RLONG, /*FIXME*/},
    {{PACKNUM(88,83),0},"symlink", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},}},
    {{PACKNUM(-1,84),0},"lstat", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct __old_kernel_stat),W},}},
    {{PACKNUM(6,-1),0},"lstat", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct stat),W},}},
    {{PACKNUM(89,85),0},"readlink", OK, RLONG, 3,{{0,0,R|CT,CSTRING},{1,-2,W},{1,RET,W},}},
    {{PACKNUM(134,86),0},"uselib", OK, RLONG, 1,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(167,87),0},"swapon", OK, RLONG, 2,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(169,88),0},"reboot", OK, RLONG, 4, /*FIXME: 3 is optional*/},
    {{PACKNUM(-1,89),0},"old_readdir", OK, RLONG, 3,/*FIXME type: {{1,sizeof(struct old_linux_dirent),W},}*/},
    {{PACKNUM(-1,90),0},"mmap", OK, RLONG, /*FIXME*/},
    {{PACKNUM(11,91),0},"munmap", OK, RLONG, 2,},
    /* XXX i#822: for framework w/ inlined types we'll need separate x64 entries */
    {{PACKNUM(76,92),0},"truncate", OK, RLONG, 2,{{0,0,R|CT,CSTRING},}},
    /* XXX i#822: for framework w/ inlined types we'll need separate x64 entries */
    {{PACKNUM(77,93),0},"ftruncate", OK, RLONG, 2,},
    {{PACKNUM(91,94),0},"fchmod", OK, RLONG, 2,},
    {{PACKNUM(-1,95),0},"fchown16", OK, RLONG, 3,},
    {{PACKNUM(140,96),0},"getpriority", OK, RLONG, 2,},
    {{PACKNUM(141,97),0},"setpriority", OK, RLONG, 3,},
    {{PACKNUM(-1,98),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(137,99),0},"statfs", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct statfs),W},}},
    {{PACKNUM(138,100),0},"fstatfs", OK, RLONG, 2,{{1,sizeof(struct statfs),W},}},
    {{PACKNUM(173,101),0},"ioperm", OK, RLONG, 3,},
    {{PACKNUM(-1,102),0},"socketcall", OK, RLONG, 2, /* special-cased below */},
    {{PACKNUM(103,103),0},"syslog", OK, RLONG, 3,{{1,-2,W},}},
    {{PACKNUM(38,104),0},"setitimer", OK, RLONG, 3,{{1,sizeof(struct itimerval),R},{2,sizeof(struct itimerval),W},}},
    {{PACKNUM(36,105),0},"getitimer", OK, RLONG, 2,{{1,sizeof(struct itimerval),W},}},
    {{PACKNUM(-1,106),0},"newstat", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct stat),W},}},
    {{PACKNUM(-1,107),0},"newlstat", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct stat),W},}},
    {{PACKNUM(262,108),0},"newfstat", OK, RLONG, 2,{{1,sizeof(struct stat),W},}},
    {{PACKNUM(63,109),0},"uname", OK, RLONG, 1, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(172,110),0},"iopl", OK, RLONG, 1,},
    {{PACKNUM(153,111),0},"vhangup", OK, RLONG, 0,},
    {{PACKNUM(-1,112),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,113),0},"vm86old", OK, RLONG, 1, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(61,114),0},"wait4", OK, RLONG, 4,{{1,sizeof(int),W},{3,sizeof(struct rusage),W},}},
    {{PACKNUM(168,115),0},"swapoff", OK, RLONG, 1,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(99,116),0},"sysinfo", OK, RLONG, 1,{{0,sizeof(struct sysinfo),W},}},
    {{PACKNUM(-1,117),0},"ipc", OK, RLONG, 1, /* special-cased below */ },
    {{PACKNUM(74,118),0},"fsync", OK, RLONG, 1,},
    {{PACKNUM(15,119),0},"sigreturn", OK, RLONG, 0},
    {{PACKNUM(56,120),0},"clone", OK, RLONG, 2,}, /* 3 params added in later kernels special-cased */
    {{PACKNUM(171,121),0},"setdomainname", OK, RLONG, 2,{{0,-1,R},}},
    {{PACKNUM(-1,122),0},"newuname", OK, RLONG, 1,{{0,sizeof(struct new_utsname),W},}},
    {{PACKNUM(154,123),0},"modify_ldt", OK, RLONG, 3, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(159,124),0},"adjtimex", OK, RLONG, 1,{{0,sizeof(struct timex),R},}},
    {{PACKNUM(10,125),0},"mprotect", OK, RLONG, 3,},
    {{PACKNUM(14,126),0},"sigprocmask", OK, RLONG, 3,/*FIXME type: {{1,sizeof(old_sigset_t),R},{2,sizeof(old_sigset_t),W},}*/},
    {{PACKNUM(-1,127),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(175,128),0},"init_module", OK, RLONG, 3,{{0,-1,R},{2,0,R|CT,CSTRING},}},
    {{PACKNUM(176,129),0},"delete_module", OK, RLONG, 2, {{0,0,R|CT,CSTRING},}},
    {{PACKNUM(-1,130),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(179,131),0},"quotactl", OK, RLONG, 4,{{1,0,R|CT,CSTRING}, /* FIXME: #3 varies */}},
    {{PACKNUM(121,132),0},"getpgid", OK, RLONG, 1,},
    {{PACKNUM(81,133),0},"fchdir", OK, RLONG, 1,},
    {{PACKNUM(-1,134),0},"bdflush", OK, RLONG, 2,},
    {{PACKNUM(139,135),0},"sysfs", OK, RLONG, 3,},
    {{PACKNUM(135,136),0},"personality", OK, RLONG, 1,},
    {{PACKNUM(-1,137),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,138),0},"setfsuid16", OK, RLONG, 1,},
    {{PACKNUM(-1,139),0},"setfsgid16", OK, RLONG, 1,},
    {{PACKNUM(-1,140),0},"llseek", OK, RLONG, 5,{{3,sizeof(loff_t),W},}},
    {{PACKNUM(78,141),0},"getdents", OK, RLONG, 3,{{1,-2,W},{1,RET,W},}},
    {{PACKNUM(23,142),0},"select", OK, RLONG, 5,/* special-cased below */},
    {{PACKNUM(73,143),0},"flock", OK, RLONG, 2,},
    {{PACKNUM(26,144),0},"msync", OK, RLONG, 3,{{0,-1,R},}},
    {{PACKNUM(19,145),0},"readv", OK, RLONG, 3, /* FIXME 1,ARG3 * sizeof(struct vki_iovec),R, 1,****** special-case:  (Addr)vec[i].iov_base, nReadThisBuf,R, */},
    {{PACKNUM(20,146),0},"writev", OK, RLONG, 3, /* FIXME 1,ARG3 * sizeof(struct vki_iovec),R, 1,****** special-case:  "writev(vector[...])", OK, RLONG, (Addr)vec[i].iov_base, vec[i].iov_len,R, */},
    {{PACKNUM(124,147),0},"getsid", OK, RLONG, 1,},
    {{PACKNUM(75,148),0},"fdatasync", OK, RLONG, 1,},
    {{PACKNUM(156,149),0},"sysctl", OK, RLONG, 1,{{0,sizeof(struct __sysctl_args),R},}},/*special-cased*/
    {{PACKNUM(149,150),0},"mlock", OK, RLONG, 2,},
    {{PACKNUM(150,151),0},"munlock", OK, RLONG, 2,},
    {{PACKNUM(151,152),0},"mlockall", OK, RLONG, 1,},
    {{PACKNUM(152,153),0},"munlockall", OK, RLONG, 0,},
    {{PACKNUM(142,154),0},"sched_setparam", OK, RLONG, 2,{{1,sizeof(struct sched_param),R},}},
    {{PACKNUM(143,155),0},"sched_getparam", OK, RLONG, 2,{{1,sizeof(struct sched_param),W},}},
    {{PACKNUM(144,156),0},"sched_setscheduler", OK, RLONG, 3,{{2,sizeof(struct sched_param),R},}},
    {{PACKNUM(145,157),0},"sched_getscheduler", OK, RLONG, 1,},
    {{PACKNUM(24,158),0},"sched_yield", OK, RLONG, 0,},
    {{PACKNUM(146,159),0},"sched_get_priority_max", OK, RLONG, 1,},
    {{PACKNUM(147,160),0},"sched_get_priority_min", OK, RLONG, 1,},
    {{PACKNUM(148,161),0},"sched_rr_get_interval", OK, RLONG, 2, /* FIXME  1,sizeof(struct timespec),U, */},
    {{PACKNUM(35,162),0},"nanosleep", OK, RLONG, 2,{{0,sizeof(struct timespec),R},{1,sizeof(struct timespec),W},}},
    {{PACKNUM(25,163),0},"mremap", OK, RLONG, 4,}, /* 5th arg is conditional so special-cased below */
    {{PACKNUM(-1,164),0},"setresuid16", OK, RLONG, 3,},
    {{PACKNUM(-1,165),0},"getresuid16", OK, RLONG, 3,/*FIXME type: {{0,sizeof(old_uid_t),W},{1,sizeof(old_uid_t),W},{2,sizeof(old_uid_t),W},}*/},
    {{PACKNUM(-1,166),0},"vm86", OK, RLONG, 2, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(-1,167),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(7,168),0},"poll", OK, RLONG, 3, /* special-cased below */},
    {{PACKNUM(180,169),0},"nfsservctl", OK, RLONG, 3, /* FIXME 1,sizeof(struct nfsctl_arg),U, 2,sizeof(void),U, */},
    {{PACKNUM(-1,170),0},"setresgid16", OK, RLONG, 3,},
    {{PACKNUM(-1,171),0},"getresgid16", OK, RLONG, 3,/*FIXME type: {{0,sizeof(old_gid_t),W},{1,sizeof(old_gid_t),W},{2,sizeof(old_gid_t),W},}*/},
    {{PACKNUM(157,172),0},"prctl", OK, RLONG, 1, /* special-cased below */},
    {{PACKNUM(15,173),0},"rt_sigreturn", OK, RLONG, 0},
    {{PACKNUM(13,174),0},"rt_sigaction", OK, RLONG, 4,/*1 is special-cased below*/{{2,sizeof(kernel_sigaction_t),W},}},
    {{PACKNUM(14,175),0},"rt_sigprocmask", OK, RLONG, 4,{{1,sizeof(kernel_sigset_t),R},{2,sizeof(kernel_sigset_t),W},}},
    {{PACKNUM(127,176),0},"rt_sigpending", OK, RLONG, 2,{{0,sizeof(kernel_sigset_t),W},}},
    {{PACKNUM(128,177),0},"rt_sigtimedwait", OK, RLONG, 4,{{0,sizeof(kernel_sigset_t),R},{1,sizeof(siginfo_t),W},{2,sizeof(struct timespec),R},}},
    {{PACKNUM(129,178),0},"rt_sigqueueinfo", OK, RLONG, 3,{{2,sizeof(siginfo_t),R},}},
    {{PACKNUM(130,179),0},"rt_sigsuspend", OK, RLONG, 2, /* FIXME 0,sizeof(siginfo_t),R, 0,****** special-case:  arg2, sizeof(struct vki_msqid64_ds),R, */},
    {{PACKNUM(17,180),0},"pread64", OK, RLONG, 4,{{1,-2,W},{1,RET,W},}},
    {{PACKNUM(18,181),0},"pwrite64", OK, RLONG, 4,{{1,-2,R},}},
    {{PACKNUM(-1,182),0},"chown16", OK, RLONG, 3,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(79,183),0},"getcwd", OK, RLONG, 2,{{0,-1,W},{0,RET,W},}},
    {{PACKNUM(125,184),0},"capget", OK, RLONG, 2,{{0,sizeof(cap_user_header_t),R},{1,sizeof(cap_user_data_t),W},}},
    {{PACKNUM(126,185),0},"capset", OK, RLONG, 2,{{0,sizeof(cap_user_header_t),R},{1,sizeof(cap_user_data_t),R},}},
    {{PACKNUM(131,186),0},"sigaltstack", OK, RLONG, 2, /* FIXME 0,****** special-case:  "sigaltstack(ss)", OK, RLONG, (Addr)&ss->ss_sp, sizeof(ss->ss_sp),R, 0,****** special-case:  "sigaltstack(ss)", OK, RLONG, (Addr)&ss->ss_size, sizeof(ss->ss_size),R,{1,sizeof(cap_user_data_t data),W}, */},
    {{PACKNUM(40,187),0},"sendfile", OK, RLONG, 4,{{2,sizeof(off_t),W},}},
    {{PACKNUM(-1,188),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,189),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(58,190),0},"vfork", OK, RLONG, 0,},
    {{PACKNUM(97,191),0},"getrlimit", OK, RLONG, 2,{{1,sizeof(struct rlimit),W},}},
    {{PACKNUM(-1,192),0},"mmap2", OK, RLONG, 6,},
    {{PACKNUM(9,-1),0},  "mmap",  OK, RLONG, 6,},
    {{PACKNUM(-1,193),0},"truncate64", OK, RLONG, 2,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(-1,194),0},"ftruncate64", OK, RLONG, 2,},
#ifndef X64
    /* XXX i#1013: we'll need our own defs of stat64 for mixed-mode */
    {{PACKNUM(-1,195),0},"stat64", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct stat64),W},}},
    {{PACKNUM(-1,196),0},"lstat64", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,sizeof(struct stat64),W},}},
    {{PACKNUM(-1,197),0},"fstat64", OK, RLONG, 2,{{1,sizeof(struct stat64),W,}}},
#endif
    {{PACKNUM(94,198),0},"lchown", OK, RLONG, 3,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(102,199),0},"getuid", OK, RLONG, 0,},
    {{PACKNUM(104,200),0},"getgid", OK, RLONG, 0,},
    {{PACKNUM(107,201),0},"geteuid", OK, RLONG, 0,},
    {{PACKNUM(108,202),0},"getegid", OK, RLONG, 0,},
    {{PACKNUM(113,203),0},"setreuid", OK, RLONG, 2,},
    {{PACKNUM(114,204),0},"setregid", OK, RLONG, 2,},
    {{PACKNUM(115,205),0},"getgroups", OK, RLONG, 2,/*FIXME{{1,ARG1 * sizeof(vki_gid_t),W},{1,RES * sizeof(vki_gid_t),W},}*/},
    {{PACKNUM(116,206),0},"setgroups", OK, RLONG, 2,/*FIXME{{1,ARG1 * sizeof(vki_gid_t),R},}*/},
    {{PACKNUM(93,207),0},"fchown", OK, RLONG, 3,},
    {{PACKNUM(117,208),0},"setresuid", OK, RLONG, 3,},
    {{PACKNUM(118,209),0},"getresuid", OK, RLONG, 3,{{0,sizeof(uid_t),W},{1,sizeof(uid_t),W},{2,sizeof(uid_t),W},}},
    {{PACKNUM(119,210),0},"setresgid", OK, RLONG, 3,},
    {{PACKNUM(120,211),0},"getresgid", OK, RLONG, 3,{{0,sizeof(gid_t),W},{1,sizeof(gid_t),W},{2,sizeof(gid_t),W},}},
    {{PACKNUM(92,212),0},"chown", OK, RLONG, 3,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(105,213),0},"setuid", OK, RLONG, 1,},
    {{PACKNUM(106,214),0},"setgid", OK, RLONG, 1,},
    {{PACKNUM(122,215),0},"setfsuid", OK, RLONG, 1,},
    {{PACKNUM(123,216),0},"setfsgid", OK, RLONG, 1,},
    {{PACKNUM(155,217),0},"pivot_root", OK, RLONG, 2, /* FIXME 0,sizeof(char),U, 1,sizeof(char),U, */},
    {{PACKNUM(27,218),0},"mincore", OK, RLONG, 3,{{2,/*FIXME: round up to next page size*/-1,W},}},
    {{PACKNUM(28,219),0},"madvise", OK, RLONG, 3,},
    {{PACKNUM(217,220),0},"getdents64", OK, RLONG, 3,{{1,-2,W},{1,RET,W},}},
    {{PACKNUM(-1,221),0},"fcntl64", OK, RLONG, 2,}, /*special-cased: 3rd arg not always required*/
    {{PACKNUM(-1,222),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,223),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(186,224),0},"gettid", OK, RLONG, 0,},
    {{PACKNUM(187,225),0},"readahead", OK, RLONG, 3,},
    {{PACKNUM(188,226),0},"setxattr", OK, RLONG, 5,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},{2,-3,R},}},
    {{PACKNUM(189,227),0},"lsetxattr", OK, RLONG, 5,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},{2,-3,R},}},
    {{PACKNUM(190,228),0},"fsetxattr", OK, RLONG, 5,{{1,0,R|CT,CSTRING},{2,-3,R},}},
    {{PACKNUM(191,229),0},"getxattr", OK, RLONG, 4,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},{2,-3,W},{2,RET,W},}},
    {{PACKNUM(192,230),0},"lgetxattr", OK, RLONG, 4,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},{2,-3,W},{2,RET,W},}},
    {{PACKNUM(193,231),0},"fgetxattr", OK, RLONG, 4,{{1,0,R|CT,CSTRING},{2,-3,W},{2,RET,W},}},
    {{PACKNUM(194,232),0},"listxattr", OK, RLONG, 3,{{0,0,R|CT,CSTRING},{1,-2,W},{1,RET,W},}},
    {{PACKNUM(195,233),0},"llistxattr", OK, RLONG, 3,{{0,0,R|CT,CSTRING},{1,-2,W},{1,RET,W},}},
    {{PACKNUM(196,234),0},"flistxattr", OK, RLONG, 3,{{1,-2,W},{1,RET,W},}},
    {{PACKNUM(197,235),0},"removexattr", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},}},
    {{PACKNUM(198,236),0},"lremovexattr", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},}},
    {{PACKNUM(199,237),0},"fremovexattr", OK, RLONG, 2,{{1,0,R|CT,CSTRING},}},
    {{PACKNUM(200,238),0},"tkill", OK, RLONG, 2,},
    {{PACKNUM(-1,239),0},"sendfile64", OK, RLONG, 4,{{2,sizeof(loff_t),W},}},
    {{PACKNUM(202,240),0},"futex", OK, RLONG, 3,{{0,sizeof(uint),R},}},/*rest are special-cased*/
    {{PACKNUM(203,241),0},"sched_setaffinity", OK, RLONG, 3,{{2,-1,R},}},
    {{PACKNUM(204,242),0},"sched_getaffinity", OK, RLONG, 3,{{2,-1,W},}},
    {{PACKNUM(205,243),0},"set_thread_area", OK, RLONG, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(211,244),0},"get_thread_area", OK, RLONG, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(206,245),0},"io_setup", OK, RLONG, 2,/*FIXME type: {{1,sizeof(aio_context_t),W},}*/},
    {{PACKNUM(207,246),0},"io_destroy", OK, RLONG, 1,},
    {{PACKNUM(208,247),0},"io_getevents", OK, RLONG, 5, /* FIXME 3,sizeof(struct io_event),W, 3,****** special-case:  cb->aio_buf, vev->result,W,{4,sizeof(struct timespec),R}, */},
    {{PACKNUM(209,248),0},"io_submit", OK, RLONG, 3, /* FIXME 2,ARG2*sizeof(struct vki_iocb *),R, 2,****** special-case:  "io_submit(PWRITE)", OK, RLONG, cb->aio_buf, cb->aio_nbytes,R, */},
    {{PACKNUM(210,249),0},"io_cancel", OK, RLONG, 3,/* FIXME type: {{1,sizeof(struct iocb),R},{2,sizeof(struct io_event),W},}*/},
    {{PACKNUM(221,250),0},"fadvise64", OK, RLONG, 4,},
    {{PACKNUM(-1,251),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(231,252),0},"exit_group", OK, RLONG, 1,},
    {{PACKNUM(212,253),0},"lookup_dcookie", OK, RLONG, 3, /* FIXME 1,sizeof(char),U,{2,-3,W},{2,RET,W}, */},
    {{PACKNUM(213,254),0},"epoll_create", OK, RLONG, 1,},
    {{PACKNUM(214,255),0},"epoll_ctl", OK, RLONG, 4,{{3,sizeof(struct epoll_event),R},}},
    {{PACKNUM(215,256),0},"epoll_wait", OK, RLONG, 4,{{1,sizeof(struct epoll_event),W},/*FIXME {1,sizeof(struct vki_epoll_event)*RES,W},*/}},
    {{PACKNUM(216,257),0},"remap_file_pages", OK, RLONG, 5,},
    {{PACKNUM(218,258),0},"set_tid_address", OK, RLONG, 1, /* FIXME 0,sizeof(int),U, */},
    {{PACKNUM(222,259),0},"timer_create", OK, RLONG, 3,{{1,sizeof(struct sigevent),R},{2,sizeof(timer_t),W},}},
    {{PACKNUM(223,260),0},"timer_settime", OK, RLONG, 4,{{2,sizeof(struct itimerspec),R},{3,sizeof(struct itimerspec),W},}},
    {{PACKNUM(224,261),0},"timer_gettime", OK, RLONG, 2,{{1,sizeof(struct itimerspec),W},}},
    {{PACKNUM(225,262),0},"timer_getoverrun", OK, RLONG, 1,},
    {{PACKNUM(226,263),0},"timer_delete", OK, RLONG, 1,},
    {{PACKNUM(227,264),0},"clock_settime", OK, RLONG, 2,{{1,sizeof(struct timespec),R},}},
    {{PACKNUM(228,265),0},"clock_gettime", OK, RLONG, 2,{{1,sizeof(struct timespec),W},}},
    {{PACKNUM(229,266),0},"clock_getres", OK, RLONG, 2,{{1,sizeof(struct timespec),W},}},
    {{PACKNUM(230,267),0},"clock_nanosleep", OK, RLONG, 4,{{2,sizeof(struct timespec),R},{3,sizeof(struct timespec),W},}},
    {{PACKNUM(-1,268),0},"statfs64", OK, RLONG, 3,{{0,0,R|CT,CSTRING},{2,-1,W},}},
    {{PACKNUM(-1,269),0},"fstatfs64", OK, RLONG, 3,{{2,-1,W},}},
    {{PACKNUM(234,270),0},"tgkill", OK, RLONG, 3,},
    {{PACKNUM(235,271),0},"utimes", OK, RLONG, 2,{{0,0,R|CT,CSTRING},{1,2 * sizeof(struct timeval),R},}},
    {{PACKNUM(-1,272),0},"fadvise64_64", OK, RLONG, 4,},
    {{PACKNUM(-1,273),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(237,274),0},"mbind", OK, RLONG, 6, /*FIXME {{3,VG_ROUNDUP(ARG5,sizeof(UWord))/sizeof(UWord),R,},}*/},
    {{PACKNUM(239,275),0},"get_mempolicy", OK, RLONG, 5,/*FIXME {{0,sizeof(int),W}, {1,VG_ROUNDUP(ARG3,sizeof(UWord)*8)/sizeof(UWord),W},}*/},
    {{PACKNUM(238,276),0},"set_mempolicy", OK, RLONG, 3, /*FIXME {{1,VG_ROUNDUP(ARG3,sizeof(UWord))/sizeof(UWord),R},}*/},
    {{PACKNUM(240,277),0},"mq_open", OK, RLONG, 4, /* FIXME 0,CSTRING,R, 0,****** special-case:  "mq_open(attr->mq_msgsize)", OK, RLONG, (Addr)&attr->mq_msgsize, sizeof(attr->mq_msgsize),R, 3,sizeof(struct mq_attr),U, */},
    {{PACKNUM(241,278),0},"mq_unlink", OK, RLONG, 1,{{0,0,R|CT,CSTRING},}},
    {{PACKNUM(242,279),0},"mq_timedsend", OK, RLONG, 5,{{1,-2,R},{4,sizeof(struct timespec),R}},},
    {{PACKNUM(243,280),0},"mq_timedreceive", OK, RLONG, 5,{{1,-2,W},{3,sizeof(unsigned int),W},{4,sizeof(struct timespec),R}},},
    {{PACKNUM(244,281),0},"mq_notify", OK, RLONG, 2,{{1,sizeof(struct sigevent),R},}},
    {{PACKNUM(245,282),0},"mq_getsetattr", OK, RLONG, 3, /* FIXME 1,****** special-case:  "mq_getsetattr(mqstat->mq_flags)", OK, RLONG, (Addr)&attr->mq_flags, sizeof(attr->mq_flags),R,{2,sizeof(struct mq_attr),W}, */},
    {{PACKNUM(246,283),0},"kexec_load", OK, RLONG, 4, /* FIXME 2,sizeof(struct kexec_segment),U, */},
    {{PACKNUM(247,284),0},"waitid", OK, RLONG, 5,{{2,sizeof(struct siginfo),W},{4,sizeof(struct rusage),W},}},
    {{PACKNUM(-1,285),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(248,286),0},"add_key", OK, RLONG, 5,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},{2,-3,R},}},
    {{PACKNUM(249,287),0},"request_key", OK, RLONG, 4,{{0,0,R|CT,CSTRING},{1,0,R|CT,CSTRING},{2,0,R|CT,CSTRING},}},
    {{PACKNUM(250,288),0},"keyctl", OK, RLONG, 5,{{1,0,R|CT,CSTRING},{2,-3,R},{2,RET,R},{3,0,R|CT,CSTRING},}},
    {{PACKNUM(251,289),0},"ioprio_set", OK, RLONG, 3,},
    {{PACKNUM(252,290),0},"ioprio_get", OK, RLONG, 2,},
    {{PACKNUM(253,291),0},"inotify_init", OK, RLONG, 0,},
    {{PACKNUM(254,292),0},"inotify_add_watch", OK, RLONG, 3,{{1,0,R|CT,CSTRING},}},
    {{PACKNUM(255,293),0},"inotify_rm_watch", OK, RLONG, 2,},
    {{PACKNUM(256,294),0},"migrate_pages", OK, RLONG, 4, /* FIXME 2,sizeof(unsigned long),U, 3,sizeof(unsigned long),U, */},
    {{PACKNUM(257,295),0},"openat", OK, RLONG, 4,{{1,0,R|CT,CSTRING},}},
    {{PACKNUM(258,296),0},"mkdirat", OK, RLONG, 3,{{1,0,R|CT,CSTRING},}},
    {{PACKNUM(259,297),0},"mknodat", OK, RLONG, 4,{{1,0,R|CT,CSTRING},}},
    {{PACKNUM(260,298),0},"fchownat", OK, RLONG, 5,{{1,0,R|CT,CSTRING},}},
    {{PACKNUM(261,299),0},"futimesat", OK, RLONG, 3,{{1,0,R|CT,CSTRING},{2,2 * sizeof(struct timeval),R},}},
    {{PACKNUM(-1,300),0},"fstatat64", OK, RLONG, 4, /* FIXME 1,sizeof(char),U, 2,sizeof(struct stat64),U, */},
    {{PACKNUM(263,301),0},"unlinkat", OK, RLONG, 3,{{1,0,R|CT,CSTRING},}},
    {{PACKNUM(264,302),0},"renameat", OK, RLONG, 4,{{1,0,R|CT,CSTRING},{3,0,R|CT,CSTRING},}},
    {{PACKNUM(263,303),0},"linkat", OK, RLONG, 5,{{1,0,R|CT,CSTRING},{3,0,R|CT,CSTRING},}},
    {{PACKNUM(266,304),0},"symlinkat", OK, RLONG, 3,{{0,0,R|CT,CSTRING},{2,0,R|CT,CSTRING},}},
    {{PACKNUM(267,305),0},"readlinkat", OK, RLONG, 4,{{1,0,R|CT,CSTRING},{2,-3,W},{2,RET,W},}},
    {{PACKNUM(268,306),0},"fchmodat", OK, RLONG, 3,{{1,0,R|CT,CSTRING},}},
    {{PACKNUM(269,307),0},"faccessat", OK, RLONG, 3,{{1,0,R|CT,CSTRING},}},
    {{PACKNUM(270,308),0},"pselect6", OK, RLONG, 6, /* special-cased below */},
    {{PACKNUM(271,309),0},"ppoll", OK, RLONG, 5, /* FIXME 0,sizeof(struct pollfd),U,{2,sizeof(struct timespec),R},{3,sizeof(kernel_sigset_t),R}, 3,****** special-case:  (Addr)(&ufds[i].revents), sizeof(ufds[i].revents),R, */},
    {{PACKNUM(272,310),0},"unshare", OK, RLONG, 1,},
    {{PACKNUM(273,311),0},"set_robust_list", OK, RLONG, 2,{{0,-1,R},}},
    {{PACKNUM(274,312),0},"get_robust_list", OK, RLONG, 3,/*FIXME type: {{1,sizeof(struct robust_list_head),W},{2,sizeof(size_t),W},}*/},
    {{PACKNUM(275,313),0},"splice", OK, RLONG, 6, /* FIXME 1,sizeof(loff_t),U, 3,sizeof(loff_t),U, */},
    {{PACKNUM(277,314),0},"sync_file_range", OK, RLONG, 4,},
    {{PACKNUM(276,315),0},"tee", OK, RLONG, 4,},
    {{PACKNUM(278,316),0},"vmsplice", OK, RLONG, 4, /* FIXME 1,sizeof(struct iovec),U, */},
    {{PACKNUM(279,317),0},"move_pages", OK, RLONG, 6, /* FIXME 2,sizeof(void),U, 3,sizeof(int),U, 4,sizeof(int),U, */},
    {{PACKNUM(-1,318),0},"getcpu", OK, RLONG, 3, /* FIXME 0,sizeof(unsigned),U, 1,sizeof(unsigned),U, 2,sizeof(struct getcpu_cache),U, */},
    {{PACKNUM(281,319),0},"epoll_pwait", OK, RLONG, 6,{{1,sizeof(struct epoll_event),W},/*FIXME {1,sizeof(struct epoll_event)*RES,W},*/{4,sizeof(kernel_sigset_t),R},}},
    {{PACKNUM(280,320),0},"utimensat", OK, RLONG, 4,{{1,0,R|CT,CSTRING},{2,2 * sizeof(struct timespec),R},}},
    {{PACKNUM(282,321),0},"signalfd", OK, RLONG, 3,{{1,sizeof(kernel_sigset_t),R},}},
    {{PACKNUM(283,322),0},"timerfd_create", OK, RLONG, 2,},
    {{PACKNUM(284,323),0},"eventfd", OK, RLONG, 1,},
    {{PACKNUM(285,324),0},"fallocate", OK, RLONG, 4,},
    {{PACKNUM(286,325),0},"timerfd_settime", OK, RLONG, 4,{{2,sizeof(struct itimerspec),R},{3,sizeof(struct itimerspec),W},}},
    {{PACKNUM(287,326),0},"timerfd_gettime", OK, RLONG, 2,{{1,sizeof(struct itimerspec),W},}},
    {{PACKNUM(289,327),0},"signalfd4", OK, RLONG, 4, /* FIXME 1,sizeof(kernel_sigset_t),U, */},
    {{PACKNUM(290,328),0},"eventfd2", OK, RLONG, 2,},
    {{PACKNUM(291,329),0},"epoll_create1", OK, RLONG, 1,},
    {{PACKNUM(292,330),0},"dup3", OK, RLONG, 3,},
    {{PACKNUM(293,331),0},"pipe2", OK, RLONG, 2, /* FIXME 0,sizeof(int),U, */},
    {{PACKNUM(294,332),0},"inotify_init1", OK, RLONG, 1,},

    /* 64-bit only */
    {{PACKNUM(29,-1),0},"shmget", OK, RLONG, 3, },
    {{PACKNUM(30,-1),0},"shmat", OK, RLONG, 3, /*FIXME i#1018: mark the shared mem as defined*/ },
    {{PACKNUM(31,-1),0},"shmctl", OK, RLONG, 3, /*special-cased*/},
    {{PACKNUM(41,-1),0},"socket", OK, RLONG, 3, },
    {{PACKNUM(42,-1),0},"connect", OK, RLONG, 3, {{1,-2,R|CT,SYSARG_TYPE_SOCKADDR}, }},
    {{PACKNUM(43,-1),0},"accept", OK, RLONG, 3, {{1,-2,WI|CT,SYSARG_TYPE_SOCKADDR},{2,sizeof(int),W}, }},
    {{PACKNUM(44,-1),0},"sendto", OK, RLONG, 6, {{1,-2,R},{4,-5,R|CT,SYSARG_TYPE_SOCKADDR}, }},
    {{PACKNUM(45,-1),0},"recvfrom", OK, RLONG, 6, {{1,-2,W},{4,-5,WI|CT,SYSARG_TYPE_SOCKADDR}, }},
    {{PACKNUM(46,-1),0},"sendmsg", OK, RLONG, 3, {{1,sizeof(struct msghdr),R|CT,SYSARG_TYPE_MSGHDR}, }},
    {{PACKNUM(47,-1),0},"recvmsg", OK, RLONG, 3, {{1,sizeof(struct msghdr),W|CT,SYSARG_TYPE_MSGHDR}, }},
    {{PACKNUM(48,-1),0},"shutdown", OK, RLONG, 2, },
    {{PACKNUM(49,-1),0},"bind", OK, RLONG, 3, {{1,-2,R|CT,SYSARG_TYPE_SOCKADDR}, }},
    {{PACKNUM(50,-1),0},"listen", OK, RLONG, 2, },
    {{PACKNUM(51,-1),0},"getsockname", OK, RLONG, 3, {{1,-2,WI|CT,SYSARG_TYPE_SOCKADDR},{2,sizeof(int),W}, }},
    {{PACKNUM(52,-1),0},"getpeername", OK, RLONG, 3, {{1,-2,WI|CT,SYSARG_TYPE_SOCKADDR},{2,sizeof(int),W}, }},
    {{PACKNUM(53,-1),0},"socketpair", OK, RLONG, 4, {{3,2*sizeof(int),W}, }},
    {{PACKNUM(54,-1),0},"setsockopt", OK, RLONG, 5, {{3,-4,R}, }},
    {{PACKNUM(55,-1),0},"getsockopt", OK, RLONG, 5, {{3,-4,WI},{4,sizeof(socklen_t),W}, }},
    {{PACKNUM(64,-1),0},"semget", OK, RLONG, 3, },
    {{PACKNUM(65,-1),0},"semop", OK, RLONG, 3, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(struct sembuf)}, }},
    {{PACKNUM(66,-1),0},"semctl", OK, RLONG, 4, /*special-cased*/},
    {{PACKNUM(67,-1),0},"shmdt", OK, RLONG, 1, /*FIXME i#1018: mark the un-shared mem as unaddr*/  },
    {{PACKNUM(68,-1),0},"msgget", OK, RLONG, 2, },
    {{PACKNUM(69,-1),0},"msgsnd", OK, RLONG, 4, {{1,-2,R|CT,SYSARG_TYPE_MSGBUF}, }},
    {{PACKNUM(70,-1),0},"msgrcv", OK, RLONG, 5, {{1,-2,W|CT,SYSARG_TYPE_MSGBUF}, }},
    {{PACKNUM(71,-1),0},"msgctl", OK, RLONG, 3, /*special-cased*/},
    /* FIXME i#1019: fill these in */
    {{PACKNUM(156,-1),0},"_sysctl", UNKNOWN, RLONG, 0, },
    {{PACKNUM(158,-1),0},"arch_prctl", UNKNOWN, RLONG, 0, },
    {{PACKNUM(166,-1),0},"umount2", UNKNOWN, RLONG, 0, },
    {{PACKNUM(174,-1),0},"create_module", UNKNOWN, RLONG, 0, },
    {{PACKNUM(177,-1),0},"get_kernel_syms", UNKNOWN, RLONG, 0, },
    {{PACKNUM(178,-1),0},"query_module", UNKNOWN, RLONG, 0, },
    {{PACKNUM(181,-1),0},"getpmsg", UNKNOWN, RLONG, 0, },
    {{PACKNUM(182,-1),0},"putpmsg", UNKNOWN, RLONG, 0, },
    {{PACKNUM(183,-1),0},"afs_syscall", UNKNOWN, RLONG, 0, },
    {{PACKNUM(184,-1),0},"tuxcall", UNKNOWN, RLONG, 0, },
    {{PACKNUM(185,-1),0},"security", UNKNOWN, RLONG, 0, },
    {{PACKNUM(214,-1),0},"epoll_ctl_old", UNKNOWN, RLONG, 0, },
    {{PACKNUM(215,-1),0},"epoll_wait_old", UNKNOWN, RLONG, 0, },
    {{PACKNUM(220,-1),0},"semtimedop", OK, RLONG, 4, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(struct sembuf)},{3,sizeof(struct timespec),R}, }},
    {{PACKNUM(236,-1),0},"vserver", UNKNOWN, RLONG, 0, },
    {{PACKNUM(262,-1),0},"newfstatat", UNKNOWN, RLONG, 0, },
    {{PACKNUM(288,-1),0},"paccept", OK, RLONG, 4, {{1,-2,WI|CT,SYSARG_TYPE_SOCKADDR},{2,sizeof(int),W}, }}, /* == accept4 */

    /* FIXME i#1019: add recently added linux syscalls */
};

#undef OK
#undef UNKNOWN
#undef W
#undef R
#undef WI
#undef CT
#undef CSTRING
#undef RET

#define NUM_SYSCALL_STATIC_ENTRIES (sizeof(syscall_info)/sizeof(syscall_info[0]))

/***************************************************************************
 * TOP-LEVEL
 */

/* Table that maps syscall names to numbers.  Payload points at num in syscall_info[]. */
#define NAME2NUM_TABLE_HASH_BITS 10 /* <500 of them */
static hashtable_t name2num_table;

drmf_status_t
drsyscall_os_init(void *drcontext)
{
    uint i;
    hashtable_init_ex(&systable, SYSTABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/,
                      false/*!synch*/, NULL, sysnum_hash, sysnum_cmp);
 
    hashtable_init(&name2num_table, NAME2NUM_TABLE_HASH_BITS, HASH_STRING,
                   false/*!strdup*/);

    dr_recurlock_lock(systable_lock);
    for (i = 0; i < NUM_SYSCALL_STATIC_ENTRIES; i++) {
#ifdef X64
        syscall_info[i].num.number = UNPACK_X64(syscall_info[i].num.number);
#else
        syscall_info[i].num.number = UNPACK_X86(syscall_info[i].num.number);
#endif
        if (syscall_info[i].num.number != -1) {
            IF_DEBUG(bool ok =)
                hashtable_add(&systable, (void *) &syscall_info[i].num,
                              (void *) &syscall_info[i]);
            ASSERT(ok, "no dups");

            IF_DEBUG(ok =)
                hashtable_add(&name2num_table, (void *) syscall_info[i].name,
                              (void *) &syscall_info[i].num);
            ASSERT(ok || strcmp(syscall_info[i].name, "ni_syscall") == 0, "no dups");
        }
    }
    dr_recurlock_unlock(systable_lock);
    return DRMF_SUCCESS;
}

void
drsyscall_os_exit(void)
{
    hashtable_delete(&systable);
    hashtable_delete(&name2num_table);
}

void
drsyscall_os_thread_init(void *drcontext)
{
}

void
drsyscall_os_thread_exit(void *drcontext)
{
}

void
drsyscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
}

bool
os_syscall_get_num(const char *name, drsys_sysnum_t *num_out OUT)
{
    drsys_sysnum_t *num = (drsys_sysnum_t *)
        hashtable_lookup(&name2num_table, (void *)name);
    if (num != NULL) {
        *num_out = *num;
        return true;
    }
    return false;
}

static inline reg_id_t
sysparam_reg(uint argnum)
{
#ifdef X64
    switch (argnum) {
    case 0: return REG_RDI;
    case 1: return REG_RSI;
    case 2: return REG_RDX;
    case 3: return REG_R10; /* rcx = retaddr for OP_syscall */
    case 4: return REG_R8;
    case 5: return REG_R9;
    default: ASSERT(false, "invalid syscall argnum");
    }
#else
    switch (argnum) {
    case 0: return REG_EBX;
    case 1: return REG_ECX;
    case 2: return REG_EDX;
    case 3: return REG_ESI;
    case 4: return REG_EDI;
    case 5: return REG_EBP; /* for vsyscall, value is instead on stack */
    default: 
        ASSERT(false, "invalid syscall argnum");
    }
#endif
    return REG_NULL;
}

/* Either sets arg->reg to DR_REG_NULL and sets arg->start_addr, or sets arg->reg
 * to non-DR_REG_NULL
 */
void
drsyscall_os_get_sysparam_location(cls_syscall_t *pt, uint argnum, drsys_arg_t *arg)
{
    reg_id_t reg = sysparam_reg(argnum);
    /* DR's syscall events don't tell us if this was vsyscall so we compare
     * values to find out
     */
    if (reg == REG_EBP && reg_get_value(reg, arg->mc) != pt->sysarg[argnum]) {
        /* must be vsyscall */
        ASSERT(!is_using_sysint(), "vsyscall incorrect assumption");
        arg->reg = DR_REG_NULL;
        arg->start_addr = (app_pc) arg->mc->xsp;
    } else {
        arg->reg = reg;
        arg->start_addr = NULL;
    }
}

drmf_status_t
drsys_syscall_type(drsys_sysnum_t sysnum, drsys_syscall_type_t *type OUT)
{
    *type = DRSYS_SYSCALL_TYPE_KERNEL;
    return DRMF_SUCCESS;
}

/***************************************************************************
 * PER-SYSCALL HANDLING
 */

static void
handle_clone(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint flags = (uint) pt->sysarg[0];

    /* PR 426162: pre-2.5.32-kernel, only 2 args.  Later glibc clone() has 3
     * optional args.  It blindly copies the 3 added args into registers, but
     * the kernel ignores them unless selected by appropriate flags.
     * We check the writes here to avoid races (xref PR 408540).
     */
    if (TEST(CLONE_PARENT_SETTID, flags)) {
        pid_t *ptid = (pid_t *) pt->sysarg[2];
        if (!report_sysarg(ii, 2, SYSARG_WRITE))
            return;
        if (ptid != NULL) {
            if (!report_memarg_type(ii, 2, SYSARG_WRITE, (app_pc) ptid, sizeof(*ptid),
                                    NULL, DRSYS_TYPE_INT, NULL))
                return;
        }
    }
    if (TEST(CLONE_SETTLS, flags)) {
        /* handle differences in type name */
#ifdef _LINUX_LDT_H
        typedef struct modify_ldt_ldt_s user_desc_t;
#else
        typedef struct user_desc user_desc_t;
#endif
        user_desc_t *tls = (user_desc_t *) pt->sysarg[3];
        if (!report_sysarg(ii, 3, SYSARG_READ))
            return;
        if (tls != NULL) {
            if (!report_memarg_type(ii, 3, SYSARG_READ, (app_pc) tls, sizeof(*tls), NULL,
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
    }
    if (TESTANY(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID, flags)) {
        /* Even though CLEARTID is not used until child exit, and the address
         * can be changed later with set_tid_address(), and at one time glibc
         * didn't support the param but the kernel did, the kernel will store
         * this address so we should complain.
         */
        pid_t *ptid = (pid_t *) pt->sysarg[4];
        if (!report_sysarg(ii, 4, SYSARG_WRITE))
            return;
        if (ptid != NULL) {
            if (!report_memarg_type(ii, 4, SYSARG_WRITE, (app_pc) ptid, sizeof(*ptid),
                                    NULL, DRSYS_TYPE_INT, NULL))
                return;
        }
    }
}

static ssize_t
ipmi_addr_len_adjust(struct ipmi_addr * addr)
{
    /* Some types have the final byte as padding and when initialized
     * field-by-field with no memset we complain about uninit on that byte.
     * FIXME: this is a general problem w/ syscall param checking!
     */
    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE ||
        addr->addr_type == IPMI_LAN_ADDR_TYPE)
        return -1;
    return 0;
}

#define IOCTL_BUF_ARGNUM 2

static void
handle_pre_ioctl(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint request = (uint) pt->sysarg[1];
    void *arg = (void *) pt->sysarg[IOCTL_BUF_ARGNUM];
    bool write = false;
    size_t sz = 0;
    const char *id = NULL;
    if (arg == NULL)
        return;
    /* easier to safe_read the whole thing at once 
     * N.B.: be careful about large structs that don't all have to be set
     * causing us to fail to read when really syscall would work fine
     */
    union ioctl_data data;
    /* shorter, easier-to-read code */
#define CHECK_DEF(ii, ptr, sz, id) do {                                       \
    if (!report_memarg_type(ii, IOCTL_BUF_ARGNUM, SYSARG_READ, (byte*)ptr,    \
                                sz, id, DRSYS_TYPE_STRUCT, NULL))             \
        return;                                                               \
} while (0)
#define CHECK_ADDR(ii, ptr, sz, id) do {                                       \
    if (!report_memarg_type(ii, IOCTL_BUF_ARGNUM, SYSARG_WRITE, (byte*)ptr,    \
                                sz, id, DRSYS_TYPE_STRUCT, NULL))              \
        return;                                                                \
} while (0)

    /* From "man ioctl_list" 
     * Note that we treat in-out as just read since we'll report and mark
     * as defined if undefined.
     */
    /* FIXME: "Some ioctls take a pointer to a structure which contains
     * additional pointers."  These are marked above with "FIXME: more".
     * They are listed in the man page but I'm too lazy to add them just now.
     */
    /* XXX: could use SYSINFO_SECONDARY_TABLE instead */
    switch (request) {

    // <include/asm-i386/socket.h>
    case FIOSETOWN: sz = sizeof(int); break;
    case SIOCSPGRP: sz = sizeof(int); break;
    case FIOGETOWN: sz = sizeof(int); write = true; break;
    case SIOCGPGRP: sz = sizeof(int); write = true; break;
    case SIOCATMARK: sz = sizeof(int); write = true; break;
    case SIOCGSTAMP: sz = sizeof(struct timeval); write = true; break;

    // <include/asm-i386/termios.h>
    case TCGETS: sz = sizeof(struct termios); write = true; break;
    case TCSETS: sz = sizeof(struct termios); break;
    case TCSETSW: sz = sizeof(struct termios ); break;
    case TCSETSF: sz = sizeof(struct termios); break;
    case TCGETA: sz = sizeof(struct termios); write = true; break;
    case TCSETA: sz = sizeof(struct termios); break;
    case TCSETAW: sz = sizeof(struct termios); break;
    case TCSETAF: sz = sizeof(struct termios); break;
    case TCSBRK: sz = 0; /* int */ break;
    case TCXONC: sz = 0; /* int */ break;
    case TCFLSH: sz = 0; /* int */ break;
    case TIOCEXCL: sz = 0; /* void */ break;
    case TIOCNXCL: sz = 0; /* void */ break;
    case TIOCSCTTY: sz = 0; /* int */ break;
    case TIOCGPGRP: sz = sizeof(pid_t); write = true; break;
    case TIOCSPGRP: sz = sizeof(pid_t); break;
    case TIOCOUTQ: sz = sizeof(int); write = true; break;
    case TIOCSTI: sz = sizeof(char); break;
    case TIOCGWINSZ: sz = sizeof(struct winsize); write = true; break;
    case TIOCSWINSZ: sz = sizeof(struct winsize); break;
    case TIOCMGET: sz = sizeof(int); write = true; break;
    case TIOCMBIS: sz = sizeof(int); break;
    case TIOCMBIC: sz = sizeof(int); break;
    case TIOCMSET: sz = sizeof(int); break;
    case TIOCGSOFTCAR: sz = sizeof(int); write = true; break;
    case TIOCSSOFTCAR: sz = sizeof(int); break;
    case TIOCINQ /*== FIONREAD*/: sz = sizeof(int); write = true; break;
    case TIOCLINUX: sz = sizeof(char); break; /* FIXME: more */
    case TIOCCONS: sz = 0; /* void */ break;
    case TIOCGSERIAL: sz = sizeof(struct serial_struct); write = true; break;
    case TIOCSSERIAL: sz = sizeof(struct serial_struct); break;
    case TIOCPKT: sz = sizeof(int); break;
    case FIONBIO: sz = sizeof(int); break;
    case TIOCNOTTY: sz = 0; /* void */ break;
    case TIOCSETD: sz = sizeof(int); break;
    case TIOCGETD: sz = sizeof(int); write = true; break;
    case TCSBRKP: sz = 0; /* int */ break;
#if 0 /* FIXME: struct not in my headers */
    case TIOCTTYGSTRUCT: sz = sizeof(struct tty_struct); write = true; break;
#endif
    case FIONCLEX: sz = 0; /* void */ break;
    case FIOCLEX: sz = 0; /* void */ break;
    case FIOASYNC: sz = sizeof(int); break;
    case TIOCSERCONFIG: sz = 0; /* void */ break;
    case TIOCSERGWILD: sz = sizeof(int); write = true; break;
    case TIOCSERSWILD: sz = sizeof(int); break;
    case TIOCGLCKTRMIOS: sz = sizeof(struct termios); write = true; break;
    case TIOCSLCKTRMIOS: sz = sizeof(struct termios); break;
#if 0 /* FIXME: struct not in my headers */
    case TIOCSERGSTRUCT: sz = sizeof(struct async_struct); write = true; break;
#endif
    case TIOCSERGETLSR: sz = sizeof(int); write = true; break;
    case TIOCSERGETMULTI: sz = sizeof(struct serial_multiport_struct); write = true; break;
    case TIOCSERSETMULTI: sz = sizeof(struct serial_multiport_struct); break;

    // <include/linux/ax25.h>
    case SIOCAX25GETUID: sz = sizeof(struct sockaddr_ax25); break;
    case SIOCAX25ADDUID: sz = sizeof(struct sockaddr_ax25); break;
    case SIOCAX25DELUID: sz = sizeof(struct sockaddr_ax25); break;
    case SIOCAX25NOUID: sz = sizeof(int); break;
#if 0 /* FIXME: define not in my headers */
    case SIOCAX25DIGCTL: sz = sizeof(int); break;
    case SIOCAX25GETPARMS: sz = sizeof(struct ax25_parms_struct); /* in-out */ break;
    case SIOCAX25SETPARMS: sz = sizeof(struct ax25_parms_struct); break;
#endif

    // <include/linux/cdk.h>
    case STL_BINTR: sz = 0; /* void */ break;
    case STL_BSTART: sz = 0; /* void */ break;
    case STL_BSTOP: sz = 0; /* void */ break;
    case STL_BRESET: sz = 0; /* void */ break;

    // <include/linux/cdrom.h>
    case CDROMPAUSE: sz = 0; /* void */ break;
    case CDROMRESUME: sz = 0; /* void */ break;
    case CDROMPLAYMSF: sz = sizeof(struct cdrom_msf); break;
    case CDROMPLAYTRKIND: sz = sizeof(struct cdrom_ti); break;
    case CDROMREADTOCHDR: sz = sizeof(struct cdrom_tochdr); write = true; break;
    case CDROMREADTOCENTRY: sz = sizeof(struct cdrom_tocentry); /* in-out */ break;
    case CDROMSTOP: sz = 0; /* void */ break;
    case CDROMSTART: sz = 0; /* void */ break;
    case CDROMEJECT: sz = 0; /* void */ break;
    case CDROMVOLCTRL: sz = sizeof(struct cdrom_volctrl); break;
    case CDROMSUBCHNL: sz = sizeof(struct cdrom_subchnl); /* in-out */ break;
    case CDROMREADMODE2: sz = sizeof(struct cdrom_msf); break; /* FIXME: more */
    case CDROMREADMODE1: sz = sizeof(struct cdrom_msf); break; /* FIXME: more */
    case CDROMREADAUDIO: sz = sizeof(struct cdrom_read_audio); break; /* FIXME: more */
    case CDROMEJECT_SW: sz = 0; /* int */ break;
    case CDROMMULTISESSION: sz = sizeof(struct cdrom_multisession); /* in-out */ break;
    case CDROM_GET_UPC: sz = sizeof(char[8]); write = true; break;
    case CDROMRESET: sz = 0; /* void */ break;
    case CDROMVOLREAD: sz = sizeof(struct cdrom_volctrl); write = true; break;
    case CDROMREADRAW: sz = sizeof(struct cdrom_msf); break; /* FIXME: more */
    case CDROMREADCOOKED: sz = sizeof(struct cdrom_msf); break; /* FIXME: more */
    case CDROMSEEK: sz = sizeof(struct cdrom_msf); break;

    // <include/linux/cm206.h>
#if 0 /* FIXME: define not in my headers */
    case CM206CTL_GET_STAT: sz = 0; /* int */ break;
    case CM206CTL_GET_LAST_STAT: sz = 0; /* int */ break;
#endif

    // <include/linux/cyclades.h>
    case CYGETMON: sz = sizeof(struct cyclades_monitor); write = true; break;
    case CYGETTHRESH: sz = sizeof(int); write = true; break;
    case CYSETTHRESH: sz = 0; /* int */ break;
    case CYGETDEFTHRESH: sz = sizeof(int); write = true; break;
    case CYSETDEFTHRESH: sz = 0; /* int */ break;
    case CYGETTIMEOUT: sz = sizeof(int); write = true; break;
    case CYSETTIMEOUT: sz = 0; /* int */ break;
    case CYGETDEFTIMEOUT: sz = sizeof(int); write = true; break;
    case CYSETDEFTIMEOUT: sz = 0; /* int */ break;

    // <include/linux/ext2_fs.h>
    case EXT2_IOC_GETFLAGS: sz = sizeof(int); write = true; break;
    case EXT2_IOC_SETFLAGS: sz = sizeof(int); break;
    case EXT2_IOC_GETVERSION: sz = sizeof(int); write = true; break;
    case EXT2_IOC_SETVERSION: sz = sizeof(int); break;

    // <include/linux/fd.h>
    case FDCLRPRM: sz = 0; /* void */ break;
    case FDSETPRM: sz = sizeof(struct floppy_struct); break;
    case FDDEFPRM: sz = sizeof(struct floppy_struct); break;
    case FDGETPRM: sz = sizeof(struct floppy_struct); write = true; break;
    case FDMSGON: sz = 0; /* void */ break;
    case FDMSGOFF: sz = 0; /* void */ break;
    case FDFMTBEG: sz = 0; /* void */ break;
    case FDFMTTRK: sz = sizeof(struct format_descr); break;
    case FDFMTEND: sz = 0; /* void */ break;
    case FDSETEMSGTRESH: sz = 0; /* int */ break;
    case FDFLUSH: sz = 0; /* void */ break;
    case FDSETMAXERRS: sz = sizeof(struct floppy_max_errors); break;
    case FDGETMAXERRS: sz = sizeof(struct floppy_max_errors); write = true; break;
    case FDGETDRVTYP: sz = sizeof(char[16]); write = true; break;
    case FDSETDRVPRM: sz = sizeof(struct floppy_drive_params); break;
    case FDGETDRVPRM: sz = sizeof(struct floppy_drive_params); write = true; break;
    case FDGETDRVSTAT: sz = sizeof(struct floppy_drive_struct); write = true; break;
    case FDPOLLDRVSTAT: sz = sizeof(struct floppy_drive_struct); write = true; break;
    case FDRESET: sz = 0; /* int */ break;
    case FDGETFDCSTAT: sz = sizeof(struct floppy_fdc_state); write = true; break;
    case FDWERRORCLR: sz = 0; /* void */ break;
    case FDWERRORGET: sz = sizeof(struct floppy_write_errors); write = true; break;
    case FDRAWCMD: sz = sizeof(struct floppy_raw_cmd); /* in-out */ break; /* FIXME: more */
    case FDTWADDLE: sz = 0; /* void */ break;

    // <include/linux/fs.h>
    case BLKROSET: sz = sizeof(int); break;
    case BLKROGET: sz = sizeof(int); write = true; break;
    case BLKRRPART: sz = 0; /* void */ break;
    case BLKGETSIZE: sz = sizeof(unsigned long); write = true; break;
    case BLKFLSBUF: sz = 0; /* void */ break;
    case BLKRASET: sz = 0; /* int */ break;
    case BLKRAGET: sz = sizeof(int); write = true; break;
    case FIBMAP: sz = sizeof(int); /* in-out */ break;
    case FIGETBSZ: sz = sizeof(int); write = true; break;

    // <include/linux/hdreg.h>
    case HDIO_GETGEO: sz = sizeof(struct hd_geometry); write = true; break;
    case HDIO_GET_UNMASKINTR: sz = sizeof(int); write = true; break;
    case HDIO_GET_MULTCOUNT: sz = sizeof(int); write = true; break;
    case HDIO_GET_IDENTITY: sz = sizeof(struct hd_driveid); write = true; break;
    case HDIO_GET_KEEPSETTINGS: sz = sizeof(int); write = true; break;
#if 0 /* FIXME: define not in my headers */
    case HDIO_GET_CHIPSET: sz = sizeof(int); write = true; break;
#endif
    case HDIO_GET_NOWERR: sz = sizeof(int); write = true; break;
    case HDIO_GET_DMA: sz = sizeof(int); write = true; break;
    case HDIO_DRIVE_CMD: sz = sizeof(int); /* in-out */ break;
    case HDIO_SET_MULTCOUNT: sz = 0; /* int */ break;
    case HDIO_SET_UNMASKINTR: sz = 0; /* int */ break;
    case HDIO_SET_KEEPSETTINGS: sz = 0; /* int */ break;
#if 0 /* FIXME: define not in my headers */
    case HDIO_SET_CHIPSET: sz = 0; /* int */ break;
#endif
    case HDIO_SET_NOWERR: sz = 0; /* int */ break;
    case HDIO_SET_DMA: sz = 0; /* int */ break;

#if 0 /* FIXME: having problems including header */
    // <include/linux/if_eql.h>
    case EQL_ENSLAVE: sz = sizeof(struct ifreq); /* in-out */ break; /* FIXME: more */
    case EQL_EMANCIPATE: sz = sizeof(struct ifreq); /* in-out */ break; /* FIXME: more */
    case EQL_GETSLAVECFG: sz = sizeof(struct ifreq); /* in-out */ break; /* FIXME: more */
    case EQL_SETSLAVECFG: sz = sizeof(struct ifreq); /* in-out */ break; /* FIXME: more */
    case EQL_GETMASTRCFG: sz = sizeof(struct ifreq); /* in-out */ break; /* FIXME: more */
    case EQL_SETMASTRCFG: sz = sizeof(struct ifreq); /* in-out */ break; /* FIXME: more */
#endif

    // <include/linux/if_plip.h>
    case SIOCDEVPLIP: sz = sizeof(struct ifreq); /* in-out */ break;

#if 0 /* FIXME: having problems including header */
    // <include/linux/if_ppp.h>
    case PPPIOCGFLAGS: sz = sizeof(int); write = true; break;
    case PPPIOCSFLAGS: sz = sizeof(int); break;
    case PPPIOCGASYNCMAP: sz = sizeof(int); write = true; break;
    case PPPIOCSASYNCMAP: sz = sizeof(int); break;
    case PPPIOCGUNIT: sz = sizeof(int); write = true; break;
    case PPPIOCSINPSIG: sz = sizeof(int); break;
    case PPPIOCSDEBUG: sz = sizeof(int); break;
    case PPPIOCGDEBUG: sz = sizeof(int); write = true; break;
    case PPPIOCGSTAT: sz = sizeof(struct ppp_stats); write = true; break;
    case PPPIOCGTIME: sz = sizeof(struct ppp_ddinfo); write = true; break;
    case PPPIOCGXASYNCMAP: sz = sizeof(struct { int [8]; }); write = true; break;
    case PPPIOCSXASYNCMAP: sz = sizeof(struct { int [8]; }); break;
    case PPPIOCSMRU: sz = sizeof(int); break;
    case PPPIOCRASYNCMAP: sz = sizeof(int); break;
    case PPPIOCSMAXCID: sz = sizeof(int); break;
#endif

#if 0 /* FIXME: identical to ax25 1st 3 */
    // <include/linux/ipx.h>
    case SIOCAIPXITFCRT: sz = sizeof(char); break;
    case SIOCAIPXPRISLT: sz = sizeof(char); break;
    case SIOCIPXCFGDATA: sz = sizeof(struct ipx_config_data); write = true; break;
#endif

    // <include/linux/kd.h>
    case GIO_FONT: sz = sizeof(char[8192]); write = true; break;
    case PIO_FONT: sz = sizeof(char[8192]); break;
#if 0 /* FIXME: struct not in my defines */
    case GIO_FONTX: sz = sizeof(struct console_font_desc); /* in-out */ break; /* FIXME: more */
    case PIO_FONTX: sz = sizeof(struct console_font_desc); break; /* FIXME: more */
#endif
    case GIO_CMAP: sz = sizeof(char[48]); write = true; break;
    case PIO_CMAP: sz = 0; /* const struct { char [48]; } */ break;
    case KIOCSOUND: sz = 0; /* int */ break;
    case KDMKTONE: sz = 0; /* int */ break;
    case KDGETLED: sz = sizeof(char); write = true; break;
    case KDSETLED: sz = 0; /* int */ break;
    case KDGKBTYPE: sz = sizeof(char); write = true; break;
    case KDADDIO: sz = 0; /* int */ break; /* FIXME: more */
    case KDDELIO: sz = 0; /* int */ break; /* FIXME: more */
    case KDENABIO: sz = 0; /* void */ break; /* FIXME: more */
    case KDDISABIO: sz = 0; /* void */ break; /* FIXME: more */
    case KDSETMODE: sz = 0; /* int */ break;
    case KDGETMODE: sz = sizeof(int); write = true; break;
    case KDMAPDISP: sz = 0; /* void */ break; /* FIXME: more */
    case KDUNMAPDISP: sz = 0; /* void */ break; /* FIXME: more */
    case GIO_SCRNMAP: sz = sizeof(char[E_TABSZ]); write = true; break;
    case PIO_SCRNMAP: sz = sizeof(char[E_TABSZ]); break;
    case GIO_UNISCRNMAP: sz = sizeof(short[E_TABSZ]); write = true; break;
    case PIO_UNISCRNMAP: sz = sizeof(short[E_TABSZ]); break;
    case GIO_UNIMAP: sz = sizeof(struct unimapdesc); /* in-out */ break; /* FIXME: more */
    case PIO_UNIMAP: sz = sizeof(struct unimapdesc); break; /* FIXME: more */
    case PIO_UNIMAPCLR: sz = sizeof(struct unimapinit); break;
    case KDGKBMODE: sz = sizeof(int); write = true; break;
    case KDSKBMODE: sz = 0; /* int */ break;
    case KDGKBMETA: sz = sizeof(int); write = true; break;
    case KDSKBMETA: sz = 0; /* int */ break;
    case KDGKBLED: sz = sizeof(int); write = true; break;
    case KDSKBLED: sz = 0; /* int */ break;
    case KDGKBENT: sz = sizeof(struct kbentry); /* in-out */ break;
    case KDSKBENT: sz = sizeof(struct kbentry); break;
    case KDGKBSENT: sz = sizeof(struct kbsentry); /* in-out */ break;
    case KDSKBSENT: sz = sizeof(struct kbsentry); break;
    case KDGKBDIACR: sz = sizeof(struct kbdiacrs); write = true; break;
    case KDSKBDIACR: sz = sizeof(struct kbdiacrs); break;
    case KDGETKEYCODE: sz = sizeof(struct kbkeycode); /* in-out */ break;
    case KDSETKEYCODE: sz = sizeof(struct kbkeycode); break;
    case KDSIGACCEPT: sz = 0; /* int */ break;

    // <include/linux/lp.h>
    case LPCHAR: sz = 0; /* int */ break;
    case LPTIME: sz = 0; /* int */ break;
    case LPABORT: sz = 0; /* int */ break;
    case LPSETIRQ: sz = 0; /* int */ break;
    case LPGETIRQ: sz = sizeof(int); write = true; break;
    case LPWAIT: sz = 0; /* int */ break;
    case LPCAREFUL: sz = 0; /* int */ break;
    case LPABORTOPEN: sz = 0; /* int */ break;
    case LPGETSTATUS: sz = sizeof(int); write = true; break;
    case LPRESET: sz = 0; /* void */ break;
#if 0 /* FIXME: define not in my headers */
    case LPGETSTATS: sz = sizeof(struct lp_stats); write = true; break;
#endif

#if 0 /* FIXME: identical to ax25 1st 2 */
    // <include/linux/mroute.h>
    case SIOCGETVIFCNT: sz = sizeof(struct sioc_vif_req); /* in-out */ break;
    case SIOCGETSGCNT: sz = sizeof(struct sioc_sg_req); /* in-out */ break;
#endif

    // <include/linux/mtio.h>
    case MTIOCTOP: sz = sizeof(struct mtop); break;
    case MTIOCGET: sz = sizeof(struct mtget); write = true; break;
    case MTIOCPOS: sz = sizeof(struct mtpos); write = true; break;
    case MTIOCGETCONFIG: sz = sizeof(struct mtconfiginfo); write = true; break;
    case MTIOCSETCONFIG: sz = sizeof(struct mtconfiginfo); break;

#if 0 /* FIXME: define not in my headers */
    // <include/linux/netrom.h>
    case SIOCNRGETPARMS: sz = sizeof(struct nr_parms_struct); /* in-out */ break;
    case SIOCNRSETPARMS: sz = sizeof(struct nr_parms_struct); break;
    case SIOCNRDECOBS: sz = 0; /* void */ break;
    case SIOCNRRTCTL: sz = sizeof(int); break;
#endif

#if 0 /* FIXME: define not in my headers */
    // <include/linux/sbpcd.h>
    case DDIOCSDBG: sz = sizeof(int); break;
    case CDROMAUDIOBUFSIZ: sz = 0; /* int */ break;
#endif

#if 0 /* FIXME: define not in my headers */
    // <include/linux/scc.h>
    case TIOCSCCINI: sz = 0; /* void */ break;
    case TIOCCHANINI: sz = sizeof(struct scc_modem); break;
    case TIOCGKISS: sz = sizeof(struct ioctl_command); /* in-out */ break;
    case TIOCSKISS: sz = sizeof(struct ioctl_command); break;
    case TIOCSCCSTAT: sz = sizeof(struct scc_stat); write = true; break;
#endif

#if 0 /* FIXME: define not in my headers */
    // <include/linux/scsi.h>
    case SCSI_IOCTL_GET_IDLUN: sz = sizeof(struct { int [2]; }); write = true; break;
    case SCSI_IOCTL_TAGGED_ENABLE: sz = 0; /* void */ break;
    case SCSI_IOCTL_TAGGED_DISABLE: sz = 0; /* void */ break;
    case SCSI_IOCTL_PROBE_HOST: sz = sizeof(int); break; /* FIXME: more */
#endif

    // <include/linux/smb_fs.h>
    case SMB_IOC_GETMOUNTUID: sz = sizeof(uid_t); write = true; break;

    // <include/linux/sockios.h>
    case SIOCADDRT: sz = sizeof(struct rtentry); break; /* FIXME: more */
    case SIOCDELRT: sz = sizeof(struct rtentry); break; /* FIXME: more */
    case SIOCGIFNAME: sz = 0; /* char [] */ break;
    case SIOCSIFLINK: sz = 0; /* void */ break;
    case SIOCGIFCONF: {
        struct ifconf input;
        CHECK_DEF(ii, arg, sizeof(struct ifconf), NULL);
        if (safe_read((void *)arg, sizeof(input), &input))
            CHECK_ADDR(ii, input.ifc_buf, input.ifc_len, "SIOCGIFCONF ifc_buf");
        return;
    }
    case SIOCGIFFLAGS: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCSIFFLAGS: sz = sizeof(struct ifreq); break;
    case SIOCGIFADDR: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCSIFADDR: sz = sizeof(struct ifreq); break;
    case SIOCGIFDSTADDR: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCSIFDSTADDR: sz = sizeof(struct ifreq); break;
    case SIOCGIFBRDADDR: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCSIFBRDADDR: sz = sizeof(struct ifreq); break;
    case SIOCGIFNETMASK: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCSIFNETMASK: sz = sizeof(struct ifreq); break;
    case SIOCGIFMETRIC: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCSIFMETRIC: sz = sizeof(struct ifreq); break;
    case SIOCGIFMEM: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCSIFMEM: sz = sizeof(struct ifreq); break;
    case SIOCGIFMTU: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCSIFMTU: sz = sizeof(struct ifreq); break;
#if 0 /* FIXME: define not in my headers */
    case OLD_SIOCGIFHWADDR: sz = sizeof(struct ifreq); /* in-out */ break;
#endif
    case SIOCSIFHWADDR: sz = sizeof(struct ifreq); break;     /* FIXME: more */
    case SIOCGIFENCAP: sz = sizeof(int); write = true; break;
    case SIOCSIFENCAP: sz = sizeof(int); break;
    case SIOCGIFHWADDR: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCGIFSLAVE: sz = 0; /* void */ break;
    case SIOCSIFSLAVE: sz = 0; /* void */ break;
    case SIOCADDMULTI: sz = sizeof(struct ifreq); break;
    case SIOCDELMULTI: sz = sizeof(struct ifreq); break;
#if 0 /* FIXME: define not in my headers */
    case SIOCADDRTOLD: sz = 0; /* void */ break;
    case SIOCDELRTOLD: sz = 0; /* void */ break;
#endif
    case SIOCDARP: sz = sizeof(struct arpreq); break;
    case SIOCGARP: sz = sizeof(struct arpreq); /* in-out */ break;
    case SIOCSARP: sz = sizeof(struct arpreq); break;
    case SIOCDRARP: sz = sizeof(struct arpreq); break;
    case SIOCGRARP: sz = sizeof(struct arpreq); /* in-out */ break;
    case SIOCSRARP: sz = sizeof(struct arpreq); break;
    case SIOCGIFMAP: sz = sizeof(struct ifreq); /* in-out */ break;
    case SIOCSIFMAP: sz = sizeof(struct ifreq); break;

    // <include/linux/soundcard.h>
    case SNDCTL_SEQ_RESET: sz = 0; /* void */ break;
    case SNDCTL_SEQ_SYNC: sz = 0; /* void */ break;
    case SNDCTL_SYNTH_INFO: sz = sizeof(struct synth_info); /* in-out */ break;
    case SNDCTL_SEQ_CTRLRATE: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_SEQ_GETOUTCOUNT: sz = sizeof(int); write = true; break;
    case SNDCTL_SEQ_GETINCOUNT: sz = sizeof(int); write = true; break;
    case SNDCTL_SEQ_PERCMODE: sz = 0; /* void */ break;
    case SNDCTL_FM_LOAD_INSTR: sz = sizeof(struct sbi_instrument); break;
    case SNDCTL_SEQ_TESTMIDI: sz = sizeof(int); break;
    case SNDCTL_SEQ_RESETSAMPLES: sz = sizeof(int); break;
    case SNDCTL_SEQ_NRSYNTHS: sz = sizeof(int); write = true; break;
    case SNDCTL_SEQ_NRMIDIS: sz = sizeof(int); write = true; break;
    case SNDCTL_MIDI_INFO: sz = sizeof(struct midi_info); /* in-out */ break;
    case SNDCTL_SEQ_THRESHOLD: sz = sizeof(int); break;
    case SNDCTL_SYNTH_MEMAVL: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_FM_4OP_ENABLE: sz = sizeof(int); break;
#if 0 /* FIXME: define not in my headers */
    case SNDCTL_PMGR_ACCESS: sz = sizeof(struct patmgr_info); /* in-out */ break;
#endif
    case SNDCTL_SEQ_PANIC: sz = 0; /* void */ break;
    case SNDCTL_SEQ_OUTOFBAND: sz = sizeof(struct seq_event_rec); break;
    case SNDCTL_TMR_TIMEBASE: sz = sizeof(int); /* in-out */ break;
#if 0 /* FIXME: identical to TCSETS and subsequent 2 */
    case SNDCTL_TMR_START: sz = 0; /* void */ break;
    case SNDCTL_TMR_STOP: sz = 0; /* void */ break;
    case SNDCTL_TMR_CONTINUE: sz = 0; /* void */ break;
#endif
    case SNDCTL_TMR_TEMPO: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_TMR_SOURCE: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_TMR_METRONOME: sz = sizeof(int); break;
    case SNDCTL_TMR_SELECT: sz = sizeof(int); /* in-out */ break;
#if 0 /* FIXME: define not in my headers */
    case SNDCTL_PMGR_IFACE: sz = sizeof(struct patmgr_info); /* in-out */ break;
#endif
    case SNDCTL_MIDI_PRETIME: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_MIDI_MPUMODE: sz = sizeof(int); break;
#if 0 /* FIXME: struct not in my headers */
    case SNDCTL_MIDI_MPUCMD: sz = sizeof(struct mpu_command_rec); /* in-out */ break;
#endif
    case SNDCTL_DSP_RESET: sz = 0; /* void */ break;
    case SNDCTL_DSP_SYNC: sz = 0; /* void */ break;
    case SNDCTL_DSP_SPEED: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_DSP_STEREO: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_DSP_GETBLKSIZE: sz = sizeof(int); /* in-out */ break;
    case SOUND_PCM_WRITE_CHANNELS: sz = sizeof(int); /* in-out */ break;
    case SOUND_PCM_WRITE_FILTER: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_DSP_POST: sz = 0; /* void */ break;
    case SNDCTL_DSP_SUBDIVIDE: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_DSP_SETFRAGMENT: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_DSP_GETFMTS: sz = sizeof(int); write = true; break;
    case SNDCTL_DSP_SETFMT: sz = sizeof(int); /* in-out */ break;
    case SNDCTL_DSP_GETOSPACE: sz = sizeof(struct audio_buf_info); write = true; break;
    case SNDCTL_DSP_GETISPACE: sz = sizeof(struct audio_buf_info); write = true; break;
    case SNDCTL_DSP_NONBLOCK: sz = 0; /* void */ break;
    case SOUND_PCM_READ_RATE: sz = sizeof(int); write = true; break;
    case SOUND_PCM_READ_CHANNELS: sz = sizeof(int); write = true; break;
    case SOUND_PCM_READ_BITS: sz = sizeof(int); write = true; break;
    case SOUND_PCM_READ_FILTER: sz = sizeof(int); write = true; break;
    case SNDCTL_COPR_RESET: sz = 0; /* void */ break;
    case SNDCTL_COPR_LOAD: sz = sizeof(struct copr_buffer); break;
    case SNDCTL_COPR_RDATA: sz = sizeof(struct copr_debug_buf); /* in-out */ break;
    case SNDCTL_COPR_RCODE: sz = sizeof(struct copr_debug_buf); /* in-out */ break;
    case SNDCTL_COPR_WDATA: sz = sizeof(struct copr_debug_buf); break;
    case SNDCTL_COPR_WCODE: sz = sizeof(struct copr_debug_buf); break;
    case SNDCTL_COPR_RUN: sz = sizeof(struct copr_debug_buf); /* in-out */ break;
    case SNDCTL_COPR_HALT: sz = sizeof(struct copr_debug_buf); /* in-out */ break;
    case SNDCTL_COPR_SENDMSG: sz = sizeof(struct copr_msg); break;
    case SNDCTL_COPR_RCVMSG: sz = sizeof(struct copr_msg); write = true; break;
    case SOUND_MIXER_READ_VOLUME: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_BASS: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_TREBLE: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_SYNTH: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_PCM: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_SPEAKER: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_LINE: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_MIC: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_CD: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_IMIX: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_ALTPCM: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_RECLEV: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_IGAIN: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_OGAIN: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_LINE1: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_LINE2: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_LINE3: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_MUTE: sz = sizeof(int); write = true; break;
#if 0 /* FIXME: identical to SOUND_MIXER_READ_MUTE */
    case SOUND_MIXER_READ_ENHANCE: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_LOUD: sz = sizeof(int); write = true; break;
#endif
    case SOUND_MIXER_READ_RECSRC: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_DEVMASK: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_RECMASK: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_STEREODEVS: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_READ_CAPS: sz = sizeof(int); write = true; break;
    case SOUND_MIXER_WRITE_VOLUME: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_BASS: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_TREBLE: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_SYNTH: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_PCM: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_SPEAKER: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_LINE: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_MIC: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_CD: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_IMIX: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_ALTPCM: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_RECLEV: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_IGAIN: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_OGAIN: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_LINE1: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_LINE2: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_LINE3: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_MUTE: sz = sizeof(int); /* in-out */ break;
#if 0 /* FIXME: identical to SOUND_MIXER_WRITE_MUTE */
    case SOUND_MIXER_WRITE_ENHANCE: sz = sizeof(int); /* in-out */ break;
    case SOUND_MIXER_WRITE_LOUD: sz = sizeof(int); /* in-out */ break;
#endif
    case SOUND_MIXER_WRITE_RECSRC: sz = sizeof(int); /* in-out */ break;

#if 0 /* FIXME: define not in my headers */
    // <include/linux/umsdos_fs.h>
    case UMSDOS_READDIR_DOS: sz = sizeof(struct umsdos_ioctl); /* in-out */ break;
    case UMSDOS_UNLINK_DOS: sz = sizeof(struct umsdos_ioctl); break;
    case UMSDOS_RMDIR_DOS: sz = sizeof(struct umsdos_ioctl); break;
    case UMSDOS_STAT_DOS: sz = sizeof(struct umsdos_ioctl); /* in-out */ break;
    case UMSDOS_CREAT_EMD: sz = sizeof(struct umsdos_ioctl); break;
    case UMSDOS_UNLINK_EMD: sz = sizeof(struct umsdos_ioctl); break;
    case UMSDOS_READDIR_EMD: sz = sizeof(struct umsdos_ioctl); /* in-out */ break;
    case UMSDOS_GETVERSION: sz = sizeof(struct umsdos_ioctl); write = true; break;
    case UMSDOS_INIT_EMD: sz = 0; /* void */ break;
    case UMSDOS_DOS_SETUP: sz = sizeof(struct umsdos_ioctl); break;
    case UMSDOS_RENAME_DOS: sz = sizeof(struct umsdos_ioctl); break;
#endif

    // <include/linux/vt.h>
    case VT_OPENQRY: sz = sizeof(int); write = true; break;
    case VT_GETMODE: sz = sizeof(struct vt_mode); write = true; break;
    case VT_SETMODE: sz = sizeof(struct vt_mode); break;
    case VT_GETSTATE: sz = sizeof(struct vt_stat); write = true; break;
    case VT_SENDSIG: sz = 0; /* void */ break;
    case VT_RELDISP: sz = 0; /* int */ break;
    case VT_ACTIVATE: sz = 0; /* int */ break;
    case VT_WAITACTIVE: sz = 0; /* int */ break;
    case VT_DISALLOCATE: sz = 0; /* int */ break;
    case VT_RESIZE: sz = sizeof(struct vt_sizes); break;
    case VT_RESIZEX: sz = sizeof(struct vt_consize); break;

    /* include <linux/ipmi.h> PR 531644 */
    case IPMICTL_SEND_COMMAND:
        CHECK_DEF(ii, arg, sizeof(struct ipmi_req), NULL); /*no id == arg itself*/
        if (safe_read((void *)arg, sizeof(struct ipmi_req), &data.req)) {
            CHECK_DEF(ii, data.req.addr, data.req.addr_len +
                      ipmi_addr_len_adjust((struct ipmi_addr *)data.req.addr),
                      "IPMICTL_SEND_COMMAND addr");
            CHECK_DEF(ii, data.req.msg.data, data.req.msg.data_len,
                      "IPMICTL_SEND_COMMAND msg.data");
        }
        return;
    case IPMICTL_SEND_COMMAND_SETTIME:
        CHECK_DEF(ii, arg, sizeof(struct ipmi_req_settime), NULL); /*no id == arg*/
        if (safe_read((void *)arg, sizeof(struct ipmi_req_settime), &data.reqs)) {
            CHECK_DEF(ii, data.reqs.req.addr, data.reqs.req.addr_len +
                      ipmi_addr_len_adjust((struct ipmi_addr *)data.reqs.req.addr),
                      "IPMICTL_SEND_COMMAND_SETTIME addr");
            CHECK_DEF(ii, data.reqs.req.msg.data, data.reqs.req.msg.data_len,
                      "IPMICTL_SEND_COMMAND_SETTIME msg.data");
        }
        return;
    case IPMICTL_RECEIVE_MSG:
    case IPMICTL_RECEIVE_MSG_TRUNC: {
        struct ipmi_recv *recv = (struct ipmi_recv *) arg;
        CHECK_ADDR(ii, arg, sizeof(struct ipmi_recv), NULL); /*no id == arg*/
        /* some fields are purely OUT so we must check the IN ones separately */
        CHECK_DEF(ii, &recv->addr, sizeof(recv->addr), NULL);
        CHECK_DEF(ii, &recv->addr_len, sizeof(recv->addr_len), NULL);
        CHECK_DEF(ii, &recv->msg.data, sizeof(recv->msg.data), NULL);
        CHECK_DEF(ii, &recv->msg.data_len, sizeof(recv->msg.data_len), NULL);
        if (safe_read((void *)arg, sizeof(struct ipmi_recv), &data.recv)) {
            CHECK_ADDR(ii, data.recv.addr, data.recv.addr_len,
                      "IPMICTL_RECEIVE_MSG* addr");
            CHECK_ADDR(ii, data.recv.msg.data, data.recv.msg.data_len,
                      "IPMICTL_RECEIVE_MSG* msg.data");
        }
        return;
    }
    case IPMICTL_REGISTER_FOR_CMD: sz = sizeof(struct ipmi_cmdspec); break;
    case IPMICTL_UNREGISTER_FOR_CMD: sz = sizeof(struct ipmi_cmdspec); break;
    case IPMICTL_REGISTER_FOR_CMD_CHANS: sz = sizeof(struct ipmi_cmdspec_chans); break;
    case IPMICTL_UNREGISTER_FOR_CMD_CHANS: sz = sizeof(struct ipmi_cmdspec_chans); break;
    case IPMICTL_SET_GETS_EVENTS_CMD: sz = sizeof(int); break;
    case IPMICTL_SET_MY_CHANNEL_ADDRESS_CMD:
        sz = sizeof(struct ipmi_channel_lun_address_set); break;
    case IPMICTL_GET_MY_CHANNEL_ADDRESS_CMD:
        sz = sizeof(struct ipmi_channel_lun_address_set); write = true; break;
    case IPMICTL_SET_MY_CHANNEL_LUN_CMD:
        sz = sizeof(struct ipmi_channel_lun_address_set); break;
    case IPMICTL_GET_MY_CHANNEL_LUN_CMD:
        sz = sizeof(struct ipmi_channel_lun_address_set); write = true; break;
    case IPMICTL_SET_MY_ADDRESS_CMD: sz = sizeof(uint); break;
    case IPMICTL_GET_MY_ADDRESS_CMD: sz = sizeof(uint); write = true; break;
    case IPMICTL_SET_MY_LUN_CMD: sz = sizeof(uint); break;
    case IPMICTL_GET_MY_LUN_CMD: sz = sizeof(uint); write = true; break;
    case IPMICTL_SET_TIMING_PARMS_CMD:
        sz = sizeof(struct ipmi_timing_parms); break;
    case IPMICTL_GET_TIMING_PARMS_CMD:
        sz = sizeof(struct ipmi_timing_parms); write = true; break;
    case IPMICTL_GET_MAINTENANCE_MODE_CMD: sz = sizeof(int); write = true; break;
    case IPMICTL_SET_MAINTENANCE_MODE_CMD: sz = sizeof(int); break;

    default: 
#if 0/* FIXME PR 494716: disabling since wasting a lot of log space */
        /* FIXME PR 494716: this and the sycall_vmkuw.c warning are
         * both erroneous b/c they don't consider the other's code
         */
        LOG(1, "WARNING: unknown ioctl request %d\n", request); 
        IF_DEBUG(report_callstack(drcontext);)
#endif
        break;
    }

    if (sz > 0) {
        /* FIXME: should we report the ioctl # a la PR 525269?  Hard
         * to fit that into the string literal model of syscall_aux
         * info.  For ioctls vs each other, the rest of the callstack
         * should distinguish (though that's also true for SYS_ipc, etc.),
         * and for multi-arg we can provide custom strings.
         */
        if (!report_memarg_type(ii, IOCTL_BUF_ARGNUM, write ? SYSARG_WRITE : SYSARG_READ,
                                (app_pc) arg, sz, id, DRSYS_TYPE_STRUCT, NULL))
            return;
    }
#undef CHECK_DEF
#undef CHECK_ADDR
}

static void
handle_post_ioctl(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint request = (uint) pt->sysarg[1];
    void *arg = (ptr_uint_t *) pt->sysarg[2];
    ptr_int_t result = dr_syscall_get_result(drcontext);
    if (arg == NULL)
        return;
    if (result < 0)
        return;
    /* easier to safe_read the whole thing at once 
     * to save space we could use a different union that only has the
     * structs needed in post: though currently it's the same set,
     * and most likely the larger ones will be in post.
     */
    union ioctl_data data;
    /* shorter, easier-to-read code */
#define MARK_WRITE(ii, ptr, sz, id) do {                                       \
    if (!report_memarg_type(ii, IOCTL_BUF_ARGNUM, SYSARG_WRITE, (byte*)ptr,    \
                                sz, id, DRSYS_TYPE_STRUCT, NULL))              \
        return;                                                                \
} while (0)
    switch (request) {
    case SIOCGIFCONF: {
        struct ifconf output;
        if (safe_read((void *)arg, sizeof(output), &output))
            MARK_WRITE(ii, output.ifc_buf, output.ifc_len, "SIOCGIFCONF ifc_buf");
        return;
    }
    case IPMICTL_RECEIVE_MSG:
    case IPMICTL_RECEIVE_MSG_TRUNC:
        if (safe_read((void *)arg, sizeof(struct ipmi_recv), &data.recv)) {
            MARK_WRITE(ii, data.recv.addr, data.recv.addr_len,
                       "IPMICTL_RECEIVE_MSG* addr");
            MARK_WRITE(ii, data.recv.msg.data, data.recv.msg.data_len,
                       "IPMICTL_RECEIVE_MSG* msg.data");
        }
        return;
    }
#undef MARK_WRITE
}

/* struct sockaddr is large but the meaningful portions vary by family */
/* it's up to the caller to check the whole struct for addressability on writes */
static void
check_sockaddr(cls_syscall_t *pt, sysarg_iter_info_t *ii,
               byte *ptr, socklen_t socklen, int ordinal, uint arg_flags, const char *id)
{
    struct sockaddr *sa = (struct sockaddr *) ptr;
    sa_family_t family;

    /* If not enough space kernel writes space needed, so we need to adjust
     * to the passed-in size by storing it in pre-syscall.
     */
    if (pt->first_iter && ii->arg->pre && TEST(SYSARG_WRITE, arg_flags)) {
        store_extra_info(pt, EXTRA_INFO_SOCKADDR, socklen);
    } else if (TEST(SYSARG_WRITE, arg_flags)) {
        socklen_t pre_len = (socklen_t) release_extra_info(pt, EXTRA_INFO_SOCKADDR);
        if (socklen > pre_len)
            socklen = pre_len;
    }    

    if (ii->arg->pre) {
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &sa->sa_family,
                                sizeof(sa->sa_family), id, DRSYS_TYPE_INT, NULL))
            return;
    }
    if (!safe_read(&sa->sa_family, sizeof(family), &family))
        return;
    /* FIXME: do not check beyond socklen */
    switch (family) {
    case AF_UNIX: {
        struct sockaddr_un *sun = (struct sockaddr_un *) sa;
        size_t len = safe_strnlen(sun->sun_path, (socklen < sizeof(*sun)) ?
                                  socklen : sizeof(*sun)) + 1;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) sun->sun_path,
                                len, id, DRSYS_TYPE_CARRAY, NULL))
            return;
        break;
    }
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &sin->sin_port,
                                sizeof(sin->sin_port), id, DRSYS_TYPE_INT, NULL))
            return;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &sin->sin_addr,
                                sizeof(sin->sin_addr), id, DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &sin6->sin6_port,
                                sizeof(sin6->sin6_port), id, DRSYS_TYPE_INT, NULL))
            return;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &sin6->sin6_flowinfo,
                                sizeof(sin6->sin6_flowinfo), id, DRSYS_TYPE_INT, NULL))
            return;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &sin6->sin6_addr,
                                sizeof(sin6->sin6_addr), id, DRSYS_TYPE_STRUCT, NULL))
            return;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &sin6->sin6_scope_id,
                                sizeof(sin6->sin6_scope_id), id, DRSYS_TYPE_INT, NULL))
            return;
        break;
    }
    case AF_NETLINK: {
        struct sockaddr_nl *snl = (struct sockaddr_nl *) sa;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &snl->nl_pad,
                                sizeof(snl->nl_pad), id, DRSYS_TYPE_INT, NULL))
            return;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &snl->nl_pid,
                                sizeof(snl->nl_pid), id, DRSYS_TYPE_INT, NULL))
            return;
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &snl->nl_groups,
                                sizeof(snl->nl_groups), id, DRSYS_TYPE_INT, NULL))
            return;
        break;
    }
    default:
        ELOGF(0, f_global, "WARNING: unknown sockaddr type %d\n", family); 
        IF_DEBUG(report_callstack(ii->arg->drcontext, ii->arg->mc);)
        break;
    }
}

/* scatter-gather buffer vector handling.
 * ignores bytes_read unless arg_flags == SYSARG_WRITE.
 */
static void
check_iov(cls_syscall_t *pt, sysarg_iter_info_t *ii,
          struct iovec *iov, size_t iov_len, size_t bytes_read,
          int ordinal, uint arg_flags, const char *id)
{
    uint i;
    size_t bytes_so_far = 0;
    bool done = false;
    struct iovec iov_copy;
    if (iov == NULL || iov_len == 0)
        return;
    if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc)iov,
                            iov_len * sizeof(struct iovec), id, DRSYS_TYPE_STRUCT, NULL))
        return;
    for (i = 0; i < iov_len; i++) {
        if (safe_read(&iov[i], sizeof(iov_copy), &iov_copy)) {
            if (arg_flags == SYSARG_WRITE) {
                if (bytes_so_far + iov_copy.iov_len > bytes_read) {
                    done = true;
                    iov_copy.iov_len = (bytes_read - bytes_so_far);
                }
                bytes_so_far += iov_copy.iov_len;
            }
            LOG(3, "check_iov: iov entry %d, buf="PFX", len="PIFX"\n",
                i, iov_copy.iov_base, iov_copy.iov_len);
            if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc)iov_copy.iov_base,
                                    iov_copy.iov_len, id, DRSYS_TYPE_STRUCT, NULL))
                return;
            if (done)
                break;
        }
    }
}

/* checks entire struct so caller need do nothing */
static void
check_msghdr(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii,
             byte *ptr, size_t len, int ordinal, uint arg_flags)
{
    bool sendmsg = TEST(SYSARG_READ, arg_flags); /* else, recvmsg */
    struct msghdr *msg = (struct msghdr *) ptr;
    byte *ptr1, *ptr2;
    size_t val_socklen;
    if (ii->arg->pre) {
        /* pre-syscall */
        size_t len = sendmsg ? sizeof(struct msghdr) :
            /* msg_flags is an out param */
            offsetof(struct msghdr, msg_flags);
        LOG(3, "\tmsg="PFX", name="PFX", iov="PFX", control="PFX"\n",
            msg, msg->msg_name, msg->msg_iov, msg->msg_control);/*unsafe reads*/
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc)msg, len,
                                sendmsg ? "sendmsg msg" : "recvmsg msg",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        if (!sendmsg) {
            if (!report_memarg_type(ii, ordinal, arg_flags,
                                    (app_pc)&msg->msg_flags, sizeof(msg->msg_flags),
                                    "recvmsg msg_flags", DRSYS_TYPE_INT, NULL))
                return;
        }
        if (safe_read(&msg->msg_name, sizeof(msg->msg_name), &ptr2) &&
            safe_read(&msg->msg_namelen, sizeof(msg->msg_namelen), &val_socklen) &&
            ptr2 != NULL) {
            if (sendmsg) {
                check_sockaddr(pt, ii, ptr2, val_socklen, ordinal, SYSARG_READ,
                               "sendmsg addr");
                if (ii->abort)
                    return;
            } else {
                if (!report_memarg_type(ii, ordinal, arg_flags, ptr2, val_socklen,
                                        "recvmsg addr", DRSYS_TYPE_STRUCT, NULL))
                return;
            }
        }
        if (safe_read(&msg->msg_iov, sizeof(msg->msg_iov), &ptr1) &&
            safe_read(&msg->msg_iovlen, sizeof(msg->msg_iovlen), &len) &&
            ptr1 != NULL) {
            check_iov(pt, ii, (struct iovec *) ptr1, len, 0, ordinal, arg_flags,
                      sendmsg ? "sendmsg iov" : "recvmsg iov");
            if (ii->abort)
                return;
        }
        if (safe_read(&msg->msg_control, sizeof(msg->msg_control), &ptr2) &&
            safe_read(&msg->msg_controllen, sizeof(msg->msg_controllen),
                      &val_socklen)) {
            if (pt->first_iter) {
                store_extra_info(pt, EXTRA_INFO_MSG_CONTROL, (ptr_int_t) ptr2);
                store_extra_info(pt, EXTRA_INFO_MSG_CONTROLLEN, val_socklen);
            }
            if (ptr2 != NULL) {
                if (!report_memarg_type(ii, ordinal, arg_flags, ptr2, val_socklen,
                                        sendmsg ? "sendmsg msg_control" :
                                        "recvmsg msg_control", DRSYS_TYPE_STRUCT, NULL))
                    return;
            }
        } else if (pt->first_iter) {
            store_extra_info(pt, EXTRA_INFO_MSG_CONTROL, 0);
            store_extra_info(pt, EXTRA_INFO_MSG_CONTROLLEN, 0);
        }
    } else {
        /* post-syscall: thus must be recvmsg */
        ptr_int_t result = dr_syscall_get_result(drcontext);
        struct iovec *iov;
        size_t len;
        /* we saved this in pre-syscall */
        void *pre_control = (void *) release_extra_info(pt, EXTRA_INFO_MSG_CONTROL);
        size_t pre_controllen = (size_t) release_extra_info(pt, EXTRA_INFO_MSG_CONTROLLEN);
        ASSERT(!sendmsg, "logic error"); /* currently axiomatic but just in case */
        if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc)&msg->msg_flags,
                                sizeof(msg->msg_flags), "recvmsg msg_flags",
                                DRSYS_TYPE_INT, NULL))
            return;
        if (safe_read(&msg->msg_iov, sizeof(msg->msg_iov), &iov) &&
            safe_read(&msg->msg_iovlen, sizeof(msg->msg_iovlen), &len) &&
            iov != NULL) {
            check_iov(pt, ii, iov, len, result, ordinal, arg_flags, "recvmsg iov");
            if (ii->abort)
                return;
        }
        if (safe_read(&msg->msg_name, sizeof(msg->msg_name), &ptr2) &&
            safe_read(&msg->msg_namelen, sizeof(msg->msg_namelen), &val_socklen) &&
            ptr2 != NULL) {
            check_sockaddr(pt, ii, (app_pc)ptr2, val_socklen, ordinal, arg_flags,
                           "recvmsg addr");
            if (ii->abort)
                return;
        }
        /* re-read to see size returned by kernel */
        if (safe_read(&msg->msg_controllen, sizeof(msg->msg_controllen), &val_socklen)) {
            /* Not sure what kernel does on truncation so being safe */
            size_t len = (val_socklen <= pre_controllen) ? val_socklen : pre_controllen;
            if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc)&msg->msg_controllen,
                                    sizeof(msg->msg_controllen), "recvmsg msg_controllen",
                                    DRSYS_TYPE_INT, NULL))
                return;
            if (pre_control != NULL && len > 0) {
                if (!report_memarg_type(ii, ordinal, arg_flags,
                                        (app_pc)pt->sysarg[3]/*msg_control*/, len,
                                        "recvmsg msg_control", DRSYS_TYPE_STRUCT, NULL))
                    return;
            } else
                ASSERT(len == 0, "msg w/ no data can't have non-zero len!");
        }
    }
}

#ifndef X64 /* XXX i#1013: for mixed-mode we'll need to indirect SYS_socketcall, etc. */
static void
handle_pre_socketcall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint request = (uint) pt->sysarg[0];
    /* The first sysparam is an array of args of varying length */
#   define SOCK_ARRAY_ARG 1
    ptr_uint_t *arg = (ptr_uint_t *) pt->sysarg[SOCK_ARRAY_ARG];
    app_pc ptr1, ptr2;
    socklen_t val_socklen;
    size_t val_size;
    const char *id = NULL;
    /* we store some values for post-syscall on successful safe_read using
     * these array values beyond our 2 params
     */
    if (pt->first_iter) {
        pt->sysarg[2] = 0;
        pt->sysarg[3] = 0;
        pt->sysarg[4] = 0;
        pt->sysarg[5] = 0;
    }
    LOG(2, "pre-sys_socketcall request=%d arg="PFX"\n", request, arg);
    LOG(3, "\targs: 0="PFX", 2="PFX", 3="PFX", 4="PFX"\n",
        arg[0], arg[1], arg[2], arg[3], arg[4]);/*unsafe reads*/
    if (arg == NULL)
        return;
    /* XXX: could use SYSINFO_SECONDARY_TABLE instead */
    switch (request) {
    case SYS_SOCKET:
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                3*sizeof(ptr_uint_t), "socket", DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    case SYS_BIND:
        id = "bind";
    case SYS_CONNECT:
        id = (id == NULL) ? "connect" : id;
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                3*sizeof(ptr_uint_t), id, DRSYS_TYPE_STRUCT, NULL))
            return;
        if (safe_read((void *)&arg[2], sizeof(val_socklen), &val_socklen) &&
            safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            /* whole thing should be addressable, but only part must be defined */
            if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_WRITE, ptr1, val_socklen,
                                    id, DRSYS_TYPE_STRUCT, NULL))
                return;
            check_sockaddr(pt, ii, ptr1, val_socklen, SOCK_ARRAY_ARG, SYSARG_READ, id);
            if (ii->abort)
                return;
        }
        break;
    case SYS_SHUTDOWN:
        id = "shutdown";
    case SYS_LISTEN:
        id = (id == NULL) ? "listen" : id;
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                2*sizeof(ptr_uint_t), id, DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    case SYS_ACCEPT:
        id = "accept";
    case SYS_GETSOCKNAME:
        id = (id == NULL) ? "getsockname" : id;
    case SYS_GETPEERNAME:
        id = (id == NULL) ? "getpeername" : id;
    case SYS_ACCEPT4:
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                3*sizeof(ptr_uint_t), id, DRSYS_TYPE_STRUCT, NULL))
            return;
        if (safe_read((void *)&arg[2], sizeof(arg[2]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen) &&
            safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            /* the size is an in-out arg */
            if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, ptr2,
                                    sizeof(socklen_t), id, DRSYS_TYPE_INT, NULL))
                return;
            if (pt->first_iter) {
                pt->sysarg[2] = (ptr_int_t) ptr1;
                pt->sysarg[3] = val_socklen;
            }
            if (ptr1 != NULL) { /* ok to be NULL for SYS_ACCEPT at least */
                check_sockaddr(pt, ii, ptr1, val_socklen, SOCK_ARRAY_ARG, SYSARG_WRITE,
                               id);
                if (ii->abort)
                    return;
            }
        }
        break;
    case SYS_SOCKETPAIR:
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                4*sizeof(ptr_uint_t), "socketpair",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        if (safe_read((void *)&arg[3], sizeof(arg[3]), &ptr1)) {
            if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_WRITE, ptr1,
                                    2*sizeof(int), "socketpair", DRSYS_TYPE_STRUCT, NULL))
                return;
        }
        break;
    case SYS_SEND:
        id = "send";
    case SYS_RECV:
        id = (id == NULL) ? "recv" : id;
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                4*sizeof(ptr_uint_t), id, DRSYS_TYPE_STRUCT, NULL))
            return;
        if (safe_read((void *)&arg[2], sizeof(arg[2]), &val_size) &&
            safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            if (pt->first_iter) {
                pt->sysarg[4] = (ptr_int_t) ptr1;
                pt->sysarg[5] = val_size;
            }
            if (!report_memarg_type(ii, SOCK_ARRAY_ARG,
                                    request == SYS_SEND ? SYSARG_READ :
                                    SYSARG_WRITE, ptr1, val_size, id,
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
        break;
    case SYS_SENDTO:
    case SYS_RECVFROM:
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                6*sizeof(ptr_uint_t),
                                (request == SYS_SENDTO) ? "sendto args" : "recvfrom args",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        if (safe_read((void *)&arg[2], sizeof(arg[2]), &val_size) &&
            safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            if (pt->first_iter) {
                pt->sysarg[4] = (ptr_int_t) ptr1;
                pt->sysarg[5] = val_size;
            }
            if (!report_memarg_type(ii, SOCK_ARRAY_ARG,
                                    request == SYS_SENDTO ? SYSARG_READ : SYSARG_WRITE,
                                    ptr1, val_size, (request == SYS_SENDTO) ?
                                    "sendto buf" : "recvfrom buf",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
        if (((request == SYS_SENDTO && 
              safe_read((void *)&arg[5], sizeof(val_socklen), &val_socklen)) ||
             (request == SYS_RECVFROM && 
              safe_read((void *)&arg[5], sizeof(arg[5]), &ptr2) &&
              safe_read(ptr2, sizeof(val_socklen), &val_socklen))) &&
            safe_read((void *)&arg[4], sizeof(arg[4]), &ptr1)) {
            if (pt->first_iter) {
                pt->sysarg[2] = (ptr_int_t) ptr1;
                pt->sysarg[3] = val_socklen;
            }
            if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_WRITE, ptr1, val_socklen, 
                                    (request == SYS_SENDTO) ? "sendto addr" :
                                    "recvfrom addr", DRSYS_TYPE_STRUCT, NULL))
                return;
            if (request == SYS_SENDTO) {
                check_sockaddr(pt, ii, ptr1, val_socklen, SOCK_ARRAY_ARG, SYSARG_READ,
                               "sendto addrlen");
                if (ii->abort)
                    return;
            }
        }
        break;
    case SYS_SETSOCKOPT:
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                5*sizeof(ptr_uint_t), "setsockopt args",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        if (safe_read((void *)&arg[4], sizeof(val_socklen), &val_socklen) &&
            safe_read((void *)&arg[3], sizeof(arg[3]), &ptr1)) {
            if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, ptr1, val_socklen,
                                    "setsockopt optval", DRSYS_TYPE_STRUCT, NULL))
                return;
        }
        break;
    case SYS_GETSOCKOPT:
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                5*sizeof(ptr_uint_t), "getsockopt args",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        if (safe_read((void *)&arg[4], sizeof(arg[4]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen) &&
            safe_read((void *)&arg[3], sizeof(arg[3]), &ptr1) &&
            ptr1 != NULL/*optional*/) {
            /* in-out arg */
            if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, ptr2,
                                    sizeof(socklen_t), "getsockopt optval",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
            if (pt->first_iter) {
                pt->sysarg[2] = (ptr_int_t) ptr1;
                pt->sysarg[3] = val_socklen;
            }
            if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_WRITE, ptr1, val_socklen,
                                    "getsockopt optlen", DRSYS_TYPE_INT, NULL))
                return;
        }
        break;
    case SYS_SENDMSG:
    case SYS_RECVMSG:
        if (!report_memarg_type(ii, SOCK_ARRAY_ARG, SYSARG_READ, (app_pc) arg,
                                3*sizeof(ptr_uint_t), (request == SYS_SENDMSG) ?
                                "sendmsg args" : "recvmsg args", DRSYS_TYPE_STRUCT, NULL))
            return;
        if (safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            if (pt->first_iter)
                pt->sysarg[2] = (ptr_int_t) ptr1; /* struct msghdr* */
            check_msghdr(drcontext, pt, ii, ptr1, sizeof(struct msghdr),
                         SOCK_ARRAY_ARG, (request == SYS_SENDMSG) ? SYSARG_READ :
                         SYSARG_WRITE);
            if (ii->abort)
                return;
        }
        break;
    default:
        ELOGF(0, f_global, "WARNING: unknown socketcall request %d\n", request); 
        IF_DEBUG(report_callstack(ii->arg->drcontext, ii->arg->mc);)
        break;
    }
}

static void
handle_post_socketcall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint request = (uint) pt->sysarg[0];
    ptr_uint_t *arg = (ptr_uint_t *) pt->sysarg[SOCK_ARRAY_ARG];
    ptr_int_t result = dr_syscall_get_result(drcontext);
    app_pc ptr2;
    socklen_t val_socklen;
    const char *id = NULL;
    LOG(2, "post-sys_socketcall result="PIFX"\n", result);
    if (result < 0)
        return;
    switch (request) {
    case SYS_ACCEPT:
        id = "accept";
    case SYS_GETSOCKNAME:
        id = (id == NULL) ? "getsockname" : id;
    case SYS_GETPEERNAME:
        id = (id == NULL) ? "getpeername" : id;
    case SYS_ACCEPT4:
        if (pt->sysarg[3]/*pre-addrlen*/ > 0 && pt->sysarg[2]/*sockaddr*/ != 0 &&
            /* re-read to see size returned by kernel */
            safe_read((void *)&arg[2], sizeof(arg[2]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen)) {
            check_sockaddr(pt, ii, (app_pc)pt->sysarg[2], val_socklen, SOCK_ARRAY_ARG,
                           SYSARG_WRITE, id);
            if (ii->abort)
                return;
        }
        break;
    case SYS_RECV:
        if (pt->sysarg[4]/*buf*/ != 0) {
            /* Not sure what kernel does on truncation so being safe */
            size_t len = (result <= pt->sysarg[5]/*buflen*/) ? result : pt->sysarg[5];
            if (len > 0) {
                if (!report_memarg_type(ii, 4, SYSARG_WRITE, (app_pc)pt->sysarg[4],
                                        len, "recv", DRSYS_TYPE_STRUCT, NULL))
                    return;
            }
        }
        break;
    case SYS_RECVFROM:
        if (pt->sysarg[4]/*buf*/ != 0) {
            /* Not sure what kernel does on truncation so being safe */
            size_t len = (result <= pt->sysarg[5]/*buflen*/) ? result : pt->sysarg[5];
            if (len > 0) {
                if (!report_memarg_type(ii, 4, SYSARG_WRITE, (app_pc)pt->sysarg[4],
                                        len, "recvfrom buf", DRSYS_TYPE_STRUCT, NULL))
                    return;
            }
        }
        if (pt->sysarg[3]/*pre-addrlen*/ > 0 && pt->sysarg[2]/*sockaddr*/ != 0 &&
            /* re-read to see size returned by kernel */
            safe_read((void *)&arg[5], sizeof(arg[5]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen)) {
            check_sockaddr(pt, ii, (app_pc)pt->sysarg[2], val_socklen, 2, SYSARG_WRITE,
                           "recvfrom addr");
            if (ii->abort)
                return;
        }
        break;
    case SYS_GETSOCKOPT:
        if (pt->sysarg[3]/*pre-optlen*/ > 0 && pt->sysarg[2]/*optval*/ != 0 &&
            /* re-read to see size returned by kernel */
            safe_read((void *)&arg[4], sizeof(arg[4]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen)) {
            /* Not sure what kernel does on truncation so being safe */
            size_t len = (val_socklen <= pt->sysarg[3]) ? val_socklen : pt->sysarg[3];
            if (!report_memarg_type(ii, 2, SYSARG_WRITE, (app_pc)pt->sysarg[2],
                                    len, "getsockopt", DRSYS_TYPE_STRUCT, NULL))
                return;
        }
        break;
    case SYS_RECVMSG: {
        if (pt->sysarg[2] != 0) { /* if 0, error on safe_read in pre */
            check_msghdr(drcontext, pt, ii, (byte *) pt->sysarg[2], sizeof(struct msghdr),
                         SOCK_ARRAY_ARG, SYSARG_WRITE);
            if (ii->abort)
                return;
        }
        break;
    }
    }
}
#endif /* !X64 */

static uint
ipc_sem_len(int semid)
{
    struct semid_ds ds;
    union semun ctlarg;
    ctlarg.buf = &ds;
    /* FIXME PR 519781: not tested! */
    if (
#ifdef X64
        raw_syscall(SYS_semctl, 4, semid, 0, IPC_STAT, (ptr_int_t)&ctlarg)
#else
        raw_syscall(SYS_ipc, 5, SEMCTL, semid, 0, IPC_STAT, (ptr_int_t)&ctlarg)
#endif
        < 0)
        return 0;
    else
        return ds.sem_nsems;
}

/* Note that we can't use a SYSINFO_SECONDARY_TABLE for this b/c some params
 * are not always used
 */
static void
handle_semctl(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii,
              /* shifted by one for 32-bit so we take in the base */
              int argnum_semid)
{
    /* int semctl(int semid, int semnum, int cmd, union semun arg) */
    uint cmd;
    ptr_int_t arg_val;
    union semun arg;
    int semid;
    ASSERT(argnum_semid + 3 < SYSCALL_NUM_ARG_STORE, "index too high");
    cmd = (uint) pt->sysarg[argnum_semid + 2];
    arg_val = (ptr_int_t) pt->sysarg[argnum_semid + 3];
    arg = *(union semun *) &arg_val;
    semid = (int) pt->sysarg[argnum_semid];
    if (!ii->arg->pre && (ptr_int_t)dr_syscall_get_result(drcontext) < 0)
        return;
    /* strip out the version flag or-ed in by libc */
    cmd &= (~IPC_64);
    if (ii->arg->pre) {
        if (!report_sysarg(ii, argnum_semid, SYSARG_READ))
            return;
        if (!report_sysarg(ii, argnum_semid + 2/*cmd*/, SYSARG_READ))
            return;
    }
    switch (cmd) {
    case IPC_SET:
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_semid + 3/*semun*/,SYSARG_READ))
                return;
            if (!report_memarg_type(ii, argnum_semid + 3, SYSARG_READ, (app_pc) arg.buf,
                                    sizeof(struct semid_ds), "semctl.IPC_SET",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
        break;
    case IPC_STAT:
    case SEM_STAT:
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_semid + 3/*semun*/,SYSARG_READ))
                return;
        }
        if (!report_memarg_type(ii, argnum_semid + 3, SYSARG_WRITE, (app_pc) arg.buf,
                                sizeof(struct semid_ds),
                                (cmd == IPC_STAT) ? "semctl.IPC_STAT" : "semctl.SEM_STAT",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    case IPC_RMID: /* nothing further */
        break;
    case IPC_INFO:
    case SEM_INFO:
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_semid + 3/*semun*/,SYSARG_READ))
                return;
        }
        if (!report_memarg_type(ii,argnum_semid + 3,  SYSARG_WRITE, (app_pc) arg.__buf,
                                sizeof(struct seminfo),
                                (cmd == IPC_INFO) ? "semctl.IPC_INFO" : "semctl.SEM_INFO",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    case GETALL: {
        /* we must query to get the length of arg.array */
        uint semlen = ipc_sem_len(semid);
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_semid + 3/*semun*/,SYSARG_READ))
                return;
        }
        if (!report_memarg_type(ii, argnum_semid + 3, SYSARG_WRITE, (app_pc) arg.array,
                                semlen*sizeof(short), "semctl.GETALL",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    }
    case SETALL: {
        if (ii->arg->pre) {
            /* we must query to get the length of arg.array */
            uint semlen = ipc_sem_len(semid);
            if (!report_sysarg(ii, argnum_semid + 3/*semun*/,SYSARG_READ))
                return;
            if (!report_memarg_type(ii, argnum_semid + 3, SYSARG_READ, (app_pc) arg.array,
                                    semlen*sizeof(short), "semctl.SETALL",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
        break;
    }
    case GETNCNT:
    case GETZCNT:
    case GETPID:
    case GETVAL:
        if (ii->arg->pre)
            if (!report_sysarg(ii, argnum_semid + 1/*semnum*/,SYSARG_READ))
                return;
        break;
    case SETVAL:
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_semid + 1/*semnun*/,SYSARG_READ))
                return;
            if (!report_sysarg(ii, argnum_semid + 3/*semun*/,SYSARG_READ))
                return;
        }
        break;
    default:
        ELOGF(0, f_global, "WARNING: unknown SEMCTL request %d\n", cmd);
        IF_DEBUG(report_callstack(ii->arg->drcontext, ii->arg->mc);)
        break;
    }
}

/* Note that we can't use a SYSINFO_SECONDARY_TABLE for this b/c some params
 * are not always used
 */
static void
handle_msgctl(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii,
              /* arg numbers vary for 32-bit vs 64-bit so we take them in */
              int argnum_msqid, int argnum_cmd, int argnum_buf)
{
    uint cmd = (uint) pt->sysarg[argnum_cmd];
    byte *ptr = (byte *) pt->sysarg[argnum_buf];
    if (!ii->arg->pre && (ptr_int_t)dr_syscall_get_result(drcontext) < 0)
        return;
    if (ii->arg->pre) {
        if (!report_sysarg(ii, argnum_msqid, SYSARG_READ))
            return;
        if (!report_sysarg(ii, argnum_cmd, SYSARG_READ))
            return;
    }
    switch (cmd) {
    case IPC_INFO:
    case MSG_INFO: {
        struct msginfo *buf = (struct msginfo *) ptr;
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_buf, SYSARG_READ))
                return;
        }
        /* not all fields are set but we simplify */
        if (!report_memarg_type(ii, argnum_buf, SYSARG_WRITE, (app_pc) buf, sizeof(*buf),
                                (cmd == IPC_INFO) ? "msgctl ipc_info" : "msgctl msg_info",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    }
    case IPC_STAT:
    case MSG_STAT: {
        struct msqid_ds *buf = (struct msqid_ds *) ptr;
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_buf, SYSARG_READ))
                return;
        }
        if (!report_memarg_type(ii, argnum_buf, SYSARG_WRITE, (app_pc) buf, sizeof(*buf),
                                (cmd == IPC_STAT) ?  "msgctl ipc_stat" : "msgctl msg_stat",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    }
    case IPC_SET: {
        if (ii->arg->pre) {
            struct msqid_ds *buf = (struct msqid_ds *) ptr;
            if (ii->arg->pre) {
                if (!report_sysarg(ii, argnum_buf, SYSARG_READ))
                    return;
            }
            /* not all fields are read but we simplify */
            if (!report_memarg_type(ii, argnum_buf, SYSARG_READ, (app_pc) buf,
                                    sizeof(*buf), "msgctl ipc_set",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
        break;
    }
    case IPC_RMID: /* nothing further to do */
        break;
    default:
        ELOGF(0, f_global, "WARNING: unknown MSGCTL request %d\n", cmd);
        IF_DEBUG(report_callstack(ii->arg->drcontext, ii->arg->mc);)
        break;
    }
}

/* Note that we can't use a SYSINFO_SECONDARY_TABLE for this b/c some params
 * are not always used
 */
static void
handle_shmctl(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii,
              /* arg numbers vary for 32-bit vs 64-bit so we take them in */
              int argnum_shmid, int argnum_cmd, int argnum_buf)
{
    uint cmd = (uint) pt->sysarg[argnum_cmd];
    byte *ptr = (byte *) pt->sysarg[argnum_buf];
    if (!ii->arg->pre && (ptr_int_t)dr_syscall_get_result(drcontext) < 0)
        return;
    if (ii->arg->pre) {
        if (!report_sysarg(ii, argnum_shmid, SYSARG_READ))
            return;
        if (!report_sysarg(ii, argnum_cmd, SYSARG_READ))
            return;
    }
    switch (cmd) {
    case IPC_INFO:
    case SHM_INFO: {
        struct shminfo *buf = (struct shminfo *) ptr;
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_buf, SYSARG_READ))
                return;
        }
        /* not all fields are set but we simplify */
        if (!report_memarg_type(ii, argnum_buf, SYSARG_WRITE, (app_pc) buf, sizeof(*buf),
                                "shmctl ipc_info", DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    }
    case IPC_STAT:
    case SHM_STAT: {
        struct shmid_ds *buf = (struct shmid_ds *) ptr;
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_buf, SYSARG_READ))
                return;
        }
        if (!report_memarg_type(ii, argnum_buf, SYSARG_WRITE, (app_pc) buf, sizeof(*buf),
                                (cmd == IPC_STAT) ? "shmctl ipc_stat" : "shmctl shm_stat",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    }
    case IPC_SET: {
        struct shmid_ds *buf = (struct shmid_ds *) ptr;
        if (ii->arg->pre) {
            if (!report_sysarg(ii, argnum_buf, SYSARG_READ))
                return;
        }
        /* not all fields are read but we simplify */
        if (!report_memarg_type(ii, argnum_buf, ii->arg->pre ? SYSARG_WRITE : SYSARG_READ,
                                (app_pc) buf, sizeof(*buf), "shmctl ipc_set",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    }
    case IPC_RMID: /* nothing further to do */
        break;
    default:
        ELOGF(0, f_global, "WARNING: unknown SHMCTL request %d\n", cmd);
        IF_DEBUG(report_callstack(ii->arg->drcontext, ii->arg->mc);)
        break;
    }
}

static void
check_msgbuf(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii,
             byte *ptr, size_t len, int ordinal, uint arg_flags)
{
    bool msgsnd = TEST(SYSARG_READ, arg_flags); /* else, msgrcv */
    struct msgbuf *buf = (struct msgbuf *) ptr;
    if (!ii->arg->pre) {
        if (msgsnd)
            return;
        else
            len = (size_t) dr_syscall_get_result(drcontext);
    }
    if (!report_memarg_type(ii, ordinal, arg_flags, (app_pc) &buf->mtype,
                            sizeof(buf->mtype), msgsnd? "msgsnd mtype" : "msgrcv mtype",
                            DRSYS_TYPE_INT, NULL))
        return;
    report_memarg_type(ii, ordinal, arg_flags, (app_pc) &buf->mtext, len,
                       msgsnd? "msgsnd mtext" : "msgrcv mtext",
                       DRSYS_TYPE_STRUCT, NULL);
}

#ifndef X64 /* XXX i#1013: for mixed-mode we'll need to indirect SYS_socketcall, etc. */
static void
handle_pre_ipc(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint request = (uint) pt->sysarg[0];
    int arg2 = (int) pt->sysarg[2];
    ptr_uint_t *ptr = (ptr_uint_t *) pt->sysarg[4];
    ptr_int_t arg5 = (int) pt->sysarg[5];
    /* They all use param #0, which is checked via table specifying 1 arg */
    /* Note that we can't easily use SYSINFO_SECONDARY_TABLE for these
     * b/c they don't require all their params to be defined.
     */
    switch (request) {
    case SEMTIMEDOP:
        /* int semtimedop(int semid, struct sembuf *sops, unsigned nsops,
         *                struct timespec *timeout)
         */
        if (!report_sysarg(ii, 5, SYSARG_READ))
            return;
        if (!report_memarg_type(ii, 5, SYSARG_READ, (app_pc) arg5,
                                sizeof(struct timespec), "semtimedop",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        /* fall-through */
    case SEMOP:
        /* int semop(int semid, struct sembuf *sops, unsigned nsops) */
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return;
        if (!report_sysarg(ii, 2, SYSARG_READ))
            return;
        if (!report_sysarg(ii, 4, SYSARG_READ))
            return;
        if (!report_memarg_type(ii, 4, SYSARG_READ, (app_pc) ptr,
                                arg2*sizeof(struct sembuf), "semop",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        break;
    case SEMGET: /* nothing */
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return;
        if (!report_sysarg(ii, 2, SYSARG_READ))
            return;
        if (!report_sysarg(ii, 3, SYSARG_READ))
            return;
        break;
    case SEMCTL: {
        /* int semctl(int semid, int semnum, int cmd, ...) */
        handle_semctl(drcontext, pt, ii, 1);
        if (ii->abort)
            return;
        break;
    }
    case MSGSND: {
        /* int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg) */
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return; /* msqid */
        if (!report_sysarg(ii, 2, SYSARG_READ))
            return; /* msgsz */
        if (!report_sysarg(ii, 3, SYSARG_READ))
            return; /* msgflg */
        if (!report_sysarg(ii, 4, SYSARG_READ))
            return; /* msgp */
        check_msgbuf(drcontext, pt, ii, (byte *) ptr, arg2, 2, SYSARG_READ);
        if (ii->abort)
            return;
        break;
    }
    case MSGRCV: {
        /* ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp,
         *                int msgflg)
         */
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return; /* msqid */
        if (!report_sysarg(ii, 2, SYSARG_READ))
            return; /* msgsz */
        if (!report_sysarg(ii, 3, SYSARG_READ))
            return; /* msgflg */
        if (!report_sysarg(ii, 4, SYSARG_READ))
            return; /* msgp */
        if (!report_sysarg(ii, 5, SYSARG_READ))
            return; /* msgtyp */
        check_msgbuf(drcontext, pt, ii, (byte *) ptr, arg2, 2, SYSARG_WRITE);
        break;
    }
    case MSGGET:
        /* int msgget(key_t key, int msgflg) */
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return;
        if (!report_sysarg(ii, 2, SYSARG_READ))
            return;
        break;
    case MSGCTL: {
        handle_msgctl(drcontext, pt, ii, 1, 2, 4);
        break;
    }
    case SHMAT:
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return;
        if (!report_sysarg(ii, 2, SYSARG_READ))
            return;
        if (!report_sysarg(ii, 4, SYSARG_READ))
            return;
        /* FIXME: this should be treated as a new mmap by DR? */
        break;
    case SHMDT:
        if (!report_sysarg(ii, 4, SYSARG_READ))
            return;
        break;
    case SHMGET:
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return;
        if (!report_sysarg(ii, 2, SYSARG_READ))
            return;
        if (!report_sysarg(ii, 3, SYSARG_READ))
            return;
        break;
    case SHMCTL: {
        handle_shmctl(drcontext, pt, ii, 1, 2, 4);
        break;
    }
    default:
        ELOGF(0, f_global, "WARNING: unknown ipc request %d\n", request); 
        IF_DEBUG(report_callstack(ii->arg->drcontext, ii->arg->mc);)
        break;
    }
    /* If you add any handling here: need to check ii->abort first */
}

static void
handle_post_ipc(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint request = (uint) pt->sysarg[0];
    ptr_uint_t *ptr = (ptr_uint_t *) pt->sysarg[4];
    ptr_int_t result = dr_syscall_get_result(drcontext);
    switch (request) {
    case SEMCTL: {
        handle_semctl(drcontext, pt, ii, 1);
        break;
    }
    case MSGRCV: {
        if (result >= 0) {
            check_msgbuf(drcontext, pt, ii, (byte *) ptr, (size_t) result,
                         4, SYSARG_WRITE);
        }
        break;
    }
    case MSGCTL: {
        handle_msgctl(drcontext, pt, ii, 1, 2, 4);
        break;
    }
    case SHMCTL: {
        handle_shmctl(drcontext, pt, ii, 1, 2, 4);
        break;
    }
    }
    /* If you add any handling here: need to check ii->abort first */
}
#endif /* !X64 */

/* handles both select and pselect6 */
static void
handle_pre_select(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    int nfds = (int) pt->sysarg[0];
    /* Only special-cased b/c the size is special: one bit each.
     * No post-syscall action needed b/c no writes to previously-undef mem.
     */
    size_t sz = nfds / 8; /* 8 bits per byte, size is in bytes */
    app_pc ptr = (app_pc) pt->sysarg[1];
    if (ptr != NULL) {
        if (!report_memarg_type(ii, 1, SYSARG_READ, ptr, sz,
                                "select readfds", DRSYS_TYPE_STRUCT, NULL))
            return;
    }
    ptr = (app_pc) pt->sysarg[2];
    if (ptr != NULL) {
        if (!report_memarg_type(ii, 2, SYSARG_READ, ptr, sz,
                                "select writefds", DRSYS_TYPE_STRUCT, NULL))
            return;
    }
    ptr = (app_pc) pt->sysarg[3];
    if (ptr != NULL) {
        if (!report_memarg_type(ii, 3, SYSARG_READ, ptr, sz,
                                "select exceptfds", DRSYS_TYPE_STRUCT, NULL))
            return;
    }
    ptr = (app_pc) pt->sysarg[4];
    if (ptr != NULL) {
        if (!report_memarg_type(ii, 4, SYSARG_READ, ptr,
                                (ii->arg->sysnum.number == SYS_select ? 
                                 sizeof(struct timeval) : sizeof(struct timespec)),
                                "select timeout", DRSYS_TYPE_STRUCT, NULL))
            return;
    }
    if (ii->arg->sysnum.number == SYS_pselect6) {
        ptr = (app_pc) pt->sysarg[5];
        if (ptr != NULL) {
            if (!report_memarg_type(ii, 5, SYSARG_READ, ptr,
                                    sizeof(kernel_sigset_t), "pselect sigmask",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
    }
}

#define PRCTL_NAME_SZ 16 /* from man page */

static void
handle_pre_prctl(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint request = (uint) pt->sysarg[0];
    ptr_int_t arg1 = (ptr_int_t) pt->sysarg[1];
    /* They all use param #0, which is checked via table specifying 1 arg.
     * Officially it's a 5-arg syscall but so far nothing using beyond 2 args.
     */
    /* XXX: could use SYSINFO_SECONDARY_TABLE instead */
    switch (request) {
    case PR_SET_PDEATHSIG:
    case PR_SET_UNALIGN:
    case PR_SET_FPEMU:
    case PR_SET_FPEXC:
    case PR_SET_DUMPABLE:
    case PR_SET_TIMING:
    case PR_SET_TSC:
    case PR_SET_SECUREBITS:
    case PR_SET_SECCOMP:
    case PR_SET_KEEPCAPS:
    case PR_SET_ENDIAN:
    case PR_SET_TIMERSLACK:
    case PR_CAPBSET_READ:
    case PR_CAPBSET_DROP:
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return;
        break;
    case PR_GET_PDEATHSIG:
    case PR_GET_UNALIGN:
    case PR_GET_FPEMU:
    case PR_GET_FPEXC:
    case PR_GET_TSC:
    case PR_GET_ENDIAN:
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return;
        if (!report_memarg_type(ii, 1, SYSARG_WRITE, (app_pc) arg1, sizeof(int), NULL,
                                DRSYS_TYPE_INT, NULL))
            return;
        break;
    case PR_GET_DUMPABLE:
    case PR_GET_TIMING:
    case PR_GET_SECUREBITS:
    case PR_GET_SECCOMP:
    case PR_GET_KEEPCAPS:
    case PR_GET_TIMERSLACK:
        /* returned data is just syscall return value */
        break;
    case PR_SET_NAME:
    case PR_GET_NAME:
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return;
        if (!report_memarg_type(ii, 1, (request == PR_GET_NAME) ? SYSARG_WRITE :
                                SYSARG_READ, (app_pc) arg1, PRCTL_NAME_SZ, NULL,
                                DRSYS_TYPE_CARRAY, NULL))
            return;
        break;
    default:
        ELOGF(0, f_global, "WARNING: unknown prctl request %d\n", request); 
        IF_DEBUG(report_callstack(ii->arg->drcontext, ii->arg->mc);)
        break;
    }
}

static void
handle_post_prctl(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint request = (uint) pt->sysarg[0];
    ptr_int_t result = dr_syscall_get_result(drcontext);
    switch (request) {
    case PR_GET_PDEATHSIG:
    case PR_GET_UNALIGN:
    case PR_GET_FPEMU:
    case PR_GET_FPEXC:
    case PR_GET_TSC:
    case PR_GET_ENDIAN:
        if (result >= 0) {
            if (!report_memarg_type(ii, 1, SYSARG_WRITE, (app_pc) pt->sysarg[1],
                                    sizeof(int), NULL, DRSYS_TYPE_INT, NULL))
                return;
        }
        break;
    case PR_GET_NAME:
        /* FIXME PR 408539: actually only writes up to null char */
        if (!report_memarg_type(ii, 1, SYSARG_WRITE, (app_pc) pt->sysarg[1],
                                PRCTL_NAME_SZ, NULL, DRSYS_TYPE_CARRAY, NULL))
            return;
        break;
    }
}

void
os_handle_pre_syscall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    switch (ii->arg->sysnum.number) {
    case SYS_clone: 
        handle_clone(drcontext, pt, ii); 
        break;
    case SYS__sysctl: {
        struct __sysctl_args *args = (struct __sysctl_args *) pt->sysarg[0];
        if (args != NULL) {
            /* just doing reads here: writes in post */
            if (!report_memarg_type(ii, 0, SYSARG_READ, (app_pc) args->name,
                                    args->nlen*sizeof(int), NULL,
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
            if (args->newval != NULL) {
                if (!report_memarg_type(ii, 0, SYSARG_READ, (app_pc) args->newval,
                                        args->newlen, NULL, DRSYS_TYPE_STRUCT, NULL))
                    return;
            }
        }
        break;
    }
    case SYS_mremap: {
        /* 5th arg is conditionally valid */
        int flags = (int) pt->sysarg[3];
        if (TEST(MREMAP_FIXED, flags)) {
            if (!report_sysarg(ii, 4, SYSARG_READ))
                return;
        }
        break;
    }
    case SYS_open: {
        /* 3rd arg is sometimes required.  glibc open() wrapper passes
         * a constant 0 as mode if no O_CREAT, but opendir() bypasses
         * that wrapper (PR 488597).
         */
        int flags = (int) pt->sysarg[1];
        if (TEST(O_CREAT, flags)) {
            if (!report_sysarg(ii, 2, SYSARG_READ))
                return;
        }
        break;
    }
    case SYS_fcntl:
#ifndef X64
    case SYS_fcntl64: 
#endif
        {
        /* 3rd arg is sometimes required.  Note that SYS_open has a similar
         * situation but we don't yet bother to special-case b/c glibc passes
         * a constant 0 as mode if no O_CREAT: yet fcntl glibc routine
         * blindly reads 3rd arg regardless of 2nd.
         */
            int cmd = (int) pt->sysarg[1];
            /* Some kernels add custom cmds, so error on side of false pos
             * rather than false neg via negative checks
             */
            if (cmd != F_GETFD && cmd != F_GETFL && cmd != F_GETOWN
#ifdef __USE_GNU
                && cmd != F_GETSIG && cmd != F_GETLEASE
#endif
                ) {
                if (!report_sysarg(ii, 2, SYSARG_READ))
                    return;
            }
        }
        break;
    case SYS_ioctl: 
        handle_pre_ioctl(drcontext, pt, ii); 
        break;
#ifdef X64
    case SYS_semctl:
        handle_semctl(drcontext, pt, ii, 0);
        break;
    case SYS_msgctl:
        handle_msgctl(drcontext, pt, ii, 0, 1, 2);
        break;
    case SYS_shmctl:
        handle_shmctl(drcontext, pt, ii, 0, 1, 2);
        break;
#else
    /* XXX i#1013: for mixed-mode we'll need is_sysnum() for access to these */
    case SYS_socketcall: 
        handle_pre_socketcall(drcontext, pt, ii);
        break;
    case SYS_ipc: 
        handle_pre_ipc(drcontext, pt, ii); 
        break;
#endif
    case SYS_select: /* fall-through */
    case SYS_pselect6:
        handle_pre_select(drcontext, pt, ii);
        break;
    case SYS_poll: {
        struct pollfd *fds = (struct pollfd *) pt->sysarg[0];
        nfds_t nfds = (nfds_t) pt->sysarg[1];
        if (fds != NULL) {
            int i;
            for (i = 0; i < nfds; i++) {
                /* First fields are inputs, last is output */
                if (!report_memarg_type(ii, 0, SYSARG_READ, (app_pc) &fds[i],
                                        offsetof(struct pollfd, revents), NULL,
                                        DRSYS_TYPE_STRUCT, NULL))
                    return;
                if (!report_memarg_type(ii, 0, SYSARG_WRITE, (app_pc) &fds[i].revents,
                                        sizeof(fds[i].revents), NULL,
                                        DRSYS_TYPE_STRUCT, NULL))
                    return;
            }
        }
        break;
    }
    case SYS_prctl:
        handle_pre_prctl(drcontext, pt, ii);
        break;
    case SYS_rt_sigaction: {
        /* restorer field not always filled in.  we ignore the old (pre-2.1.68)
         * kernel sigaction struct layout.
         */
        kernel_sigaction_t *sa = (kernel_sigaction_t *) pt->sysarg[1];
        if (sa != NULL) {
            if (TEST(SA_RESTORER, sa->flags)) {
                if (!report_memarg_type(ii, 1, SYSARG_READ, (app_pc) sa, sizeof(*sa),
                                        NULL, DRSYS_TYPE_STRUCT, NULL))
                    return;
            } else {
                if (!report_memarg_type(ii, 1, SYSARG_READ, (app_pc) sa,
                                        offsetof(kernel_sigaction_t, restorer), NULL,
                                        DRSYS_TYPE_STRUCT, NULL))
                    return;
                /* skip restorer field */
                if (!report_memarg_type(ii, 1, SYSARG_READ, (app_pc) &sa->mask,
                                        sizeof(*sa) - offsetof(kernel_sigaction_t, mask),
                                        NULL, DRSYS_TYPE_STRUCT, NULL))
                    return;
            }
        }
        break;
    }
    case SYS_futex: {
        /* PR 479107: later args are optional */
        int op = (int) pt->sysarg[1];
        if (op == FUTEX_WAKE || op == FUTEX_FD) {
            /* just the 3 params */
        } else if (op == FUTEX_WAIT) {
            struct timespec *timeout = (struct timespec *) pt->sysarg[3];
            if (!report_sysarg(ii, 3, SYSARG_READ))
                return;
            if (timeout != NULL) {
                if (!report_memarg_type(ii, 3, SYSARG_READ, (app_pc) timeout,
                                        sizeof(*timeout), NULL, DRSYS_TYPE_STRUCT, NULL))
                    return;
            }
        } else if (op == FUTEX_REQUEUE || op == FUTEX_CMP_REQUEUE) {
            if (!report_sysarg(ii, 4, SYSARG_READ))
                return;
            if (op == FUTEX_CMP_REQUEUE) {
                if (!report_sysarg(ii, 5, SYSARG_READ))
                    return;
            }
            if (!report_memarg_type(ii, 4, SYSARG_READ, (app_pc) pt->sysarg[4],
                                    sizeof(uint), NULL, DRSYS_TYPE_INT, NULL))
                return;
        }
        break;
    }
    }
    /* If you add any handling here: need to check ii->abort first */
}

void
os_handle_post_syscall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* each handler checks result for success */
    switch (ii->arg->sysnum.number) {
    case SYS__sysctl: {
        struct __sysctl_args *args = (struct __sysctl_args *) pt->sysarg[0];
        size_t len;
        if (dr_syscall_get_result(drcontext) == 0 && args != NULL) {
            /* xref PR 408540: here we wait until post so we can use the
             * actual written size.  There could be races but they're
             * app errors, which we should report, right?
             */
            if (args->oldval != NULL && safe_read(args->oldlenp, sizeof(len), &len)) {
                if (!report_memarg_type(ii, 0, SYSARG_WRITE, (app_pc) args->oldval, len,
                                        NULL, DRSYS_TYPE_STRUCT, NULL))
                    return;
            }
        }
        break;
    }
    case SYS_ioctl: 
        handle_post_ioctl(drcontext, pt, ii); 
        break;
#ifdef X64
    case SYS_semctl:
        handle_semctl(drcontext, pt, ii, 0);
        break;
    case SYS_msgctl:
        handle_msgctl(drcontext, pt, ii, 0, 1, 2);
        break;
    case SYS_shmctl:
        handle_shmctl(drcontext, pt, ii, 0, 1, 2);
        break;
#else
    case SYS_socketcall: 
        handle_post_socketcall(drcontext, pt, ii); 
        break;
    case SYS_ipc: 
        handle_post_ipc(drcontext, pt, ii); 
        break;
#endif
    case SYS_prctl:
        handle_post_prctl(drcontext, pt, ii);
        break;
    };
    /* If you add any handling here: need to check ii->abort first */
}

/***************************************************************************
 * SHADOW PER-ARG-TYPE HANDLING
 */

static bool
handle_cstring_access(sysarg_iter_info_t *ii,
                      const syscall_arg_t *arg_info,
                      app_pc start, uint size/*in bytes*/)
{
    return handle_cstring(ii, arg_info->param, arg_info->flags,
                          NULL, start, size, NULL,
                          /* let normal check ensure full size is addressable */
                          false);
}

static bool
handle_sockaddr_access(sysarg_iter_info_t *ii, const syscall_arg_t *arg_info,
                       app_pc start, uint size)
{
    cls_syscall_t *pt = (cls_syscall_t *)
        drmgr_get_cls_field(ii->arg->drcontext, cls_idx_drsys);
    check_sockaddr(pt, ii, start, (socklen_t) size, arg_info->param,
                   arg_info->flags, NULL);
    if (TEST(SYSARG_READ, arg_info->flags))
        return true; /* whole struct not defined */
    else
        return false; /* do check whole struct for addressability */
}

static bool
handle_msghdr_access(sysarg_iter_info_t *ii, const syscall_arg_t *arg_info,
                       app_pc start, uint size)
{
    cls_syscall_t *pt = (cls_syscall_t *)
        drmgr_get_cls_field(ii->arg->drcontext, cls_idx_drsys);
    check_msghdr(ii->arg->drcontext, pt, ii, start, (socklen_t) size,
                 arg_info->param, arg_info->flags);
    return true; /* check_msghdr checks whole struct */
}

static bool
handle_msgbuf_access(sysarg_iter_info_t *ii, const syscall_arg_t *arg_info,
                     app_pc start, uint size)
{
    cls_syscall_t *pt = (cls_syscall_t *)
        drmgr_get_cls_field(ii->arg->drcontext, cls_idx_drsys);
    check_msgbuf(ii->arg->drcontext, pt, ii, start, size,
                 arg_info->param, arg_info->flags);
    return true; /* check_msgbuf checks whole struct */
}

static bool
os_handle_syscall_arg_access(sysarg_iter_info_t *ii,
                             const syscall_arg_t *arg_info,
                             app_pc start, uint size)
{
    if (!TEST(SYSARG_COMPLEX_TYPE, arg_info->flags))
        return false;

    switch (arg_info->misc) {
    case SYSARG_TYPE_CSTRING:
        return handle_cstring_access(ii, arg_info, start, size);
    case SYSARG_TYPE_SOCKADDR:
        return handle_sockaddr_access(ii, arg_info, start, size);
    case SYSARG_TYPE_MSGHDR:
        return handle_msghdr_access(ii, arg_info, start, size);
    case SYSARG_TYPE_MSGBUF:
        return handle_msgbuf_access(ii, arg_info, start, size);
    }
    return false;
}

bool
os_handle_pre_syscall_arg_access(sysarg_iter_info_t *ii,
                                 const syscall_arg_t *arg_info,
                                 app_pc start, uint size)
{
    return os_handle_syscall_arg_access(ii, arg_info, start, size);
}

bool
os_handle_post_syscall_arg_access(sysarg_iter_info_t *ii,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size)
{
    return os_handle_syscall_arg_access(ii, arg_info, start, size);
}

/***************************************************************************
 * TOP_LEVEL
 */

bool
os_syscall_succeeded(drsys_sysnum_t sysnum, syscall_info_t *info, ptr_int_t res)
{
    if (sysnum.number == SYS_mmap || IF_X86_32(sysnum.number == SYS_mmap2 ||)
        sysnum.number == SYS_mremap)
        return (res >= 0 || res < -PAGE_SIZE);
    else
        return (res >= 0);
}

/* provides name if known when not in syscall_lookup(num) */
const char *
os_syscall_get_name(drsys_sysnum_t num)
{
    /* everything's in the table */
    return NULL;
}
