/* **********************************************************
 * Copyright (c) 2009 VMware, Inc.  All rights reserved.
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
#include "drmemory.h"
#include "syscall.h"
#include "syscall_os.h"
#include "shadow.h"
#include "readwrite.h"
#include "sysnum_linux.h"
#include "alloc_drmem.h"
#include "alloc.h"
#include "heap.h"
#include "stack.h"
#ifdef DEBUG
# include "report.h"    /* To report callstacks on unknown ioctl syscalls. */
#endif /* DEBUG */
#include <stddef.h> /* for offsetof */

/* for linux-specific types/defines for fcntl and ipc */
#define __USE_GNU 1

#ifdef HAVE_ASM_I386
/* tying them all to this one header for now */
# define GLIBC_2_2_5 1
#endif

#include <sys/types.h>
#ifdef GLIBC_2_2_5
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
#include <signal.h> /* siginfo_t */
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
#include <fcntl.h> /* F_GETFD, etc. */
#include <asm/ldt.h> /* struct user_desc */
#include <linux/futex.h>
#include <linux/mman.h> /* MREMAP_FIXED */

/* ipc */
#ifdef GLIBC_2_2_5
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
#include <linux/ext2_fs.h>
#include <linux/fd.h>
#include <linux/hdreg.h>
#include <linux/if.h>
#include <linux/if_plip.h>
#include <linux/ipx.h>
#include <linux/kd.h>
#include <linux/lp.h>
#include <linux/mroute.h>
#ifdef GLIBC_2_2_5
# include <linux/mtio.h>
#else
# include <sys/mtio.h>
#endif
#include <linux/netrom.h>
#include <linux/scc.h>
#include <linux/smb_fs.h>
#include <linux/sockios.h>
#include <linux/route.h>
#include <linux/if_arp.h>
#include <linux/soundcard.h>
#if 0 /* XXX: header not avail: ioctl code below disabled as well */
# include <linux/umsdos_fs.h>
#endif
#include <linux/vt.h>
#include <linux/ipmi.h> /* PR 531644 */
#ifndef GLIBC_2_2_5
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

#ifdef GLIBC_2_2_5
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

/***************************************************************************
 * SYSTEM CALLS FOR LINUX
 */

/* Created from ./mksystable_linux.pl
 * And then manually:
 * - filling in params for those marked "Missing prototype"
 * - filling in params for those marked "special-case"
 * - replacing U with W or R
 * - updating sizeof(char) and sizeof(void)
 *
 * FIXME PR 406302: still a lot of missing details below!
 */
#define W (SYSARG_WRITE)
#define R (0)
#define CSTRING (SYSARG_SIZE_CSTRING)
#define RET (SYSARG_POST_SIZE_RETVAL)
syscall_info_t syscall_info[] = {
    {0,"restart_syscall", 0,},
    {1,"exit", 1,},
    {2,"fork", 0,},
    {3,"read", 3,{{1,-2,W},{1,RET,W},}},
    {4,"write", 3,{{1,-2,R},}},
    {5,"open", 2,{{0,CSTRING,R},}}, /*special-cased: 3rd arg not always required*/
    {6,"close", 1,},
    {7,"waitpid", 3,{{1,sizeof(int),W},}},
    {8,"creat", 2,{{0,CSTRING,R},}},
    {9,"link", 2,{{0,CSTRING,R},{1,CSTRING,R},}},
    {10,"unlink", 1,{{0,CSTRING,R},}},
    {11,"execve", 3,{{0,CSTRING,R},/* FIXME: char** argv and envp */}},
    {12,"chdir", 1,{{0,CSTRING,R},}},
    {13,"time", 1,{{0,sizeof(time_t),W},}},
    {14,"mknod", 3,{{0,CSTRING,R},}},
    {15,"chmod", 2,{{0,CSTRING,R},}},
    {16,"lchown16", 3,{{0,CSTRING,R},}},
    {17,"ni_syscall", 0,},
    {18,"stat", 2,{{0,CSTRING,R},{1,sizeof(struct __old_kernel_stat),W},}},
    {19,"lseek", 3,},
    {20,"getpid", 0,},
    {21,"mount", 5,{{0,CSTRING,R},{1,CSTRING,R},{2,CSTRING,R},/*FIXME: 4 varies: ignore for now*/}},
    {22,"oldumount", 1,{{0,CSTRING,R},}},
    {23,"setuid16", 1,},
    {24,"getuid16", 0,},
    {25,"stime", 1,{{0,sizeof(time_t),R},}},
    {26,"ptrace", 4,},
    {27,"alarm", 1,},
    {28,"fstat", 2,{{1,sizeof(struct __old_kernel_stat),W},}},
    {29,"pause", 0,},
    {30,"utime", 2,{{0,CSTRING,R},{1,sizeof(struct utimbuf),R},}},
    {31,"ni_syscall", 0,},
    {32,"ni_syscall", 0,},
    {33,"access", 2,{{0,CSTRING,R},}},
    {34,"nice", 1,},
    {35,"ni_syscall", 0,},
    {36,"sync", 0,},
    {37,"kill", 2,},
    {38,"rename", 2,{{0,CSTRING,R},{1,CSTRING,R},}},
    {39,"mkdir", 2,{{0,CSTRING,R},}},
    {40,"rmdir", 1,{{0,CSTRING,R},}},
    {41,"dup", 1,},
    {42,"pipe", 1,{{0,2*sizeof(int),W},}},
    {43,"times", 1,{{0,sizeof(struct tms),W},}},
    {44,"ni_syscall", 0,},
    {45,"brk", 1,},
    {46,"setgid16", 1,},
    {47,"getgid16", 0,},
    {48,"signal", 2,},
    {49,"geteuid16", 0,},
    {50,"getegid16", 0,},
    {51,"acct", 1,{{0,CSTRING,R},}},
    {52,"umount", 2,{{0,CSTRING,R},}},
    {53,"ni_syscall", 0,},
    {54,"ioctl", 3,}, /* varies: special-cased below */
    {55,"fcntl", 2,}, /*special-cased: 3rd arg not always required*/
    {56,"ni_syscall", 0,},
    {57,"setpgid", 2,},
    {58,"ni_syscall", 0,},
    {59,"olduname", 1, /* FIXME: ***Missing prototype*** */ },
    {60,"umask", 1,},
    {61,"chroot", 1,{{0,CSTRING,R},}},
    {62,"ustat", 2,{{1,sizeof(struct ustat),W},}},
    {63,"dup2", 2,},
    {64,"getppid", 0,},
    {65,"getpgrp", 0,},
    {66,"setsid", 0,},
    {67,"sigaction", 3,/*FIXME type: {{1,sizeof(struct old_sigaction),W},{2,sizeof(struct old_sigaction),R},}*/},
    {68,"sgetmask", 0,},
    {69,"ssetmask", 1,},
    {70,"setreuid16", 2,},
    {71,"setregid16", 2,},
    {72,"sigsuspend", 3,},
    {73,"sigpending", 1,/*FIXME type: {{0,sizeof(old_sigset_t),W},}*/},
    {74,"sethostname", 2,{{0,-1,R},}},
    {75,"setrlimit", 2,{{1,sizeof(struct rlimit),R},}},
    {76,"old_getrlimit", 2,{{1,sizeof(struct rlimit),W},}},
    {77,"getrusage", 2,{{1,sizeof(struct rusage),W},}},
    {78,"gettimeofday", 2,{{0,sizeof(struct timeval),W},{1,sizeof(struct timezone),W},}},
    {79,"settimeofday", 2,{{0,sizeof(struct timeval),R},{1,sizeof(struct timezone),R},}},
    {80,"getgroups16", 2,/* FIXME how encode these: {{1,ARG1 * sizeof(vki_old_gid_t),W},{1,RES * sizeof(vki_old_gid_t),W},}*/},
    {81,"setgroups16", 2,/* FIXME how encode these:{{1,ARG1 * sizeof(vki_old_gid_t),R},}*/},
    {82,"old_select", /*FIXME*/},
    {83,"symlink", 2,{{0,CSTRING,R},{1,CSTRING,R},}},
    {84,"lstat", 2,{{0,CSTRING,R},{1,sizeof(struct __old_kernel_stat),W},}},
    {85,"readlink", 3,{{0,CSTRING,R},{1,-2,W},{1,RET,W},}},
    {86,"uselib", 1,{{0,CSTRING,R},}},
    {87,"swapon", 2,{{0,CSTRING,R},}},
    {88,"reboot", 4, /*FIXME: 3 is optional*/},
    {89,"old_readdir", 3,/*FIXME type: {{1,sizeof(struct old_linux_dirent),W},}*/},
    {90,"mmap", /*FIXME*/},
    {91,"munmap", 2,},
    {92,"truncate", 2,{{0,CSTRING,R},}},
    {93,"ftruncate", 2,},
    {94,"fchmod", 2,},
    {95,"fchown16", 3,},
    {96,"getpriority", 2,},
    {97,"setpriority", 3,},
    {98,"ni_syscall", 0,},
    {99,"statfs", 2,{{0,CSTRING,R},{1,sizeof(struct statfs),W},}},
    {100,"fstatfs", 2,{{1,sizeof(struct statfs),W},}},
    {101,"ioperm", 3,},
    {102,"socketcall", 2, /* special-cased below */},
    {103,"syslog", 3,{{1,-2,W},}},
    {104,"setitimer", 3,{{1,sizeof(struct itimerval),R},{2,sizeof(struct itimerval),W},}},
    {105,"getitimer", 2,{{1,sizeof(struct itimerval),W},}},
    {106,"newstat", 2,{{0,CSTRING,R},{1,sizeof(struct stat),W},}},
    {107,"newlstat", 2,{{0,CSTRING,R},{1,sizeof(struct stat),W},}},
    {108,"newfstat", 2,{{1,sizeof(struct stat),W},}},
    {109,"uname", 1, /* FIXME: ***Missing prototype*** */ },
    {110,"iopl", 1,},
    {111,"vhangup", 0,},
    {112,"ni_syscall", 0,},
    {113,"vm86old", 1, /* FIXME: ***Missing prototype*** */ },
    {114,"wait4", 4,{{1,sizeof(int),W},{3,sizeof(struct rusage),W},}},
    {115,"swapoff", 1,{{0,CSTRING,R},}},
    {116,"sysinfo", 1,{{0,sizeof(struct sysinfo),W},}},
    {117,"ipc", 1, /* special-cased below */ },
    {118,"fsync", 1,},
    {119,"sigreturn", 0},
    {120,"clone", 2,}, /* 3 params added in later kernels special-cased */
    {121,"setdomainname", 2,{{0,-1,R},}},
    {122,"newuname", 1,{{0,sizeof(struct new_utsname),W},}},
    {123,"modify_ldt", 3, /* FIXME: ***Missing prototype*** */ },
    {124,"adjtimex", 1,{{0,sizeof(struct timex),R},}},
    {125,"mprotect", 3,},
    {126,"sigprocmask", 3,/*FIXME type: {{1,sizeof(old_sigset_t),R},{2,sizeof(old_sigset_t),W},}*/},
    {127,"ni_syscall", 0,},
    {128,"init_module", 3,{{0,-1,R},{2,CSTRING,R},}},
    {129,"delete_module", 2, {{0,CSTRING,R,},}},
    {130,"ni_syscall", 0,},
    {131,"quotactl", 4,{{1,CSTRING,R}, /* FIXME: #3 varies */}},
    {132,"getpgid", 1,},
    {133,"fchdir", 1,},
    {134,"bdflush", 2,},
    {135,"sysfs", 3,},
    {136,"personality", 1,},
    {137,"ni_syscall", 0,},
    {138,"setfsuid16", 1,},
    {139,"setfsgid16", 1,},
    {140,"llseek", 5,{{3,sizeof(loff_t),W},}},
    {141,"getdents", 3,{{1,-2,W},{1,RET,W},}},
    /* FIXME: process manually below here */
    {142,"select", 5,/* special-cased below */},
    {143,"flock", 2,},
    {144,"msync", 3,{{0,-1,R},}},
    {145,"readv", 3, /* FIXME 1,ARG3 * sizeof(struct vki_iovec),R, 1,****** special-case:  (Addr)vec[i].iov_base, nReadThisBuf,R, */},
    {146,"writev", 3, /* FIXME 1,ARG3 * sizeof(struct vki_iovec),R, 1,****** special-case:  "writev(vector[...])", (Addr)vec[i].iov_base, vec[i].iov_len,R, */},
    {147,"getsid", 1,},
    {148,"fdatasync", 1,},
    {149,"sysctl", 1,{{0,sizeof(struct __sysctl_args),R},}},/*special-cased*/
    {150,"mlock", 2,},
    {151,"munlock", 2,},
    {152,"mlockall", 1,},
    {153,"munlockall", 0,},
    {154,"sched_setparam", 2,{{1,sizeof(struct sched_param),R},}},
    {155,"sched_getparam", 2,{{1,sizeof(struct sched_param),W},}},
    {156,"sched_setscheduler", 3,{{2,sizeof(struct sched_param),R},}},
    {157,"sched_getscheduler", 1,},
    {158,"sched_yield", 0,},
    {159,"sched_get_priority_max", 1,},
    {160,"sched_get_priority_min", 1,},
    {161,"sched_rr_get_interval", 2, /* FIXME  1,sizeof(struct timespec),U, */},
    {162,"nanosleep", 2,{{0,sizeof(struct timespec),R},{1,sizeof(struct timespec),W},}},
    {163,"mremap", 4,}, /* 5th arg is conditional so special-cased below */
    {164,"setresuid16", 3,},
    {165,"getresuid16", 3,/*FIXME type: {{0,sizeof(old_uid_t),W},{1,sizeof(old_uid_t),W},{2,sizeof(old_uid_t),W},}*/},
    {166,"vm86", 2, /* FIXME: ***Missing prototype*** */ },
    {167,"ni_syscall", 0,},
    {168,"poll", 3, /* special-cased below */},
    {169,"nfsservctl", 3, /* FIXME 1,sizeof(struct nfsctl_arg),U, 2,sizeof(void),U, */},
    {170,"setresgid16", 3,},
    {171,"getresgid16", 3,/*FIXME type: {{0,sizeof(old_gid_t),W},{1,sizeof(old_gid_t),W},{2,sizeof(old_gid_t),W},}*/},
    {172,"prctl", 1, /* special-cased below */},
    {173,"rt_sigreturn", 0},
    {174,"rt_sigaction", 4,/*1 is special-cased below*/{{2,sizeof(kernel_sigaction_t),W},}},
    {175,"rt_sigprocmask", 4,{{1,sizeof(kernel_sigset_t),R},{2,sizeof(kernel_sigset_t),W},}},
    {176,"rt_sigpending", 2,{{0,sizeof(kernel_sigset_t),W},}},
    {177,"rt_sigtimedwait", 4,{{0,sizeof(kernel_sigset_t),R},{1,sizeof(siginfo_t),W},{2,sizeof(struct timespec),R},}},
    {178,"rt_sigqueueinfo", 3,{{2,sizeof(siginfo_t),R},}},
    {179,"rt_sigsuspend", 2, /* FIXME 0,sizeof(siginfo_t),R, 0,****** special-case:  arg2, sizeof(struct vki_msqid64_ds),R, */},
/* WARNING: pread64 4 != 5 */
    {180,"pread64", 4,{{1,-2,W},{1,RET,W},}},
/* WARNING: pwrite64 4 != 5 */
    {181,"pwrite64", 4,{{1,-2,R},}},
    {182,"chown16", 3,{{0,CSTRING,R},}},
    {183,"getcwd", 2,{{0,-1,W},{0,RET,W},}},
    {184,"capget", 2,{{0,sizeof(cap_user_header_t),R},{1,sizeof(cap_user_data_t),W},}},
    {185,"capset", 2,{{0,sizeof(cap_user_header_t),R},{1,sizeof(cap_user_data_t),R},}},
    {186,"sigaltstack", 2, /* FIXME 0,****** special-case:  "sigaltstack(ss)", (Addr)&ss->ss_sp, sizeof(ss->ss_sp),R, 0,****** special-case:  "sigaltstack(ss)", (Addr)&ss->ss_size, sizeof(ss->ss_size),R,{1,sizeof(cap_user_data_t data),W}, */},
    {187,"sendfile", 4,{{2,sizeof(off_t),W},}},
    {188,"ni_syscall", 0,},
    {189,"ni_syscall", 0,},
    {190,"vfork", 0,},
    {191,"getrlimit", 2,{{1,sizeof(struct rlimit),W},}},
    {192,"mmap2", 6,},
/* WARNING: truncate64 2 != 3 */
    {193,"truncate64", 2,{{0,CSTRING,R},}},
/* WARNING: ftruncate64 2 != 3 */
    {194,"ftruncate64", 2,},
    {195,"stat64", 2,{{0,CSTRING,R},{1,sizeof(struct stat64),W},}},
    {196,"lstat64", 2,{{0,CSTRING,R},{1,sizeof(struct stat64),W},}},
    {197,"fstat64", 2,{{1,sizeof(struct stat64),W,}}},
    {198,"lchown", 3,{{0,CSTRING,R},}},
    {199,"getuid", 0,},
    {200,"getgid", 0,},
    {201,"geteuid", 0,},
    {202,"getegid", 0,},
    {203,"setreuid", 2,},
    {204,"setregid", 2,},
    {205,"getgroups", 2,/*FIXME{{1,ARG1 * sizeof(vki_gid_t),W},{1,RES * sizeof(vki_gid_t),W},}*/},
    {206,"setgroups", 2,/*FIXME{{1,ARG1 * sizeof(vki_gid_t),R},}*/},
    {207,"fchown", 3,},
    {208,"setresuid", 3,},
    {209,"getresuid", 3,{{0,sizeof(uid_t),W},{1,sizeof(uid_t),W},{2,sizeof(uid_t),W},}},
    {210,"setresgid", 3,},
    {211,"getresgid", 3,{{0,sizeof(gid_t),W},{1,sizeof(gid_t),W},{2,sizeof(gid_t),W},}},
    {212,"chown", 3,{{0,CSTRING,R},}},
    {213,"setuid", 1,},
    {214,"setgid", 1,},
    {215,"setfsuid", 1,},
    {216,"setfsgid", 1,},
    {217,"pivot_root", 2, /* FIXME 0,sizeof(char),U, 1,sizeof(char),U, */},
    {218,"mincore", 3,{{2,/*FIXME: round up to next page size*/-1,W},}},
    {219,"madvise", 3,},
    {220,"getdents64", 3,{{1,-2,W},{1,RET,W},}},
    {221,"fcntl64", 2,}, /*special-cased: 3rd arg not always required*/
    {222,"ni_syscall", 0,},
    {223,"ni_syscall", 0,},
    {224,"gettid", 0,},
    {225,"readahead", 3,},
    {226,"setxattr", 5,{{0,CSTRING,R},{1,CSTRING,R},{2,-3,R},}},
    {227,"lsetxattr", 5,{{0,CSTRING,R},{1,CSTRING,R},{2,-3,R},}},
    {228,"fsetxattr", 5,{{1,CSTRING,R},{2,-3,R},}},
    {229,"getxattr", 4,{{0,CSTRING,R},{1,CSTRING,R},{2,-3,W},{2,RET,W},}},
    {230,"lgetxattr", 4,{{0,CSTRING,R},{1,CSTRING,R},{2,-3,W},{2,RET,W},}},
    {231,"fgetxattr", 4,{{1,CSTRING,R},{2,-3,W},{2,RET,W},}},
    {232,"listxattr", 3,{{0,CSTRING,R},{1,-2,W},{1,RET,W},}},
    {233,"llistxattr", 3,{{0,CSTRING,R},{1,-2,W},{1,RET,W},}},
    {234,"flistxattr", 3,{{1,-2,W},{1,RET,W},}},
    {235,"removexattr", 2,{{0,CSTRING,R},{1,CSTRING,R},}},
    {236,"lremovexattr", 2,{{0,CSTRING,R},{1,CSTRING,R},}},
    {237,"fremovexattr", 2,{{1,CSTRING,R},}},
    {238,"tkill", 2,},
    {239,"sendfile64", 4,{{2,sizeof(loff_t),W},}},
    {240,"futex", 3,{{0,sizeof(uint),R},}},/*rest are special-cased*/
    {241,"sched_setaffinity", 3,{{2,-1,R},}},
    {242,"sched_getaffinity", 3,{{2,-1,W},}},
    {243,"set_thread_area", /* FIXME: ***Missing prototype*** */ },
    {244,"get_thread_area", /* FIXME: ***Missing prototype*** */ },
    {245,"io_setup", 2,/*FIXME type: {{1,sizeof(aio_context_t),W},}*/},
    {246,"io_destroy", 1,},
    {247,"io_getevents", 5, /* FIXME 3,sizeof(struct io_event),W, 3,****** special-case:  cb->aio_buf, vev->result,W,{4,sizeof(struct timespec),R}, */},
    {248,"io_submit", 3, /* FIXME 2,ARG2*sizeof(struct vki_iocb *),R, 2,****** special-case:  "io_submit(PWRITE)", cb->aio_buf, cb->aio_nbytes,R, */},
    {249,"io_cancel", 3,/* FIXME type: {{1,sizeof(struct iocb),R},{2,sizeof(struct io_event),W},}*/},
/* WARNING: fadvise64 4 != 5 */
    {250,"fadvise64", 4,},
    {251,"ni_syscall", 0,},
    {252,"exit_group", 1,},
/* WARNING: lookup_dcookie 3 != 4 */
    {253,"lookup_dcookie", 3, /* FIXME 1,sizeof(char),U,{2,-3,W},{2,RET,W}, */},
    {254,"epoll_create", 1,},
    {255,"epoll_ctl", 4,{{3,sizeof(struct epoll_event),R},}},
    {256,"epoll_wait", 4,{{1,sizeof(struct epoll_event),W},/*FIXME {1,sizeof(struct vki_epoll_event)*RES,W},*/}},
    {257,"remap_file_pages", 5,},
    {258,"set_tid_address", 1, /* FIXME 0,sizeof(int),U, */},
    {259,"timer_create", 3,{{1,sizeof(struct sigevent),R},{2,sizeof(timer_t),W},}},
    {260,"timer_settime", 4,{{2,sizeof(struct itimerspec),R},{3,sizeof(struct itimerspec),W},}},
    {261,"timer_gettime", 2,{{1,sizeof(struct itimerspec),W},}},
    {262,"timer_getoverrun", 1,},
    {263,"timer_delete", 1,},
    {264,"clock_settime", 2,{{1,sizeof(struct timespec),R},}},
    {265,"clock_gettime", 2,{{1,sizeof(struct timespec),W},}},
    {266,"clock_getres", 2,{{1,sizeof(struct timespec),W},}},
    {267,"clock_nanosleep", 4,{{2,sizeof(struct timespec),R},{3,sizeof(struct timespec),W},}},
    {268,"statfs64", 3,{{0,CSTRING,R},{2,-1,W},}},
    {269,"fstatfs64", 3,{{2,-1,W},}},
    {270,"tgkill", 3,},
    {271,"utimes", 2,{{0,CSTRING,R},{1,2 * sizeof(struct timeval),R},}},
/* WARNING: fadvise64_64 4 != 6 */
    {272,"fadvise64_64", 4,},
    {273,"ni_syscall", 0,},
    {274,"mbind", 6, /*FIXME {{3,VG_ROUNDUP(ARG5,sizeof(UWord))/sizeof(UWord),R,},}*/},
    {275,"get_mempolicy", 5,/*FIXME {{0,sizeof(int),W}, {1,VG_ROUNDUP(ARG3,sizeof(UWord)*8)/sizeof(UWord),W},}*/},
    {276,"set_mempolicy", 3, /*FIXME {{1,VG_ROUNDUP(ARG3,sizeof(UWord))/sizeof(UWord),R},}*/},
    {277,"mq_open", 4, /* FIXME 0,CSTRING,R, 0,****** special-case:  "mq_open(attr->mq_msgsize)", (Addr)&attr->mq_msgsize, sizeof(attr->mq_msgsize),R, 3,sizeof(struct mq_attr),U, */},
    {278,"mq_unlink", 1,{{0,CSTRING,R},}},
    {279,"mq_timedsend", 5,{{1,-2,R},{4,sizeof(struct timespec),R}},},
    {280,"mq_timedreceive", 5,{{1,-2,W},{3,sizeof(unsigned int),W},{4,sizeof(struct timespec),R}},},
    {281,"mq_notify", 2,{{1,sizeof(struct sigevent),R},}},
    {282,"mq_getsetattr", 3, /* FIXME 1,****** special-case:  "mq_getsetattr(mqstat->mq_flags)", (Addr)&attr->mq_flags, sizeof(attr->mq_flags),R,{2,sizeof(struct mq_attr),W}, */},
    {283,"kexec_load", 4, /* FIXME 2,sizeof(struct kexec_segment),U, */},
    {284,"waitid", 5,{{2,sizeof(struct siginfo),W},{4,sizeof(struct rusage),W},}},
    {285,"ni_syscall", 0,},
    {286,"add_key", 5,{{0,CSTRING,R},{1,CSTRING,R},{2,-3,R},}},
    {287,"request_key", 4,{{0,CSTRING,R},{1,CSTRING,R},{2,CSTRING,R},}},
    {288,"keyctl", 5,{{1,CSTRING,R},{2,-3,R},{2,RET,R},{3,CSTRING,R},}},
    {289,"ioprio_set", 3,},
    {290,"ioprio_get", 2,},
    {291,"inotify_init", 0,},
    {292,"inotify_add_watch", 3,{{1,CSTRING,R},}},
    {293,"inotify_rm_watch", 2,},
    {294,"migrate_pages", 4, /* FIXME 2,sizeof(unsigned long),U, 3,sizeof(unsigned long),U, */},
    {295,"openat", 4,{{1,CSTRING,R},}},
    {296,"mkdirat", 3,{{1,CSTRING,R},}},
    {297,"mknodat", 4,{{1,CSTRING,R},}},
/* WARNING: fchownat 5 != 4 */
    {298,"fchownat", 5,{{1,CSTRING,R},}},
    {299,"futimesat", 3,{{1,CSTRING,R},{2,2 * sizeof(struct timeval),R},}},
    {300,"fstatat64", 4, /* FIXME 1,sizeof(char),U, 2,sizeof(struct stat64),U, */},
/* WARNING: unlinkat 3 != 2 */
    {301,"unlinkat", 3,{{1,CSTRING,R},}},
    {302,"renameat", 4,{{1,CSTRING,R},{3,CSTRING,R},}},
    {303,"linkat", 5,{{1,CSTRING,R},{3,CSTRING,R},}},
    {304,"symlinkat", 3,{{0,CSTRING,R},{2,CSTRING,R},}},
    {305,"readlinkat", 4,{{1,CSTRING,R},{2,-3,W},{2,RET,W},}},
    {306,"fchmodat", 3,{{1,CSTRING,R},}},
    {307,"faccessat", 3,{{1,CSTRING,R},}},
    {308,"pselect6", 6, /* special-cased below */},
    {309,"ppoll", 5, /* FIXME 0,sizeof(struct pollfd),U,{2,sizeof(struct timespec),R},{3,sizeof(kernel_sigset_t),R}, 3,****** special-case:  (Addr)(&ufds[i].revents), sizeof(ufds[i].revents),R, */},
    {310,"unshare", 1,},
    {311,"set_robust_list", 2,{{0,-1,R},}},
    {312,"get_robust_list", 3,/*FIXME type: {{1,sizeof(struct robust_list_head),W},{2,sizeof(size_t),W},}*/},
    {313,"splice", 6, /* FIXME 1,sizeof(loff_t),U, 3,sizeof(loff_t),U, */},
    {314,"sync_file_range", 4,},
    {315,"tee", 4,},
    {316,"vmsplice", 4, /* FIXME 1,sizeof(struct iovec),U, */},
    {317,"move_pages", 6, /* FIXME 2,sizeof(void),U, 3,sizeof(int),U, 4,sizeof(int),U, */},
    {318,"getcpu", 3, /* FIXME 0,sizeof(unsigned),U, 1,sizeof(unsigned),U, 2,sizeof(struct getcpu_cache),U, */},
    {319,"epoll_pwait", 6,{{1,sizeof(struct epoll_event),W},/*FIXME {1,sizeof(struct epoll_event)*RES,W},*/{4,sizeof(kernel_sigset_t),R},}},
    {320,"utimensat", 4,{{1,CSTRING,R},{2,2 * sizeof(struct timespec),R},}},
    {321,"signalfd", 3,{{1,sizeof(kernel_sigset_t),R},}},
/* WARNING: timerfd_create 2 != 3 */
    {322,"timerfd_create", 2,},
    {323,"eventfd", 1,},
    {324,"fallocate", 4,},
    {325,"timerfd_settime", 4,{{2,sizeof(struct itimerspec),R},{3,sizeof(struct itimerspec),W},}},
    {326,"timerfd_gettime", 2,{{1,sizeof(struct itimerspec),W},}},
    {327,"signalfd4", 4, /* FIXME 1,sizeof(kernel_sigset_t),U, */},
    {328,"eventfd2", 2,},
    {329,"epoll_create1", 1,},
    {330,"dup3", 3,},
    {331,"pipe2", 2, /* FIXME 0,sizeof(int),U, */},
    {332,"inotify_init1", 1,},
};
#undef W
#undef R
#undef CSTRING
#undef RET

#define NUM_SYSCALLS (sizeof(syscall_info)/sizeof(syscall_info[0]))


void
syscall_os_init(void *drcontext)
{
}

void
syscall_os_exit(void)
{
}

syscall_info_t *
syscall_lookup(int num)
{
    if (num > 0 && num < NUM_SYSCALLS)
        return &syscall_info[num];
    return NULL;
}

static inline reg_id_t
sysparam_reg(uint sysnum, uint argnum)
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

uint
get_sysparam_shadow_val(uint sysnum, uint argnum, dr_mcontext_t *mc)
{
    void *drcontext = dr_get_current_drcontext();
    reg_id_t reg = sysparam_reg(sysnum, argnum);
    ASSERT(!options.leaks_only && options.shadowing, "shadowing disabled");
    /* DR's syscall events don't tell us if this was vsyscall so we compare
     * values to find out
     */
    if (reg == REG_EBP &&
        reg_get_value(reg, mc) != dr_syscall_get_param(drcontext, argnum)) {
        /* must be vsyscall */
        ASSERT(!is_using_sysint(), "vsyscall incorrect assumption");
        return shadow_get_byte((app_pc)mc->xsp);
    } else {
        return get_shadow_register(reg);
    }
}

void
check_sysparam_defined(uint sysnum, uint argnum, dr_mcontext_t *mc, size_t argsz)
{
    void *drcontext = dr_get_current_drcontext();
    reg_id_t reg = sysparam_reg(sysnum, argnum);
    ASSERT(!options.leaks_only && options.shadowing, "shadowing disabled");
    /* DR's syscall events don't tell us if this was vsyscall so we compare
     * values to find out
     */
    if (reg == REG_EBP &&
        reg_get_value(reg, mc) != dr_syscall_get_param(drcontext, argnum)) {
        /* must be vsyscall */
        ASSERT(!is_using_sysint(), "vsyscall incorrect assumption");
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                     (app_pc)mc->xsp, argsz, mc, NULL);
    } else {
        app_loc_t loc;
        syscall_to_loc(&loc, sysnum, NULL);
        check_register_defined(drcontext, reg, &loc, argsz, mc, NULL);
    }
}

static void
handle_clone(void *drcontext, dr_mcontext_t *mc)
{
    uint flags = (uint) dr_syscall_get_param(drcontext, 0);
    app_pc newsp = (app_pc) dr_syscall_get_param(drcontext, 1);

    /* PR 426162: pre-2.5.32-kernel, only 2 args.  Later glibc clone() has 3
     * optional args.  It blindly copies the 3 added args into registers, but
     * the kernel ignores them unless selected by appropriate flags.
     * We check the writes here to avoid races (xref PR 408540).
     */
    if (TEST(CLONE_PARENT_SETTID, flags)) {
        pid_t *ptid = (pid_t *) dr_syscall_get_param(drcontext, 2);
        check_sysparam_defined(SYS_clone, 2, mc, sizeof(reg_t));
        if (ptid != NULL) {
            check_sysmem(MEMREF_WRITE, SYS_clone,
                         (app_pc) ptid, sizeof(*ptid), mc, NULL);
        }
    }
    if (TEST(CLONE_SETTLS, flags)) {
        /* handle differences in type name */
#ifdef _LINUX_LDT_H
        typedef struct modify_ldt_ldt_s user_desc_t;
#else
        typedef struct user_desc user_desc_t;
#endif
        user_desc_t *tls = (user_desc_t *) dr_syscall_get_param(drcontext, 3);
        check_sysparam_defined(SYS_clone, 3, mc, sizeof(reg_t));
        if (tls != NULL) {
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_clone,
                         (app_pc) tls, sizeof(*tls), mc, NULL);
        }
    }
    if (TESTANY(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID, flags)) {
        /* Even though CLEARTID is not used until child exit, and the address
         * can be changed later with set_tid_address(), and at one time glibc
         * didn't support the param but the kernel did, the kernel will store
         * this address so we should complain.
         */
        pid_t *ptid = (pid_t *) dr_syscall_get_param(drcontext, 4);
        check_sysparam_defined(SYS_clone, 4, mc, sizeof(reg_t));
        if (ptid != NULL) {
            check_sysmem(MEMREF_WRITE, SYS_clone,
                         (app_pc) ptid, sizeof(*ptid), mc, NULL);
        }
    }

    /* PR 418629: we need to change the stack from defined (marked when it
     * was allocated) to unaddressable.  Originally we couldn't get the stack
     * bounds in the thread init event (xref PR 395156) so we watch here:
     * we could move this code now but not worth it.
     * FIXME: should we watch SYS_exit and put stack back to defined
     * in case it's re-used?  Seems better to leave it unaddressable
     * since may be more common to have racy accesses we want to flag
     * rather than legitimate re-use?
     */
    if (TEST(CLONE_VM, flags) && newsp != NULL) {
        app_pc stack_base = NULL;
        size_t stack_size;
        /* newsp is TOS */
        ASSERT(options.track_heap, "now relying on -track_heap in general");
        if (is_in_heap_region(newsp)) {
            /* How find base of malloc chunk to then find size?
             * Don't want to store all mallocs in an interval data structure
             * (shown to be slow in PR 535568).
             * Maybe hardcode knowledge of how far from upper address
             * glibc clone() sets newsp?
             * Actually, should just walk shadow memory until hit
             * unaddressable.
             */
            /* FIXME: NEVER TESTED! */
            app_pc pc;
            ssize_t sz;
            /* PR 525807 added an interval tree of "large mallocs" */
            if (malloc_large_lookup(newsp, &pc, (size_t*)&sz)) {
                stack_base = pc;
                stack_size = sz;
            } else {
                /* Should be rare so we just do brute force and slow */
                pc = shadow_prev_dword(newsp, newsp - options.stack_swap_threshold,
                                       SHADOW_UNADDRESSABLE);
                sz = malloc_size(pc+1);
                if (sz > 0) { /* returns -1 on failure */
                    stack_base = pc + 1;
                    stack_size = sz;
                }
            }
        } else {
            /* On linux a pre-adjacent mmap w/ same prot will be merged into the
             * same region as returned by dr_query_memory() and we'll mark it as
             * unaddressable => many false positives (on FC10, adding a printf
             * to suite/tests/linux/clone.c between the stack mmap and the clone
             * call resulted in the merge).  My solution is to track mmaps and
             * assume a stack will be a single mmap (maybe separate guard page
             * but that should be noprot so ok to not mark unaddress: xref PR
             * 406328).
             */
            if (!mmap_anon_lookup(newsp, &stack_base, &stack_size)) {
                /* Fall back to a query */
                LOG(2, "thread stack "PFX" not in mmap table, querying\n", newsp);
                if (!dr_query_memory(newsp - 1, &stack_base, &stack_size, NULL)) {
                    /* We can estimate the stack end by assuming that clone()
                     * puts less than a page on the stack, but the base is harder:
                     * instead we rely on PR 525807 handle_push_addressable() to
                     * mark the stack unaddr one page at a time.
                     */
                    stack_base = NULL;
                }
            }
        }
        if (stack_base != NULL) {
            LOG(2, "changing thread stack "PFX"-"PFX" -"PFX" to unaddressable\n",
                stack_base, stack_base + stack_size, newsp);
            ASSERT(stack_base + stack_size >= newsp,
                   "new thread's stack alloc messed up");
            /* assume that above newsp should stay defined */
            shadow_set_range(stack_base, newsp, SHADOW_UNADDRESSABLE);
            check_stack_size_vs_threshold(drcontext, stack_size);
        } else {
            LOG(0, "ERROR: cannot find bounds of new thread's stack "PFX"\n",
                newsp);
            ASSERT(false, "can't find bounds of thread's stack");
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

static void
handle_pre_ioctl(void *drcontext, dr_mcontext_t *mc)
{
    uint request = (uint) dr_syscall_get_param(drcontext, 1);
    void *arg = (void *) dr_syscall_get_param(drcontext, 2);
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
#define CHECK_DEF(ptr, sz, mc, id) \
    check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_ioctl, (app_pc)ptr, sz, mc, id)
#define CHECK_ADDR(ptr, sz, mc, id) \
    check_sysmem(MEMREF_CHECK_ADDRESSABLE, SYS_ioctl, (app_pc)ptr, sz, mc, id)

    /* From "man ioctl_list" 
     * Note that we treat in-out as just read since we'll report and mark
     * as defined if undefined.
     */
    /* FIXME: "Some ioctls take a pointer to a structure which contains
     * additional pointers."  These are marked above with "FIXME: more".
     * They are listed in the man page but I'm too lazy to add them just now.
     */
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
        CHECK_DEF(arg, sizeof(struct ifconf), mc, NULL);
        if (safe_read((void *)arg, sizeof(input), &input))
            CHECK_ADDR(input.ifc_buf, input.ifc_len, mc, "SIOCGIFCONF ifc_buf");
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
        CHECK_DEF(arg, sizeof(struct ipmi_req), mc, NULL); /*no id == arg itself*/
        if (safe_read((void *)arg, sizeof(struct ipmi_req), &data.req)) {
            CHECK_DEF(data.req.addr, data.req.addr_len +
                      ipmi_addr_len_adjust((struct ipmi_addr *)data.req.addr), mc,
                      "IPMICTL_SEND_COMMAND addr");
            CHECK_DEF(data.req.msg.data, data.req.msg.data_len, mc,
                      "IPMICTL_SEND_COMMAND msg.data");
        }
        return;
    case IPMICTL_SEND_COMMAND_SETTIME:
        CHECK_DEF(arg, sizeof(struct ipmi_req_settime), mc, NULL); /*no id == arg*/
        if (safe_read((void *)arg, sizeof(struct ipmi_req_settime), &data.reqs)) {
            CHECK_DEF(data.reqs.req.addr, data.reqs.req.addr_len +
                      ipmi_addr_len_adjust((struct ipmi_addr *)data.reqs.req.addr), mc,
                      "IPMICTL_SEND_COMMAND_SETTIME addr");
            CHECK_DEF(data.reqs.req.msg.data, data.reqs.req.msg.data_len, mc,
                      "IPMICTL_SEND_COMMAND_SETTIME msg.data");
        }
        return;
    case IPMICTL_RECEIVE_MSG:
    case IPMICTL_RECEIVE_MSG_TRUNC: {
        struct ipmi_recv *recv = (struct ipmi_recv *) arg;
        CHECK_ADDR(arg, sizeof(struct ipmi_recv), mc, NULL); /*no id == arg*/
        /* some fields are purely OUT so we must check the IN ones separately */
        CHECK_DEF(&recv->addr, sizeof(recv->addr), mc, NULL);
        CHECK_DEF(&recv->addr_len, sizeof(recv->addr_len), mc, NULL);
        CHECK_DEF(&recv->msg.data, sizeof(recv->msg.data), mc, NULL);
        CHECK_DEF(&recv->msg.data_len, sizeof(recv->msg.data_len), mc, NULL);
        if (safe_read((void *)arg, sizeof(struct ipmi_recv), &data.recv)) {
            CHECK_ADDR(data.recv.addr, data.recv.addr_len, mc,
                      "IPMICTL_RECEIVE_MSG* addr");
            CHECK_ADDR(data.recv.msg.data, data.recv.msg.data_len, mc,
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
        IF_DEBUG(report_callstack(drcontext, mc);)
#endif
        break;
    }

    if (sz > 0) {
        /* FIXME: really for a write should do MEMREF_CHECK_ADDRESSABLE in pre-syscall
         * and MEMREF_WRITE in post
         */
        /* FIXME: should we report the ioctl # a la PR 525269?  Hard
         * to fit that into the string literal model of syscall_aux
         * info.  For ioctls vs each other, the rest of the callstack
         * should distinguish (though that's also true for SYS_ipc, etc.),
         * and for multi-arg we can provide custom strings.
         */
        check_sysmem(write ? MEMREF_WRITE : MEMREF_CHECK_DEFINEDNESS,
                     SYS_ioctl, (app_pc) arg, sz, mc, id);
    }
#undef CHECK_DEF
#undef CHECK_ADDR
}

static void
handle_post_ioctl(void *drcontext, dr_mcontext_t *mc)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
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
#define MARK_WRITE(ptr, sz, mc, id) \
    check_sysmem(MEMREF_WRITE, SYS_ioctl, (app_pc)ptr, sz, mc, id)
    switch (request) {
    case SIOCGIFCONF: {
        struct ifconf output;
        if (safe_read((void *)arg, sizeof(output), &output))
            MARK_WRITE(output.ifc_buf, output.ifc_len, mc, "SIOCGIFCONF ifc_buf");
        return;
    }
    case IPMICTL_RECEIVE_MSG:
    case IPMICTL_RECEIVE_MSG_TRUNC:
        if (safe_read((void *)arg, sizeof(struct ipmi_recv), &data.recv)) {
            MARK_WRITE(data.recv.addr, data.recv.addr_len, mc,
                       "IPMICTL_RECEIVE_MSG* addr");
            MARK_WRITE(data.recv.msg.data, data.recv.msg.data_len, mc,
                       "IPMICTL_RECEIVE_MSG* msg.data");
        }
        return;
    }
#undef MARK_WRITE
}

/* struct sockaddr is large but the meaningful portions vary by family */
static void
check_sockaddr(byte *ptr, socklen_t socklen, uint memcheck_flags, dr_mcontext_t *mc,
               const char *id)
{
    struct sockaddr *sa = (struct sockaddr *) ptr;
    sa_family_t family;
    if (TESTANY(MEMREF_CHECK_DEFINEDNESS | MEMREF_CHECK_ADDRESSABLE, memcheck_flags)) {
        check_sysmem(memcheck_flags, SYS_socketcall,
                     (app_pc) &sa->sa_family, sizeof(sa->sa_family), mc, id);
    }
    if (!safe_read(&sa->sa_family, sizeof(family), &family))
        return;
    /* FIXME: do not check beyond socklen */
    switch (family) {
    case AF_UNIX: {
        struct sockaddr_un *sun = (struct sockaddr_un *) sa;
        size_t len = safe_strnlen(sun->sun_path, (socklen < sizeof(*sun)) ?
                                  socklen : sizeof(*sun)) + 1;
        check_sysmem(memcheck_flags, SYS_socketcall, (app_pc) sun->sun_path, len, mc, id);
        break;
    }
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        check_sysmem(memcheck_flags, SYS_socketcall,
                     (app_pc) &sin->sin_port, sizeof(sin->sin_port), mc, id);
        check_sysmem(memcheck_flags, SYS_socketcall,
                     (app_pc) &sin->sin_addr, sizeof(sin->sin_addr), mc, id);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
        check_sysmem(memcheck_flags, SYS_socketcall,
                     (app_pc) &sin6->sin6_port, sizeof(sin6->sin6_port), mc, id);
        check_sysmem(memcheck_flags, SYS_socketcall,
                     (app_pc) &sin6->sin6_flowinfo, sizeof(sin6->sin6_flowinfo), mc, id);
        check_sysmem(memcheck_flags, SYS_socketcall,
                     (app_pc) &sin6->sin6_addr, sizeof(sin6->sin6_addr), mc, id);
        check_sysmem(memcheck_flags, SYS_socketcall,
                     (app_pc) &sin6->sin6_scope_id, sizeof(sin6->sin6_scope_id), mc, id);
        break;
    }
    default:
        ELOGF(0, f_global, "WARNING: unknown sockaddr type %d\n", family); 
        IF_DEBUG(report_callstack(dr_get_current_drcontext(), mc);)
        break;
    }
}

/* scatter-gather buffer vector handling.
 * ignores bytes_read unless memcheck_flags == MEMREF_WRITE.
 */
static void
check_iov(struct iovec *iov, size_t iov_len, size_t bytes_read,
          uint memcheck_flags, uint sysnum, dr_mcontext_t *mc, const char *id)
{
    uint i;
    size_t bytes_so_far = 0;
    bool done = false;
    struct iovec iov_copy;
    if (iov == NULL || iov_len == 0)
        return;
    check_sysmem(memcheck_flags, sysnum,
                 (app_pc)iov, iov_len * sizeof(struct iovec), mc, id);
    for (i = 0; i < iov_len; i++) {
        if (safe_read(&iov[i], sizeof(iov_copy), &iov_copy)) {
            if (memcheck_flags == MEMREF_WRITE) {
                if (bytes_so_far + iov_copy.iov_len > bytes_read) {
                    done = true;
                    iov_copy.iov_len = (bytes_read - bytes_so_far);
                }
                bytes_so_far += iov_copy.iov_len;
            }
            LOG(3, "check_iov: iov entry %d, buf="PFX", len="PIFX"\n",
                i, iov_copy.iov_base, iov_copy.iov_len);
            check_sysmem(memcheck_flags, sysnum,
                         (app_pc)iov_copy.iov_base, iov_copy.iov_len, mc, id);
            if (done)
                break;
        }
    }
}

static void
handle_pre_socketcall(void *drcontext, dr_mcontext_t *mc)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    uint request = (uint) dr_syscall_get_param(drcontext, 0);
    /* The first sysparam is an array of args of varying length */
    ptr_uint_t *arg = (ptr_uint_t *) dr_syscall_get_param(drcontext, 1);
    app_pc ptr1, ptr2;
    socklen_t val_socklen;
    size_t val_size;
    const char *id = NULL;
    /* we store some values for post-syscall on successful safe_read using
     * these array values beyond our 2 params
     */
    pt->sysarg[2] = 0;
    pt->sysarg[3] = 0;
    pt->sysarg[4] = 0;
    pt->sysarg[5] = 0;
    LOG(2, "pre-sys_socketcall request=%d arg="PFX"\n", request, arg);
    LOG(3, "\targs: 0="PFX", 2="PFX", 3="PFX", 4="PFX"\n",
        arg[0], arg[1], arg[2], arg[3], arg[4]);/*unsafe reads*/
    if (arg == NULL)
        return;
    switch (request) {
    case SYS_SOCKET:
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 3*sizeof(ptr_uint_t), mc, "socket");
        break;
    case SYS_BIND:
        id = "bind";
    case SYS_CONNECT:
        id = (id == NULL) ? "connect" : id;
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 3*sizeof(ptr_uint_t), mc, id);
        if (safe_read((void *)&arg[2], sizeof(val_socklen), &val_socklen) &&
            safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            /* whole thing should be addressable, but only part must be defined */
            check_sysmem(MEMREF_CHECK_ADDRESSABLE, SYS_socketcall,
                         ptr1, val_socklen, mc, id);
            check_sockaddr(ptr1, val_socklen, MEMREF_CHECK_DEFINEDNESS, mc, id);
        }
        break;
    case SYS_SHUTDOWN:
        id = "shutdown";
    case SYS_LISTEN:
        id = (id == NULL) ? "listen" : id;
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 2*sizeof(ptr_uint_t), mc, id);
        break;
    case SYS_ACCEPT:
        id = "accept";
    case SYS_GETSOCKNAME:
        id = (id == NULL) ? "getsockname" : id;
    case SYS_GETPEERNAME:
        id = (id == NULL) ? "getpeername" : id;
#if 0 /* not in my defines */
    case SYS_ACCEPT4:
#endif
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 3*sizeof(ptr_uint_t), mc, id);
        if (safe_read((void *)&arg[2], sizeof(arg[2]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen) &&
            safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            /* the size is an in-out arg */
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                         ptr2, sizeof(socklen_t), mc, id);
            pt->sysarg[2] = (ptr_int_t) ptr1;
            pt->sysarg[3] = val_socklen;
            if (ptr1 != NULL) { /* ok to be NULL for SYS_ACCEPT at least */
                check_sysmem(MEMREF_CHECK_ADDRESSABLE, SYS_socketcall,
                             ptr1, val_socklen, mc, id);
            }
        }
        break;
    case SYS_SOCKETPAIR:
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 4*sizeof(ptr_uint_t), mc, "socketpair");
        if (safe_read((void *)&arg[3], sizeof(arg[3]), &ptr1)) {
            check_sysmem(MEMREF_WRITE, SYS_socketcall,
                         ptr1, 2*sizeof(int), mc, "socketpair");
        }
        break;
    case SYS_SEND:
        id = "send";
    case SYS_RECV:
        id = (id == NULL) ? "recv" : id;
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 4*sizeof(ptr_uint_t), mc, id);
        if (safe_read((void *)&arg[2], sizeof(arg[2]), &val_size) &&
            safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            pt->sysarg[4] = (ptr_int_t) ptr1;
            pt->sysarg[5] = val_size;
            check_sysmem(request == SYS_SEND ? MEMREF_CHECK_DEFINEDNESS :
                         MEMREF_CHECK_ADDRESSABLE, SYS_socketcall,
                         ptr1, val_size, mc, id);
        }
        break;
    case SYS_SENDTO:
    case SYS_RECVFROM:
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 6*sizeof(ptr_uint_t), mc,
                     (request == SYS_SENDTO) ? "sendto args" : "recvfrom args");
        if (safe_read((void *)&arg[2], sizeof(arg[2]), &val_size) &&
            safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            pt->sysarg[4] = (ptr_int_t) ptr1;
            pt->sysarg[5] = val_size;
            check_sysmem(request == SYS_SENDTO ? MEMREF_CHECK_DEFINEDNESS :
                         MEMREF_CHECK_ADDRESSABLE, SYS_socketcall,
                         ptr1, val_size, mc,
                         (request == SYS_SENDTO) ? "sendto buf" : "recvfrom buf");
        }
        if (((request == SYS_SENDTO && 
              safe_read((void *)&arg[5], sizeof(val_socklen), &val_socklen)) ||
             (request == SYS_RECVFROM && 
              safe_read((void *)&arg[5], sizeof(arg[5]), &ptr2) &&
              safe_read(ptr2, sizeof(val_socklen), &val_socklen))) &&
            safe_read((void *)&arg[4], sizeof(arg[4]), &ptr1)) {
            pt->sysarg[2] = (ptr_int_t) ptr1;
            pt->sysarg[3] = val_socklen;
            check_sysmem(MEMREF_CHECK_ADDRESSABLE, SYS_socketcall,
                         ptr1, val_socklen, mc, 
                         (request == SYS_SENDTO) ? "sendto addr" : "recvfrom addr");
            if (request == SYS_SENDTO) {
                check_sockaddr(ptr1, val_socklen, MEMREF_CHECK_DEFINEDNESS, mc,
                               "sendto addrlen");
            }
        }
        break;
    case SYS_SETSOCKOPT:
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 5*sizeof(ptr_uint_t), mc, "setsockopt args");
        if (safe_read((void *)&arg[4], sizeof(val_socklen), &val_socklen) &&
            safe_read((void *)&arg[3], sizeof(arg[3]), &ptr1)) {
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                         ptr1, val_socklen, mc, "setsockopt optval");
        }
        break;
    case SYS_GETSOCKOPT:
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 5*sizeof(ptr_uint_t), mc, "getsockopt args");
        if (safe_read((void *)&arg[4], sizeof(arg[4]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen) &&
            safe_read((void *)&arg[3], sizeof(arg[3]), &ptr1) &&
            ptr1 != NULL/*optional*/) {
            /* in-out arg */
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                         ptr2, sizeof(socklen_t), mc, "getsockopt optval");
            pt->sysarg[2] = (ptr_int_t) ptr1;
            pt->sysarg[3] = val_socklen;
            check_sysmem(MEMREF_CHECK_ADDRESSABLE, SYS_socketcall,
                         ptr1, val_socklen, mc, "getsockopt optlen");
        }
        break;
    case SYS_SENDMSG:
    case SYS_RECVMSG:
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                     (app_pc) arg, 3*sizeof(ptr_uint_t), mc,
                     (request == SYS_SENDMSG) ? "sendmsg args" : "recvmsg args");
        if (safe_read((void *)&arg[1], sizeof(arg[1]), &ptr1)) {
            size_t len = (request == SYS_SENDMSG) ? sizeof(struct msghdr) :
                /* msg_flags is an out param */
                offsetof(struct msghdr, msg_flags);
            struct msghdr *msg = (struct msghdr *) ptr1;
            LOG(3, "\tmsg="PFX", name="PFX", iov="PFX", control="PFX"\n",
                msg, msg->msg_name, msg->msg_iov, msg->msg_control);/*unsafe reads*/
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_socketcall,
                         (app_pc)msg, len, mc,
                         (request == SYS_SENDMSG) ? "sendmsg msg" : "recvmsg msg");
            pt->sysarg[2] = (ptr_int_t) msg;
            if (safe_read(&msg->msg_name, sizeof(msg->msg_name), &ptr2) &&
                safe_read(&msg->msg_namelen, sizeof(msg->msg_namelen), &val_socklen) &&
                ptr2 != NULL) {
                check_sockaddr(ptr2, val_socklen, MEMREF_CHECK_DEFINEDNESS, mc,
                               (request == SYS_SENDMSG) ? "sendmsg addr" :
                               "recvmsg addr");
            }
            if (safe_read(&msg->msg_iov, sizeof(msg->msg_iov), &ptr1) &&
                safe_read(&msg->msg_iovlen, sizeof(msg->msg_iovlen), &len) &&
                ptr1 != NULL) {
                check_iov((struct iovec *) ptr1, len, 0,
                          (request == SYS_SENDMSG) ? MEMREF_CHECK_DEFINEDNESS :
                          MEMREF_CHECK_ADDRESSABLE, SYS_socketcall, mc,
                          (request == SYS_SENDMSG) ? "sendmsg iov" : "recvmsg iov");
            }
            if (safe_read(&msg->msg_control, sizeof(msg->msg_control), &ptr2) &&
                safe_read(&msg->msg_controllen, sizeof(msg->msg_controllen),
                          &val_socklen)) {
                pt->sysarg[3] = (ptr_int_t) ptr2;
                pt->sysarg[4] = val_socklen;
                if (ptr2 != NULL) {
                    check_sysmem((request == SYS_SENDMSG) ? MEMREF_CHECK_DEFINEDNESS :
                                 MEMREF_CHECK_ADDRESSABLE, SYS_socketcall,
                                 ptr2, val_socklen, mc,
                                 (request == SYS_SENDMSG) ? "sendmsg msg_control" :
                                 "recvmsg msg_control");
                }
            }
        }
        break;
    default:
        ELOGF(0, f_global, "WARNING: unknown socketcall request %d\n", request); 
        IF_DEBUG(report_callstack(drcontext, mc);)
        break;
    }
}

static void
handle_post_socketcall(void *drcontext, dr_mcontext_t *mc)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    uint request = (uint) pt->sysarg[0];
    ptr_uint_t *arg = (ptr_uint_t *) pt->sysarg[1];
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
#if 0 /* not in my defines */
    case SYS_ACCEPT4:
#endif
        if (pt->sysarg[3]/*pre-addrlen*/ > 0 && pt->sysarg[2]/*sockaddr*/ != 0 &&
            /* re-read to see size returned by kernel */
            safe_read((void *)&arg[2], sizeof(arg[2]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen)) {
            /* If not enough space kernel writes space needed */
            size_t len = (val_socklen <= pt->sysarg[3]) ? val_socklen : pt->sysarg[3];
            check_sockaddr((app_pc)pt->sysarg[2], len, MEMREF_WRITE, mc, id);
        }
        break;
    case SYS_RECV:
        if (pt->sysarg[4]/*buf*/ != 0) {
            /* Not sure what kernel does on truncation so being safe */
            size_t len = (result <= pt->sysarg[5]/*buflen*/) ? result : pt->sysarg[5];
            if (len > 0) {
                check_sysmem(MEMREF_WRITE, SYS_socketcall,
                             (app_pc)pt->sysarg[4], len, mc, "recv");
            }
        }
        break;
    case SYS_RECVFROM:
        if (pt->sysarg[4]/*buf*/ != 0) {
            /* Not sure what kernel does on truncation so being safe */
            size_t len = (result <= pt->sysarg[5]/*buflen*/) ? result : pt->sysarg[5];
            if (len > 0) {
                check_sysmem(MEMREF_WRITE, SYS_socketcall,
                             (app_pc)pt->sysarg[4], len, mc, "recvfrom buf");
            }
        }
        if (pt->sysarg[3]/*pre-addrlen*/ > 0 && pt->sysarg[2]/*sockaddr*/ != 0 &&
            /* re-read to see size returned by kernel */
            safe_read((void *)&arg[5], sizeof(arg[5]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen)) {
            /* If not enough space kernel writes space needed */
            size_t len = (val_socklen <= pt->sysarg[3]) ? val_socklen : pt->sysarg[3];
            check_sockaddr((app_pc)pt->sysarg[2], len, MEMREF_WRITE, mc, "recvfrom addr");
        }
        break;
    case SYS_GETSOCKOPT:
        if (pt->sysarg[3]/*pre-optlen*/ > 0 && pt->sysarg[2]/*optval*/ != 0 &&
            /* re-read to see size returned by kernel */
            safe_read((void *)&arg[4], sizeof(arg[4]), &ptr2) &&
            safe_read(ptr2, sizeof(val_socklen), &val_socklen)) {
            /* Not sure what kernel does on truncation so being safe */
            size_t len = (val_socklen <= pt->sysarg[3]) ? val_socklen : pt->sysarg[3];
            check_sysmem(MEMREF_WRITE, SYS_socketcall,
                         (app_pc)pt->sysarg[2], len, mc, "getsockopt");
        }
        break;
    case SYS_RECVMSG: {
        struct msghdr *msg = (struct msghdr *) pt->sysarg[2];
        if (msg != NULL) { /* if NULL, error on safe_read in pre */
            struct iovec *iov;
            size_t len;
            check_sysmem(MEMREF_WRITE, SYS_socketcall, (app_pc)&msg->msg_flags,
                         sizeof(msg->msg_flags), mc, "recvmsg msg_flags");
            if (safe_read(&msg->msg_iov, sizeof(msg->msg_iov), &iov) &&
                safe_read(&msg->msg_iovlen, sizeof(msg->msg_iovlen), &len) &&
                iov != NULL) {
                check_iov(iov, len, result, MEMREF_WRITE, SYS_socketcall, mc,
                          "recvmsg iov");
            }
            /* re-read to see size returned by kernel */
            if (safe_read(&msg->msg_controllen, sizeof(msg->msg_controllen),
                          &val_socklen)) {
                /* Not sure what kernel does on truncation so being safe */
                size_t len = (val_socklen <= pt->sysarg[4]) ? val_socklen : pt->sysarg[4];
                check_sysmem(MEMREF_WRITE, SYS_socketcall,
                             (app_pc)&msg->msg_controllen, sizeof(msg->msg_controllen),
                             mc, "recvmsg msg_controllen");
                if (pt->sysarg[3]/*msg_control*/ != 0 && len > 0) {
                    check_sysmem(MEMREF_WRITE, SYS_socketcall,
                                 (app_pc)pt->sysarg[3]/*msg_control*/, len, mc,
                                 "recvmsg msg_control");
                } else
                    ASSERT(len == 0, "msg w/ no data can't have non-zero len!");
            }
        }
        break;
    }
    }
}

static uint
ipc_sem_len(int semid)
{
    struct semid_ds ds;
    union semun ctlarg;
    ctlarg.buf = &ds;
    /* FIXME PR 519781: not tested! */
    if (raw_syscall_5args(SYS_ipc, SEMCTL, semid, 0, IPC_STAT, (ptr_int_t)&ctlarg) < 0)
        return 0;
    else
        return ds.sem_nsems;
}

static void
handle_pre_ipc(void *drcontext, dr_mcontext_t *mc)
{
    uint request = (uint) dr_syscall_get_param(drcontext, 0);
    int arg1 = (int) dr_syscall_get_param(drcontext, 1);
    int arg2 = (int) dr_syscall_get_param(drcontext, 2);
    int arg3 = (int) dr_syscall_get_param(drcontext, 3);
    ptr_uint_t *ptr = (ptr_uint_t *) dr_syscall_get_param(drcontext, 4);
    ptr_int_t arg5 = (int) dr_syscall_get_param(drcontext, 5);
    /* They all use param #0, which is checked via table specifying 1 arg */
    switch (request) {
    case SEMTIMEDOP:
        /* int semtimedop(int semid, struct sembuf *sops, unsigned nsops,
         *                struct timespec *timeout)
         */
        check_sysparam_defined(SYS_ipc, 5, mc, sizeof(reg_t));
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_ipc,
                     (app_pc) arg5, sizeof(struct timespec), mc, "semtimedop");
        /* fall-through */
    case SEMOP:
        /* int semop(int semid, struct sembuf *sops, unsigned nsops) */
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_ipc,
                     (app_pc) ptr, arg2*sizeof(struct sembuf), mc, "semop");
        break;
    case SEMGET: /* nothing */
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 3, mc, sizeof(reg_t));
        break;
    case SEMCTL: {
        /* int semctl(int semid, int semnum, int cmd, ...) */
        /* ptr is not always used but we declare up here */
        union semun arg = *(union semun *)&ptr;
        /* strip out the version flag or-ed in by libc */
        uint cmd = arg3 & (~IPC_64);
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 3, mc, sizeof(reg_t));
        switch (cmd) {
        case IPC_SET:
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_ipc, (app_pc) arg.buf,
                         sizeof(struct semid_ds), mc, "semctl ipc_set");
            break;
        case IPC_STAT:
        case SEM_STAT:
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            check_sysmem(MEMREF_WRITE, SYS_ipc, (app_pc) arg.buf,
                         sizeof(struct semid_ds), mc,
                         (cmd == IPC_STAT) ? "semctl ipc_stat" : "semctl sem_stat");
            break;
        case IPC_RMID: /* nothing further */
            break;
        case IPC_INFO:
        case SEM_INFO:
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            check_sysmem(MEMREF_WRITE, SYS_ipc, (app_pc) arg.__buf,
                         sizeof(struct seminfo), mc,
                         (cmd == IPC_INFO) ? "semctl ipc_info" : "semctl sem_info");
            break;
        case GETALL: {
            /* we must query to get the length of arg.array */
            uint semlen = ipc_sem_len(arg1);
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            check_sysmem(MEMREF_WRITE, SYS_ipc, (app_pc) arg.array,
                         semlen*sizeof(short), mc, "semctl getall");
            break;
        }
        case SETALL: {
            /* we must query to get the length of arg.array */
            uint semlen = ipc_sem_len(arg1);
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_ipc, (app_pc) arg.array,
                         semlen*sizeof(short), mc, "semctl setall");
            break;
        }
        case GETNCNT:
        case GETZCNT:
        case GETPID:
        case GETVAL:
            check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
            break;
        case SETVAL:
            check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            break;
        default:
            ELOGF(0, f_global, "WARNING: unknown SEMCTL request %d\n", cmd); 
            IF_DEBUG(report_callstack(drcontext, mc);)
            break;
        }
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
        break;
    }
    case MSGSND: {
        /* int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg) */
        struct msgbuf *buf = (struct msgbuf *) ptr;
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t)); /* msqid */
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t)); /* msgsz */
        check_sysparam_defined(SYS_ipc, 3, mc, sizeof(reg_t)); /* msgflg */
        check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t)); /* msgp */
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_ipc,
                     (app_pc) &buf->mtype, sizeof(buf->mtype), mc, "msgsnd mtype");
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_ipc,
                     (app_pc) &buf->mtext, arg2, mc, "msgsnd mtext");
        break;
    }
    case MSGRCV: {
        /* ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp,
         *                int msgflg)
         */
        struct msgbuf *buf = (struct msgbuf *) ptr;
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t)); /* msqid */
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t)); /* msgsz */
        check_sysparam_defined(SYS_ipc, 3, mc, sizeof(reg_t)); /* msgflg */
        check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t)); /* msgp */
        check_sysparam_defined(SYS_ipc, 5, mc, sizeof(reg_t)); /* msgtyp */
        /* write to ptr arg handled in post where we know the size */
        check_sysmem(MEMREF_CHECK_ADDRESSABLE, SYS_ipc,
                     (app_pc) &buf->mtype, sizeof(buf->mtype), mc, "msgrcv mtype");
        check_sysmem(MEMREF_CHECK_ADDRESSABLE, SYS_ipc,
                     (app_pc) &buf->mtext, arg2, mc, "msgrcv mtext");
        break;
    }
    case MSGGET:
        /* int msgget(key_t key, int msgflg) */
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
        break;
    case MSGCTL: {
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
        switch (arg2) {
	case IPC_INFO:
	case MSG_INFO: {
            struct msginfo *buf = (struct msginfo *) ptr;
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            /* not all fields are set but we simplify */
            check_sysmem(MEMREF_WRITE, SYS_ipc,
                         (app_pc) buf, sizeof(*buf), mc,
                         (arg2 == IPC_INFO) ? "msgctl ipc_info" : "msgctl msg_info");
            break;
        }
	case IPC_STAT:
	case MSG_STAT: {
            struct msqid_ds *buf = (struct msqid_ds *) ptr;
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            check_sysmem(MEMREF_WRITE, SYS_ipc,
                         (app_pc) buf, sizeof(*buf), mc,
                         (arg2 == IPC_STAT) ?  "msgctl ipc_stat" : "msgctl msg_stat");
            break;
        }
	case IPC_SET: {
            struct msqid_ds *buf = (struct msqid_ds *) ptr;
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            /* not all fields are read but we simplify */
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_ipc,
                         (app_pc) buf, sizeof(*buf), mc, "msgctl ipc_set");
            break;
        }
	case IPC_RMID: /* nothing further to do */
            break;
        default:
            ELOGF(0, f_global, "WARNING: unknown MSGCTL request %d\n", arg2); 
            IF_DEBUG(report_callstack(drcontext, mc);)
            break;
        }
        break;
    }
    case SHMAT:
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
        /* FIXME: this should be treated as a new mmap by DR? */
        break;
    case SHMDT:
        check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
        break;
    case SHMGET:
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 3, mc, sizeof(reg_t));
        break;
    case SHMCTL: {
        check_sysparam_defined(SYS_ipc, 1, mc, sizeof(reg_t));
        check_sysparam_defined(SYS_ipc, 2, mc, sizeof(reg_t));
        switch (arg2) {
	case IPC_INFO:
	case SHM_INFO: {
            struct shminfo *buf = (struct shminfo *) ptr;
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            /* not all fields are set but we simplify */
            check_sysmem(MEMREF_WRITE, SYS_ipc,
                         (app_pc) buf, sizeof(*buf), mc,  "shmctl ipc_info");
            break;
        }
	case IPC_STAT:
	case SHM_STAT: {
            struct shmid_ds *buf = (struct shmid_ds *) ptr;
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            check_sysmem(MEMREF_WRITE, SYS_ipc,
                         (app_pc) buf, sizeof(*buf), mc,
                         (arg2 == IPC_STAT) ? "shmctl ipc_stat" : "shmctl shm_stat");
            break;
        }
	case IPC_SET: {
            struct shmid_ds *buf = (struct shmid_ds *) ptr;
            check_sysparam_defined(SYS_ipc, 4, mc, sizeof(reg_t));
            /* not all fields are read but we simplify */
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, SYS_ipc,
                         (app_pc) buf, sizeof(*buf), mc, "shmctl ipc_set");
            break;
        }
        case IPC_RMID: /* nothing further to do */
            break;
        default:
            ELOGF(0, f_global, "WARNING: unknown SHMCTL request %d\n", arg2); 
            IF_DEBUG(report_callstack(drcontext, mc);)
            break;
        }
        break;
    }
    default:
        ELOGF(0, f_global, "WARNING: unknown ipc request %d\n", request); 
        IF_DEBUG(report_callstack(drcontext, mc);)
        break;
    }
}

static void
handle_post_ipc(void *drcontext, dr_mcontext_t *mc)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    uint request = (uint) pt->sysarg[0];
    ptr_uint_t *ptr = (ptr_uint_t *) pt->sysarg[4];
    ptr_int_t result = dr_syscall_get_result(drcontext);
    switch (request) {
    case MSGRCV:
        if (result >= 0) {
            struct msgbuf *buf = (struct msgbuf *) ptr;
            check_sysmem(MEMREF_WRITE, SYS_ipc,
                         (app_pc) &buf->mtype, sizeof(buf->mtype), mc, "msgrcv mtype");
            check_sysmem(MEMREF_WRITE, SYS_ipc,
                         (app_pc) &buf->mtext, (size_t) result, mc, "msgrcv mtext");
        }
        break;
    }
}

/* handles both select and pselect6 */
static void
handle_pre_select(void *drcontext, dr_mcontext_t *mc, int sysnum)
{
    int nfds = (int) dr_syscall_get_param(drcontext, 0);
    /* Only special-cased b/c the size is special: one bit each.
     * No post-syscall action needed b/c no writes to previously-undef mem.
     */
    size_t sz = nfds / 8; /* 8 bits per byte, size is in bytes */
    app_pc ptr = (app_pc) dr_syscall_get_param(drcontext, 1);
    if (ptr != NULL)
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, ptr, sz, mc, "select readfds");
    ptr = (app_pc) dr_syscall_get_param(drcontext, 2);
    if (ptr != NULL)
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, ptr, sz, mc, "select writefds");
    ptr = (app_pc) dr_syscall_get_param(drcontext, 3);
    if (ptr != NULL) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, ptr, sz, mc, "select exceptfds");
    }
    ptr = (app_pc) dr_syscall_get_param(drcontext, 4);
    if (ptr != NULL) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, ptr,
                     (sysnum == SYS_select ? 
                      sizeof(struct timeval) : sizeof(struct timespec)), mc,
                     "select timeout");
    }
    if (sysnum == SYS_pselect6) {
        ptr = (app_pc) dr_syscall_get_param(drcontext, 5);
        if (ptr != NULL) {
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, ptr,
                         sizeof(kernel_sigset_t), mc, "pselect sigmask");
        }
    }
}

#define PRCTL_NAME_SZ 16 /* from man page */

static void
check_prctl_whitelist(byte *prctl_arg1)
{
    /* disable instrumentation on seeing prctl(PR_SET_NAME) that does not
     * match any of the specified ,-separated names (PR 574018)
     */
    char nm[PRCTL_NAME_SZ+1];
    ASSERT(options.prctl_whitelist[0] != '\0', "caller should check for empty op");
    if (safe_read(prctl_arg1, PRCTL_NAME_SZ, nm)) {
        bool on_whitelist = false;
        char *s, *next;
        char *list_end = options.prctl_whitelist + strlen(options.prctl_whitelist);
        size_t white_sz;
        NULL_TERMINATE_BUFFER(nm);
        LOG(1, "prctl set name %s\n", nm);
        s = options.prctl_whitelist;
        while (s < list_end) {
            next = strchr(s, ',');
            if (next == NULL)
                white_sz = (list_end - s);
            else
                white_sz = (next - s);
            LOG(2, "comparing \"%s\" with whitelist entry \"%.*s\" sz=%d\n",
                nm, white_sz, s, white_sz);
            if (strncmp(nm, s, white_sz) == 0) {
                LOG(0, "prctl name %s matches whitelist\n", nm);
                on_whitelist = true;
                break;
            }
            s += white_sz + 1 /* skip , itself */;
        }
        if (!on_whitelist) {
            /* ideally: suspend world, then set options, then flush
             * w/o resuming.
             * FIXME: just setting options is unsafe if another thread
             * hits an event and fails to restore state or sthg.
             * Fortunately we expect most uses of PR_SET_NAME to be
             * immediately after forking.
             * Ideally we'd call dr_suspend_all_other_threads()
             * and nest dr_flush_region() inside it but both want
             * the same master lock: should check whether easy to support
             * via internal vars indicating whether lock held.
             */
            ELOGF(0, f_global, "\n*********\nDISABLING MEMORY CHECKING for %s\n", nm);
            options.shadowing = false;
            dr_flush_region(0, ~((ptr_uint_t)0));
        }
    }
}

static void
handle_pre_prctl(void *drcontext, dr_mcontext_t *mc)
{
    uint request = (uint) dr_syscall_get_param(drcontext, 0);
    ptr_int_t arg1 = (ptr_int_t) dr_syscall_get_param(drcontext, 1);
    /* They all use param #0, which is checked via table specifying 1 arg.
     * Officially it's a 5-arg syscall but so far nothing using beyond 2 args.
     */
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
        check_sysparam_defined(SYS_prctl, 1, mc, sizeof(reg_t));
        break;
    case PR_GET_PDEATHSIG:
    case PR_GET_UNALIGN:
    case PR_GET_FPEMU:
    case PR_GET_FPEXC:
    case PR_GET_TSC:
    case PR_GET_ENDIAN:
        check_sysparam_defined(SYS_prctl, 1, mc, sizeof(reg_t));
        check_sysmem(MEMREF_CHECK_ADDRESSABLE, SYS_prctl,
                     (app_pc) arg1, sizeof(int), mc, NULL);
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
        check_sysparam_defined(SYS_prctl, 1, mc, sizeof(reg_t));
        check_sysmem((request == PR_GET_NAME) ? MEMREF_CHECK_ADDRESSABLE :
                     MEMREF_CHECK_DEFINEDNESS, SYS_prctl,
                     (app_pc) arg1, PRCTL_NAME_SZ, mc, NULL);
        if (request == PR_SET_NAME && options.prctl_whitelist[0] != '\0')
            check_prctl_whitelist((byte *)arg1);
        break;
    default:
        ELOGF(0, f_global, "WARNING: unknown prctl request %d\n", request); 
        IF_DEBUG(report_callstack(drcontext, mc);)
        break;
    }
}

static void
handle_post_prctl(void *drcontext, dr_mcontext_t *mc)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
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
            check_sysmem(MEMREF_WRITE, SYS_prctl,
                         (app_pc) pt->sysarg[1], sizeof(int), mc, NULL);
        }
        break;
    case PR_GET_NAME:
        /* FIXME PR 408539: actually only writes up to null char */
        check_sysmem(MEMREF_WRITE, SYS_prctl,
                     (app_pc) pt->sysarg[1], PRCTL_NAME_SZ, mc, NULL);
        break;
    }
}

static void
handle_pre_execve(void *drcontext)
{
    /* PR 453867: tell postprocess.pl to watch for new logdir and
     * fork a new copy.
     * FIXME: what if syscall fails?  Punting on that for now.
     * Note that if it fails and then a later one succeeds, postprocess.pl
     * will replace the first with the last.
     */
    char logdir[MAXIMUM_PATH]; /* one reason we're not inside os_post_syscall() */
    size_t bytes_read = 0;
    /* Not using safe_read() since we want a partial read if hits page boundary */
    if (dr_safe_read((void *) dr_syscall_get_param(drcontext, 0),
                     BUFFER_SIZE_BYTES(logdir), logdir, &bytes_read)) {
        if (bytes_read < BUFFER_SIZE_BYTES(logdir))
            logdir[bytes_read] = '\0';
        NULL_TERMINATE_BUFFER(logdir);
        ELOGF(0, f_fork, "EXEC path=%s\n", logdir);
    }
}

/* for tasks unrelated to shadowing that are common to all tools */
bool
os_shared_pre_syscall(void *drcontext, int sysnum)
{
    bool res = true;
    dr_mcontext_t mc;
    dr_get_mcontext(drcontext, &mc, NULL);
    switch (sysnum) {
    case SYS_close: {
        /* we assume that file_t is the same type+namespace as kernel fd */
        uint fd = dr_syscall_get_param(drcontext, 0);
        if (hashtable_lookup(&logfile_table, (void*)fd) != NULL) {
            /* don't let app close our files */
            LOG(0, "WARNING: app trying to close our file %d\n", fd);
            dr_syscall_set_result(drcontext, -EBADF);
            res = false; /* do NOT execute syscall */
        }
        break;
    }
    case SYS_execve:
        handle_pre_execve(drcontext);
        break;
    }
    return res;
}

/* for tasks unrelated to shadowing that are common to all tools */
void
os_shared_post_syscall(void *drcontext, int sysnum)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    switch (sysnum) {
    case SYS_clone: {
        uint flags = (uint) pt->sysarg[0];
        if (TEST(CLONE_VM, flags))
            break;
        /* else, fall through */
    }
    case SYS_fork: {
        /* PR 453867: tell postprocess.pl to not exit until it sees a message
         * from the child starting up.
         */
        process_id_t child = dr_syscall_get_result(drcontext);
        if (child != 0)
            ELOGF(0, f_fork, "FORK child=%d\n", child);
        break;
    }
    }
}

bool
os_shadow_pre_syscall(void *drcontext, int sysnum)
{
    bool res = true;
    dr_mcontext_t mc;
    dr_get_mcontext(drcontext, &mc, NULL);
    switch (sysnum) {
    case SYS_clone: 
        handle_clone(drcontext, &mc); 
        break;
    case SYS__sysctl: {
        struct __sysctl_args *args = (struct __sysctl_args *)
            dr_syscall_get_param(drcontext, 0);
        if (args != NULL) {
            /* just doing reads here: writes in post */
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                         (app_pc) args->name, args->nlen*sizeof(int), &mc, NULL);
            if (args->newval != NULL) {
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                             (app_pc) args->newval, args->newlen, &mc, NULL);
            }
        }
        break;
    }
    case SYS_mremap: {
        /* 5th arg is conditionally valid */
        int flags = (int) dr_syscall_get_param(drcontext, 3);
        if (TEST(MREMAP_FIXED, flags))
            check_sysparam_defined(sysnum, 4, &mc, sizeof(reg_t));
        break;
    }
    case SYS_open: {
        /* 3rd arg is sometimes required.  glibc open() wrapper passes
         * a constant 0 as mode if no O_CREAT, but opendir() bypasses
         * that wrapper (PR 488597).
         */
        int flags = (int) dr_syscall_get_param(drcontext, 1);
        if (TEST(O_CREAT, flags))
            check_sysparam_defined(sysnum, 2, &mc, sizeof(reg_t));
        break;
    }
    case SYS_fcntl:
    case SYS_fcntl64: {
        /* 3rd arg is sometimes required.  Note that SYS_open has a similar
         * situation but we don't yet bother to special-case b/c glibc passes
         * a constant 0 as mode if no O_CREAT: yet fcntl glibc routine
         * blindly reads 3rd arg regardless of 2nd.
         */
        int cmd = (int) dr_syscall_get_param(drcontext, 1);
        /* Some kernels add custom cmds, so error on side of false pos
         * rather than false neg via negative checks
         */
        if (cmd != F_GETFD && cmd != F_GETFL && cmd != F_GETOWN
#ifdef __USE_GNU
            && cmd != F_GETSIG && cmd != F_GETLEASE
#endif
            )
            check_sysparam_defined(sysnum, 2, &mc, sizeof(reg_t));
        }
        break;
    case SYS_ioctl: 
        handle_pre_ioctl(drcontext, &mc); 
        break;
    case SYS_socketcall: 
        handle_pre_socketcall(drcontext, &mc); 
        break;
    case SYS_ipc: 
        handle_pre_ipc(drcontext, &mc); 
        break;
    case SYS_select: /* fall-through */
    case SYS_pselect6:
        handle_pre_select(drcontext, &mc, sysnum);
        break;
    case SYS_poll: {
        struct pollfd *fds = (struct pollfd *) dr_syscall_get_param(drcontext, 0);
        nfds_t nfds = (nfds_t) dr_syscall_get_param(drcontext, 1);
        if (fds != NULL) {
            int i;
            for (i = 0; i < nfds; i++) {
                /* First fields are inputs, last is output */
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                             (app_pc) &fds[i], offsetof(struct pollfd, revents),
                             &mc, NULL);
                check_sysmem(MEMREF_WRITE, sysnum,
                             (app_pc) &fds[i].revents, sizeof(fds[i].revents),
                             &mc, NULL);
            }
        }
        break;
    }
    case SYS_prctl:
        handle_pre_prctl(drcontext, &mc);
        break;
    case SYS_rt_sigaction: {
        /* restorer field not always filled in.  we ignore the old (pre-2.1.68)
         * kernel sigaction struct layout.
         */
        kernel_sigaction_t *sa = (kernel_sigaction_t *)
            dr_syscall_get_param(drcontext, 1);
        if (sa != NULL) {
            if (TEST(SA_RESTORER, sa->flags)) {
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                             (app_pc) sa, sizeof(*sa), &mc, NULL);
            } else {
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                             (app_pc) sa, offsetof(kernel_sigaction_t, restorer),
                             &mc, NULL);
                /* skip restorer field */
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                             (app_pc) &sa->mask,
                             sizeof(*sa) - offsetof(kernel_sigaction_t, mask),
                             &mc, NULL);
            }
        }
        break;
    }
    case SYS_futex: {
        /* PR 479107: later args are optional */
        int op = (int) dr_syscall_get_param(drcontext, 1);
        if (op == FUTEX_WAKE || op == FUTEX_FD) {
            /* just the 3 params */
        } else if (op == FUTEX_WAIT) {
            struct timespec *timeout = (struct timespec *)
                dr_syscall_get_param(drcontext, 3);
            check_sysparam_defined(sysnum, 3, &mc, sizeof(reg_t));
            if (timeout != NULL) {
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                             (app_pc) timeout, sizeof(*timeout), &mc, NULL);
            }
        } else if (op == FUTEX_REQUEUE || op == FUTEX_CMP_REQUEUE) {
            check_sysparam_defined(sysnum, 4, &mc, sizeof(reg_t));
            if (op == FUTEX_CMP_REQUEUE)
                check_sysparam_defined(sysnum, 5, &mc, sizeof(reg_t));
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                         (app_pc) dr_syscall_get_param(drcontext, 4),
                         sizeof(uint), &mc, NULL);
        }
        break;
    }
    }
    return res; /* execute syscall */
}

void
os_shadow_post_syscall(void *drcontext, int sysnum)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    dr_mcontext_t mc;
    switch (sysnum) {
    case SYS__sysctl: {
        struct __sysctl_args *args = (struct __sysctl_args *) pt->sysarg[0];
        size_t len;
        dr_get_mcontext(drcontext, &mc, NULL); /* move up once have more cases */
        if (dr_syscall_get_result(drcontext) == 0 && args != NULL) {
            /* xref PR 408540: here we wait until post so we can use the
             * actual written size.  There could be races but they're
             * app errors, which we should report, right?
             */
            if (args->oldval != NULL && safe_read(args->oldlenp, sizeof(len), &len)) {
                check_sysmem(MEMREF_WRITE, sysnum, (app_pc) args->oldval, len, &mc, NULL);
            }
        }
        break;
    }
    case SYS_ioctl: 
        handle_post_ioctl(drcontext, &mc); 
        break;
    case SYS_socketcall: 
        handle_post_socketcall(drcontext, &mc); 
        break;
    case SYS_ipc: 
        handle_post_ipc(drcontext, &mc); 
        break;
    case SYS_prctl:
        handle_post_prctl(drcontext, &mc);
        break;
    };
}

bool
os_handle_pre_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                 const syscall_arg_t *arg_info,
                                 app_pc start, uint size)
{
    /* we use specific sysnum handlers in os_shadow_{pre,post}_syscall rather than
     * flags on the general syscall entry tables, so nothing to do here
     */
    return false;
}

bool
os_handle_post_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size)
{
    /* we use specific sysnum handlers in os_shadow_{pre,post}_syscall rather than
     * flags on the general syscall entry tables, so nothing to do here
     */
    return false;
}

