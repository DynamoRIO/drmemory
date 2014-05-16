/* **********************************************************
 * Copyright (c) 2010-2014 Google, Inc.  All rights reserved.
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
#include "linux_defines.h"
#include "table_defines.h"

extern syscall_info_t syscall_ioctl_info[];

/* Created from ./mksystable_linux.pl
 * And then manually:
 * - filling in params for those marked "Missing prototype"
 * - filling in params for those marked "special-case"
 * - replacing U with W or R
 * - updating sizeof(char) and sizeof(void)
 *
 * FIXME i#92: still a lot of missing details below!
 */

syscall_info_t syscall_info[] = {
    {{PACKNUM(219,0),0},"restart_syscall", OK, RLONG, 0,},
    {{PACKNUM(60,1),0},"exit", OK, RLONG, 1,},
    {{PACKNUM(57,2),0},"fork", OK, RLONG, 0,},
    {{PACKNUM(0,3),0},"read", OK, RLONG, 3,
     {
         {1, -2, W},
         {1, RET, W},
     }
    },
    {{PACKNUM(1,4),0},"write", OK, RLONG, 3,
     {
         {1, -2, R},
     }
    },
    {{PACKNUM(2,5),0},"open", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    }, /*special-cased: 3rd arg not always required*/
    {{PACKNUM(3,6),0},"close", OK, RLONG, 1,},
    {{PACKNUM(-1,7),0},"waitpid", OK, RLONG, 3,
     {
         {1, sizeof(int), W},
     }
    },
    {{PACKNUM(85,8),0},"creat", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(86,9),0},"link", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(87,10),0},"unlink", OK, RLONG, 1,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(59,11),0},"execve", OK, RLONG, 3,
     {
         {0, 0, R|CT, CSTRING},
         {1, sizeof(char **), R|CT, DRSYS_TYPE_CSTRARRAY},
         {2, sizeof(char **), R|CT, DRSYS_TYPE_CSTRARRAY},
     }
    },
    {{PACKNUM(80,12),0},"chdir", OK, RLONG, 1,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(201,13),0},"time", OK, RLONG, 1,
     {
         {0, sizeof(time_t), W},
     }
    },
    {{PACKNUM(133,14),0},"mknod", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(90,15),0},"chmod", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(-1,16),0},"lchown16", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(-1,17),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,18),0},"stat", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct __old_kernel_stat), W},
     }
    },
    {{PACKNUM(4,-1),0},"stat", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct stat), W},
     }
    },
    {{PACKNUM(8,19),0},"lseek", OK, RLONG, 3,},
    {{PACKNUM(39,20),0},"getpid", OK, RLONG, 0,},
    {{PACKNUM(165,21),0},"mount", OK, RLONG, 5,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
         {2,0, R|CT, CSTRING},/*FIXME: 4 varies: ignore for now*/
     }
    },
    {{PACKNUM(-1,22),0},"oldumount", OK, RLONG, 1,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(-1,23),0},"setuid16", OK, RLONG, 1,},
    {{PACKNUM(-1,24),0},"getuid16", OK, RLONG, 0,},
    {{PACKNUM(-1,25),0},"stime", OK, RLONG, 1,
     {
         {0, sizeof(time_t), R},
     }
    },
    {{PACKNUM(101,26),0},"ptrace", OK, RLONG, 4,},
    {{PACKNUM(37,27),0},"alarm", OK, RLONG, 1,},
    {{PACKNUM(-1,28),0},"fstat", OK, RLONG, 2,
     {
         {1, sizeof(struct __old_kernel_stat), W},
     }
    },
    {{PACKNUM(5,-1),0},"fstat", OK, RLONG, 2,
     {
         {1, sizeof(struct stat), W},
     }
    },
    {{PACKNUM(34,29),0},"pause", OK, RLONG, 0,},
    {{PACKNUM(132,30),0},"utime", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct utimbuf), R},
     }
    },
    {{PACKNUM(-1,31),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,32),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(21,33),0},"access", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(-1,34),0},"nice", OK, RLONG, 1,},
    {{PACKNUM(-1,35),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(162,36),0},"sync", OK, RLONG, 0,},
    {{PACKNUM(62,37),0},"kill", OK, RLONG, 2,},
    {{PACKNUM(82,38),0},"rename", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(83,39),0},"mkdir", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(84,40),0},"rmdir", OK, RLONG, 1,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(32,41),0},"dup", OK, RLONG, 1,},
    {{PACKNUM(22,42),0},"pipe", OK, RLONG, 1,
     {
         {0,2*sizeof(int), W},
     }
    },
    {{PACKNUM(100,43),0},"times", OK, RLONG, 1,
     {
         {0, sizeof(struct tms), W},
     }
    },
    {{PACKNUM(-1,44),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(12,45),0},"brk", OK, RLONG, 1,},
    {{PACKNUM(-1,46),0},"setgid16", OK, RLONG, 1,},
    {{PACKNUM(-1,47),0},"getgid16", OK, RLONG, 0,},
    {{PACKNUM(-1,48),0},"signal", OK, RLONG, 2,},
    {{PACKNUM(-1,49),0},"geteuid16", OK, RLONG, 0,},
    {{PACKNUM(-1,50),0},"getegid16", OK, RLONG, 0,},
    {{PACKNUM(163,51),0},"acct", OK, RLONG, 1,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(-1,52),0},"umount", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(-1,53),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(16,54),0},"ioctl", OK|SYSINFO_SECONDARY_TABLE, RLONG, 3,
     {
         {1,}  /* ioctl request number */
     }, (drsys_sysnum_t*)syscall_ioctl_info
    },
    {{PACKNUM(72,55),0},"fcntl", OK, RLONG, 2,}, /*special-cased: 3rd arg not always required*/
    {{PACKNUM(-1,56),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(109,57),0},"setpgid", OK, RLONG, 2,},
    {{PACKNUM(-1,58),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,59),0},"olduname", OK, RLONG, 1, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(95,60),0},"umask", OK, RLONG, 1,},
    {{PACKNUM(161,61),0},"chroot", OK, RLONG, 1,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(136,62),0},"ustat", OK, RLONG, 2,
     {
         {1, sizeof(struct ustat), W},
     }
    },
    {{PACKNUM(33,63),0},"dup2", OK, RLONG, 2,},
    {{PACKNUM(110,64),0},"getppid", OK, RLONG, 0,},
    {{PACKNUM(111,65),0},"getpgrp", OK, RLONG, 0,},
    {{PACKNUM(112,66),0},"setsid", OK, RLONG, 0,},
    {{PACKNUM(-1,67),0},"sigaction", OK, RLONG, 3,/*FIXME type: {{1, sizeof(struct old_sigaction), W}, {2, sizeof(struct old_sigaction), R},}*/},
    {{PACKNUM(-1,68),0},"sgetmask", OK, RLONG, 0,},
    {{PACKNUM(-1,69),0},"ssetmask", OK, RLONG, 1,},
    {{PACKNUM(-1,70),0},"setreuid16", OK, RLONG, 2,},
    {{PACKNUM(-1,71),0},"setregid16", OK, RLONG, 2,},
    {{PACKNUM(-1,72),0},"sigsuspend", OK, RLONG, 3,},
    {{PACKNUM(-1,73),0},"sigpending", OK, RLONG, 1,/*FIXME type: {{0, sizeof(old_sigset_t), W},}*/},
    {{PACKNUM(170,74),0},"sethostname", OK, RLONG, 2,
     {
         {0, -1, R},
     }
    },
    {{PACKNUM(160,75),0},"setrlimit", OK, RLONG, 2,
     {
         {1, sizeof(struct rlimit), R},
     }
    },
    {{PACKNUM(-1,76),0},"old_getrlimit", OK, RLONG, 2,
     {
         {1, sizeof(struct rlimit), W},
     }
    },
    {{PACKNUM(98,77),0},"getrusage", OK, RLONG, 2,
     {
         {1, sizeof(struct rusage), W},
     }
    },
    {{PACKNUM(96,78),0},"gettimeofday", OK, RLONG, 2,
     {
         {0, sizeof(struct timeval), W},
         {1, sizeof(struct timezone), W},
     }
    },
    {{PACKNUM(164,79),0},"settimeofday", OK, RLONG, 2,
     {
         {0, sizeof(struct timeval), R},
         {1, sizeof(struct timezone), R},
     }
    },
    {{PACKNUM(-1,80),0},"getgroups16", OK, RLONG, 2,/* FIXME how encode these: {{1, ARG1 * sizeof(vki_old_gid_t), W}, {1, RES * sizeof(vki_old_gid_t), W},}*/},
    {{PACKNUM(-1,81),0},"setgroups16", OK, RLONG, 2,/* FIXME how encode these:{{1, ARG1 * sizeof(vki_old_gid_t), R},}*/},
    {{PACKNUM(-1,82),0},"old_select", OK, RLONG, /*FIXME*/},
    {{PACKNUM(88,83),0},"symlink", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(-1,84),0},"lstat", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct __old_kernel_stat), W},
     }
    },
    {{PACKNUM(6,-1),0},"lstat", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct stat), W},
     }
    },
    {{PACKNUM(89,85),0},"readlink", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
         {1, -2, W},
         {1, RET, W},
     }
    },
    {{PACKNUM(134,86),0},"uselib", OK, RLONG, 1,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(167,87),0},"swapon", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(169,88),0},"reboot", OK, RLONG, 4, /*FIXME: 3 is optional*/},
    {{PACKNUM(-1,89),0},"old_readdir", OK, RLONG, 3,/*FIXME type: {{1, sizeof(struct old_linux_dirent), W},}*/},
    {{PACKNUM(-1,90),0},"mmap", OK, RLONG, /*FIXME*/},
    {{PACKNUM(11,91),0},"munmap", OK, RLONG, 2,},
    /* XXX i#822: for framework w/ inlined types we'll need separate x64 entries */
    {{PACKNUM(76,92),0},"truncate", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    /* XXX i#822: for framework w/ inlined types we'll need separate x64 entries */
    {{PACKNUM(77,93),0},"ftruncate", OK, RLONG, 2,},
    {{PACKNUM(91,94),0},"fchmod", OK, RLONG, 2,},
    {{PACKNUM(-1,95),0},"fchown16", OK, RLONG, 3,},
    {{PACKNUM(140,96),0},"getpriority", OK, RLONG, 2,},
    {{PACKNUM(141,97),0},"setpriority", OK, RLONG, 3,},
    {{PACKNUM(-1,98),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(137,99),0},"statfs", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct statfs), W},
     }
    },
    {{PACKNUM(138,100),0},"fstatfs", OK, RLONG, 2,
     {
         {1, sizeof(struct statfs), W},
     }
    },
    {{PACKNUM(173,101),0},"ioperm", OK, RLONG, 3,},
    {{PACKNUM(-1,102),0},"socketcall", OK, RLONG, 2, /* special-cased below */},
    {{PACKNUM(103,103),0},"syslog", OK, RLONG, 3,
     {
         {1, -2, W},
     }
    },
    {{PACKNUM(38,104),0},"setitimer", OK, RLONG, 3,
     {
         {1, sizeof(struct itimerval), R},
         {2, sizeof(struct itimerval), W},
     }
    },
    {{PACKNUM(36,105),0},"getitimer", OK, RLONG, 2,
     {
         {1, sizeof(struct itimerval), W},
     }
    },
    {{PACKNUM(-1,106),0},"newstat", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct stat), W},
     }
    },
    {{PACKNUM(-1,107),0},"newlstat", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct stat), W},
     }
    },
    {{PACKNUM(-1,108),0},"newfstat", OK, RLONG, 2,
     {
         {1, sizeof(struct stat), W},
     }
    },
    {{PACKNUM(63,109),0},"uname", OK, RLONG, 1, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(172,110),0},"iopl", OK, RLONG, 1,},
    {{PACKNUM(153,111),0},"vhangup", OK, RLONG, 0,},
    {{PACKNUM(-1,112),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,113),0},"vm86old", OK, RLONG, 1, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(61,114),0},"wait4", OK, RLONG, 4,
     {
         {1, sizeof(int), W},
         {3, sizeof(struct rusage), W},
     }
    },
    {{PACKNUM(168,115),0},"swapoff", OK, RLONG, 1,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(99,116),0},"sysinfo", OK, RLONG, 1,
     {
         {0, sizeof(struct sysinfo), W},
     }
    },
    {{PACKNUM(-1,117),0},"ipc", OK, RLONG, 1, /* special-cased below */ },
    {{PACKNUM(74,118),0},"fsync", OK, RLONG, 1,},
    {{PACKNUM(-1,119),0},"sigreturn", OK, RLONG, 0},
    {{PACKNUM(56,120),0},"clone", OK, RLONG, 2,}, /* 3 params added in later kernels special-cased */
    {{PACKNUM(171,121),0},"setdomainname", OK, RLONG, 2,
     {
         {0, -1, R},
     }
    },
    {{PACKNUM(-1,122),0},"newuname", OK, RLONG, 1,
     {
         {0, sizeof(struct new_utsname), W},
     }
    },
    {{PACKNUM(154,123),0},"modify_ldt", OK, RLONG, 3, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(159,124),0},"adjtimex", OK, RLONG, 1,
     {
         {0, sizeof(struct timex), R},
     }
    },
    {{PACKNUM(10,125),0},"mprotect", OK, RLONG, 3,},
    {{PACKNUM(-1,126),0},"sigprocmask", OK, RLONG, 3,/*FIXME type: {{1, sizeof(old_sigset_t), R}, {2, sizeof(old_sigset_t), W},}*/},
    {{PACKNUM(-1,127),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(175,128),0},"init_module", OK, RLONG, 3,
     {
         {0, -1, R},
         {2,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(176,129),0},"delete_module", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(-1,130),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(179,131),0},"quotactl", OK, RLONG, 4,
     {
         {1,0, R|CT, CSTRING}, /* FIXME: #3 varies */
     }
    },
    {{PACKNUM(121,132),0},"getpgid", OK, RLONG, 1,},
    {{PACKNUM(81,133),0},"fchdir", OK, RLONG, 1,},
    {{PACKNUM(-1,134),0},"bdflush", OK, RLONG, 2,},
    {{PACKNUM(139,135),0},"sysfs", OK, RLONG, 3,},
    {{PACKNUM(135,136),0},"personality", OK, RLONG, 1,},
    {{PACKNUM(-1,137),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,138),0},"setfsuid16", OK, RLONG, 1,},
    {{PACKNUM(-1,139),0},"setfsgid16", OK, RLONG, 1,},
    {{PACKNUM(-1,140),0},"llseek", OK, RLONG, 5,
     {
         {3, sizeof(loff_t), W},
     }
    },
    {{PACKNUM(78,141),0},"getdents", OK, RLONG, 3,
     {
         {1, -2, W},
         {1, RET, W},
     }
    },
    {{PACKNUM(23,142),0},"select", OK, RLONG, 5,/* special-cased below */},
    {{PACKNUM(73,143),0},"flock", OK, RLONG, 2,},
    {{PACKNUM(26,144),0},"msync", OK, RLONG, 3,
     {
         {0, -1, R},
     }
    },
    {{PACKNUM(19,145),0},"readv", OK, RLONG, 3, /* FIXME 1, ARG3 * sizeof(struct vki_iovec), R, 1,****** special-case:  (Addr)vec[i].iov_base, nReadThisBuf, R, */},
    {{PACKNUM(20,146),0},"writev", OK, RLONG, 3, /* FIXME 1, ARG3 * sizeof(struct vki_iovec), R, 1,****** special-case:  "writev(vector[...])", OK, RLONG, (Addr)vec[i].iov_base, vec[i].iov_len, R, */},
    {{PACKNUM(124,147),0},"getsid", OK, RLONG, 1,},
    {{PACKNUM(75,148),0},"fdatasync", OK, RLONG, 1,},
    {{PACKNUM(156,149),0},"_sysctl", OK, RLONG, 1,
     {
         {0, sizeof(struct __sysctl_args), R},
     }
    },/*special-cased*/
    {{PACKNUM(149,150),0},"mlock", OK, RLONG, 2,},
    {{PACKNUM(150,151),0},"munlock", OK, RLONG, 2,},
    {{PACKNUM(151,152),0},"mlockall", OK, RLONG, 1,},
    {{PACKNUM(152,153),0},"munlockall", OK, RLONG, 0,},
    {{PACKNUM(142,154),0},"sched_setparam", OK, RLONG, 2,
     {
         {1, sizeof(struct sched_param), R},
     }
    },
    {{PACKNUM(143,155),0},"sched_getparam", OK, RLONG, 2,
     {
         {1, sizeof(struct sched_param), W},
     }
    },
    {{PACKNUM(144,156),0},"sched_setscheduler", OK, RLONG, 3,
     {
         {2, sizeof(struct sched_param), R},
     }
    },
    {{PACKNUM(145,157),0},"sched_getscheduler", OK, RLONG, 1,},
    {{PACKNUM(24,158),0},"sched_yield", OK, RLONG, 0,},
    {{PACKNUM(146,159),0},"sched_get_priority_max", OK, RLONG, 1,},
    {{PACKNUM(147,160),0},"sched_get_priority_min", OK, RLONG, 1,},
    {{PACKNUM(148,161),0},"sched_rr_get_interval", OK, RLONG, 2, /* FIXME  1, sizeof(struct timespec), U, */},
    {{PACKNUM(35,162),0},"nanosleep", OK, RLONG, 2,
     {
         {0, sizeof(struct timespec), R},
         {1, sizeof(struct timespec), W},
     }
    },
    {{PACKNUM(25,163),0},"mremap", OK, RLONG, 4,}, /* 5th arg is conditional so special-cased below */
    {{PACKNUM(-1,164),0},"setresuid16", OK, RLONG, 3,},
    {{PACKNUM(-1,165),0},"getresuid16", OK, RLONG, 3,/*FIXME type: {{0, sizeof(old_uid_t), W}, {1, sizeof(old_uid_t), W}, {2, sizeof(old_uid_t), W},}*/},
    {{PACKNUM(-1,166),0},"vm86", OK, RLONG, 2, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(-1,167),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(7,168),0},"poll", OK, RLONG, 3, /* special-cased below */},
    {{PACKNUM(180,169),0},"nfsservctl", OK, RLONG, 3, /* FIXME 1, sizeof(struct nfsctl_arg), U, 2, sizeof(void), U, */},
    {{PACKNUM(-1,170),0},"setresgid16", OK, RLONG, 3,},
    {{PACKNUM(-1,171),0},"getresgid16", OK, RLONG, 3,/*FIXME type: {{0, sizeof(old_gid_t), W}, {1, sizeof(old_gid_t), W}, {2, sizeof(old_gid_t), W},}*/},
    {{PACKNUM(157,172),0},"prctl", OK, RLONG, 1, /* special-cased below */},
    {{PACKNUM(15,173),0},"rt_sigreturn", OK, RLONG, 0},
    {{PACKNUM(13,174),0},"rt_sigaction", OK, RLONG, 4,/*1 is special-cased below*/{{2, sizeof(kernel_sigaction_t), W},
     }
    },
    {{PACKNUM(14,175),0},"rt_sigprocmask", OK, RLONG, 4,
     {
         {1, sizeof(kernel_sigset_t), R},
         {2, sizeof(kernel_sigset_t), W},
     }
    },
    {{PACKNUM(127,176),0},"rt_sigpending", OK, RLONG, 2,
     {
         {0, sizeof(kernel_sigset_t), W},
     }
    },
    {{PACKNUM(128,177),0},"rt_sigtimedwait", OK, RLONG, 4,
     {
         {0, sizeof(kernel_sigset_t), R},
         {1, sizeof(siginfo_t), W},
         {2, sizeof(struct timespec), R},
     }
    },
    {{PACKNUM(129,178),0},"rt_sigqueueinfo", OK, RLONG, 3,
     {
         {2, sizeof(siginfo_t), R},
     }
    },
    {{PACKNUM(130,179),0},"rt_sigsuspend", OK, RLONG, 2, /* FIXME 0, sizeof(siginfo_t), R, 0,****** special-case:  arg2, sizeof(struct vki_msqid64_ds), R, */},
    {{PACKNUM(17,180),0},"pread64", OK, RLONG, 4,
     {
         {1, -2, W},
         {1, RET, W},
     }
    },
    {{PACKNUM(18,181),0},"pwrite64", OK, RLONG, 4,
     {
         {1, -2, R},
     }
    },
    {{PACKNUM(-1,182),0},"chown16", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(79,183),0},"getcwd", OK, RLONG, 2,
     {
         {0, -1, W},
         {0, RET, W},
     }
    },
    {{PACKNUM(125,184),0},"capget", OK, RLONG, 2,
     {
         {0, sizeof(cap_user_header_t), R},
         {1, sizeof(cap_user_data_t), W},
     }
    },
    {{PACKNUM(126,185),0},"capset", OK, RLONG, 2,
     {
         {0, sizeof(cap_user_header_t), R},
         {1, sizeof(cap_user_data_t), R},
     }
    },
    {{PACKNUM(131,186),0},"sigaltstack", OK, RLONG, 2, /* FIXME 0,****** special-case:  "sigaltstack(ss)", OK, RLONG, (Addr)&ss->ss_sp, sizeof(ss->ss_sp), R, 0,****** special-case:  "sigaltstack(ss)", OK, RLONG, (Addr)&ss->ss_size, sizeof(ss->ss_size), R, {1, sizeof(cap_user_data_t data), W}, */},
    {{PACKNUM(40,187),0},"sendfile", OK, RLONG, 4,
     {
         {2, sizeof(off_t), W},
     }
    },
    {{PACKNUM(-1,188),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,189),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(58,190),0},"vfork", OK, RLONG, 0,},
    {{PACKNUM(97,191),0},"getrlimit", OK, RLONG, 2,
     {
         {1, sizeof(struct rlimit), W},
     }
    },
    {{PACKNUM(-1,192),0},"mmap2", OK, RLONG, 6,},
    {{PACKNUM(9,-1),0},  "mmap",  OK, RLONG, 6,},
    {{PACKNUM(-1,193),0},"truncate64", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(-1,194),0},"ftruncate64", OK, RLONG, 2,},
#ifndef X64
    /* XXX i#1013: we'll need our own defs of stat64 for mixed-mode */
    {{PACKNUM(-1,195),0},"stat64", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct stat64), W},
     }
    },
    {{PACKNUM(-1,196),0},"lstat64", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1, sizeof(struct stat64), W},
     }
    },
    {{PACKNUM(-1,197),0},"fstat64", OK, RLONG, 2,
     {
         {1, sizeof(struct stat64), W,}
     }
    },
#endif
    {{PACKNUM(94,198),0},"lchown", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(102,199),0},"getuid", OK, RLONG, 0,},
    {{PACKNUM(104,200),0},"getgid", OK, RLONG, 0,},
    {{PACKNUM(107,201),0},"geteuid", OK, RLONG, 0,},
    {{PACKNUM(108,202),0},"getegid", OK, RLONG, 0,},
    {{PACKNUM(113,203),0},"setreuid", OK, RLONG, 2,},
    {{PACKNUM(114,204),0},"setregid", OK, RLONG, 2,},
    {{PACKNUM(115,205),0},"getgroups", OK, RLONG, 2,/*FIXME{{1, ARG1 * sizeof(vki_gid_t), W}, {1, RES * sizeof(vki_gid_t), W},}*/},
    {{PACKNUM(116,206),0},"setgroups", OK, RLONG, 2,/*FIXME{{1, ARG1 * sizeof(vki_gid_t), R},}*/},
    {{PACKNUM(93,207),0},"fchown", OK, RLONG, 3,},
    {{PACKNUM(117,208),0},"setresuid", OK, RLONG, 3,},
    {{PACKNUM(118,209),0},"getresuid", OK, RLONG, 3,
     {
         {0, sizeof(uid_t), W},
         {1, sizeof(uid_t), W},
         {2, sizeof(uid_t), W},
     }
    },
    {{PACKNUM(119,210),0},"setresgid", OK, RLONG, 3,},
    {{PACKNUM(120,211),0},"getresgid", OK, RLONG, 3,
     {
         {0, sizeof(gid_t), W},
         {1, sizeof(gid_t), W},
         {2, sizeof(gid_t), W},
     }
    },
    {{PACKNUM(92,212),0},"chown", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(105,213),0},"setuid", OK, RLONG, 1,},
    {{PACKNUM(106,214),0},"setgid", OK, RLONG, 1,},
    {{PACKNUM(122,215),0},"setfsuid", OK, RLONG, 1,},
    {{PACKNUM(123,216),0},"setfsgid", OK, RLONG, 1,},
    {{PACKNUM(155,217),0},"pivot_root", OK, RLONG, 2, /* FIXME 0, sizeof(char), U, 1, sizeof(char), U, */},
    {{PACKNUM(27,218),0},"mincore", OK, RLONG, 3,
     {
         {2,/*FIXME: round up to next page size*/-1, W},
     }
    },
    {{PACKNUM(28,219),0},"madvise", OK, RLONG, 3,},
    {{PACKNUM(217,220),0},"getdents64", OK, RLONG, 3,
     {
         {1, -2, W},
         {1, RET, W},
     }
    },
    {{PACKNUM(-1,221),0},"fcntl64", OK, RLONG, 2,}, /*special-cased: 3rd arg not always required*/
    {{PACKNUM(-1,222),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(-1,223),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(186,224),0},"gettid", OK, RLONG, 0,},
    {{PACKNUM(187,225),0},"readahead", OK, RLONG, 3,},
    {{PACKNUM(188,226),0},"setxattr", OK, RLONG, 5,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
         {2, -3, R},
     }
    },
    {{PACKNUM(189,227),0},"lsetxattr", OK, RLONG, 5,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
         {2, -3, R},
     }
    },
    {{PACKNUM(190,228),0},"fsetxattr", OK, RLONG, 5,
     {
         {1,0, R|CT, CSTRING},
         {2, -3, R},
     }
    },
    {{PACKNUM(191,229),0},"getxattr", OK, RLONG, 4,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
         {2, -3, W},
         {2, RET, W},
     }
    },
    {{PACKNUM(192,230),0},"lgetxattr", OK, RLONG, 4,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
         {2, -3, W},
         {2, RET, W},
     }
    },
    {{PACKNUM(193,231),0},"fgetxattr", OK, RLONG, 4,
     {
         {1,0, R|CT, CSTRING},
         {2, -3, W},
         {2, RET, W},
     }
    },
    {{PACKNUM(194,232),0},"listxattr", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
         {1, -2, W},
         {1, RET, W},
     }
    },
    {{PACKNUM(195,233),0},"llistxattr", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
         {1, -2, W},
         {1, RET, W},
     }
    },
    {{PACKNUM(196,234),0},"flistxattr", OK, RLONG, 3,
     {
         {1, -2, W},
         {1, RET, W},
     }
    },
    {{PACKNUM(197,235),0},"removexattr", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(198,236),0},"lremovexattr", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(199,237),0},"fremovexattr", OK, RLONG, 2,
     {
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(200,238),0},"tkill", OK, RLONG, 2,},
    {{PACKNUM(-1,239),0},"sendfile64", OK, RLONG, 4,
     {
         {2, sizeof(loff_t), W},
     }
    },
    {{PACKNUM(202,240),0},"futex", OK, RLONG, 3,
     {
         {0, sizeof(uint), R},
     }
    },/*rest are special-cased*/
    {{PACKNUM(203,241),0},"sched_setaffinity", OK, RLONG, 3,
     {
         {2, -1, R},
     }
    },
    {{PACKNUM(204,242),0},"sched_getaffinity", OK, RLONG, 3,
     {
         {2, -1, W},
     }
    },
    {{PACKNUM(205,243),0},"set_thread_area", OK, RLONG, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(211,244),0},"get_thread_area", OK, RLONG, /* FIXME: ***Missing prototype*** */ },
    {{PACKNUM(206,245),0},"io_setup", OK, RLONG, 2,/*FIXME type: {{1, sizeof(aio_context_t), W},}*/},
    {{PACKNUM(207,246),0},"io_destroy", OK, RLONG, 1,},
    {{PACKNUM(208,247),0},"io_getevents", OK, RLONG, 5, /* FIXME 3, sizeof(struct io_event), W, 3,****** special-case:  cb->aio_buf, vev->result, W,{4, sizeof(struct timespec), R}, */},
    {{PACKNUM(209,248),0},"io_submit", OK, RLONG, 3, /* FIXME 2, ARG2*sizeof(struct vki_iocb *), R, 2,****** special-case:  "io_submit(PWRITE)", OK, RLONG, cb->aio_buf, cb->aio_nbytes, R, */},
    {{PACKNUM(210,249),0},"io_cancel", OK, RLONG, 3,/* FIXME type: {{1, sizeof(struct iocb), R},{2, sizeof(struct io_event), W},}*/},
    {{PACKNUM(221,250),0},"fadvise64", OK, RLONG, 4,},
    {{PACKNUM(-1,251),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(231,252),0},"exit_group", OK, RLONG, 1,},
    {{PACKNUM(212,253),0},"lookup_dcookie", OK, RLONG, 3, /* FIXME 1, sizeof(char), U,{2, -3, W},{2, RET, W}, */},
    {{PACKNUM(213,254),0},"epoll_create", OK, RLONG, 1,},
    {{PACKNUM(233,255),0},"epoll_ctl", OK, RLONG, 4,
     {
         {3, sizeof(struct epoll_event), R},
     }
    },
    {{PACKNUM(232,256),0},"epoll_wait", OK, RLONG, 4,
     {
         {1, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(struct epoll_event)},
         {1, RET, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(struct epoll_event)},
     }
    },
    {{PACKNUM(216,257),0},"remap_file_pages", OK, RLONG, 5,},
    {{PACKNUM(218,258),0},"set_tid_address", OK, RLONG, 1, /* FIXME 0, sizeof(int), U, */},
    {{PACKNUM(222,259),0},"timer_create", OK, RLONG, 3,
     {
         {1, sizeof(struct sigevent), R},
         {2, sizeof(timer_t), W},
     }
    },
    {{PACKNUM(223,260),0},"timer_settime", OK, RLONG, 4,
     {
         {2, sizeof(struct itimerspec), R},
         {3, sizeof(struct itimerspec), W},
     }
    },
    {{PACKNUM(224,261),0},"timer_gettime", OK, RLONG, 2,
     {
         {1, sizeof(struct itimerspec), W},
     }
    },
    {{PACKNUM(225,262),0},"timer_getoverrun", OK, RLONG, 1,},
    {{PACKNUM(226,263),0},"timer_delete", OK, RLONG, 1,},
    {{PACKNUM(227,264),0},"clock_settime", OK, RLONG, 2,
     {
         {1, sizeof(struct timespec), R},
     }
    },
    {{PACKNUM(228,265),0},"clock_gettime", OK, RLONG, 2,
     {
         {1, sizeof(struct timespec), W},
     }
    },
    {{PACKNUM(229,266),0},"clock_getres", OK, RLONG, 2,
     {
         {1, sizeof(struct timespec), W},
     }
    },
    {{PACKNUM(230,267),0},"clock_nanosleep", OK, RLONG, 4,
     {
         {2, sizeof(struct timespec), R},
         {3, sizeof(struct timespec), W},
     }
    },
    {{PACKNUM(-1,268),0},"statfs64", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
         {2, -1, W},
     }
    },
    {{PACKNUM(-1,269),0},"fstatfs64", OK, RLONG, 3,
     {
         {2, -1, W},
     }
    },
    {{PACKNUM(234,270),0},"tgkill", OK, RLONG, 3,},
    {{PACKNUM(235,271),0},"utimes", OK, RLONG, 2,
     {
         {0,0, R|CT, CSTRING},
         {1,2 * sizeof(struct timeval), R},
     }
    },
    {{PACKNUM(-1,272),0},"fadvise64_64", OK, RLONG, 4,},
    {{PACKNUM(-1,273),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(237,274),0},"mbind", OK, RLONG, 6, /*FIXME {{3, VG_ROUNDUP(ARG5, sizeof(UWord))/sizeof(UWord), R,},}*/},
    {{PACKNUM(239,275),0},"get_mempolicy", OK, RLONG, 5,/*FIXME {{0, sizeof(int), W}, {1, VG_ROUNDUP(ARG3, sizeof(UWord)*8)/sizeof(UWord), W},}*/},
    {{PACKNUM(238,276),0},"set_mempolicy", OK, RLONG, 3, /*FIXME {{1, VG_ROUNDUP(ARG3, sizeof(UWord))/sizeof(UWord), R},}*/},
    {{PACKNUM(240,277),0},"mq_open", OK, RLONG, 4, /* FIXME 0, CSTRING, R, 0,****** special-case:  "mq_open(attr->mq_msgsize)", OK, RLONG, (Addr)&attr->mq_msgsize, sizeof(attr->mq_msgsize), R, 3, sizeof(struct mq_attr), U, */},
    {{PACKNUM(241,278),0},"mq_unlink", OK, RLONG, 1,
     {
         {0,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(242,279),0},"mq_timedsend", OK, RLONG, 5,
     {
         {1, -2, R},
         {4, sizeof(struct timespec), R
     }
    },},
    {{PACKNUM(243,280),0},"mq_timedreceive", OK, RLONG, 5,
     {
         {1, -2, W},
         {3, sizeof(unsigned int), W},
         {4, sizeof(struct timespec), R
     }
    },},
    {{PACKNUM(244,281),0},"mq_notify", OK, RLONG, 2,
     {
         {1, sizeof(struct sigevent), R},
     }
    },
    {{PACKNUM(245,282),0},"mq_getsetattr", OK, RLONG, 3, /* FIXME 1,****** special-case:  "mq_getsetattr(mqstat->mq_flags)", OK, RLONG, (Addr)&attr->mq_flags, sizeof(attr->mq_flags), R,{2, sizeof(struct mq_attr), W}, */},
    {{PACKNUM(246,283),0},"kexec_load", OK, RLONG, 4, /* FIXME 2, sizeof(struct kexec_segment), U, */},
    {{PACKNUM(247,284),0},"waitid", OK, RLONG, 5,
     {
         {2, sizeof(siginfo_t), W},
         {4, sizeof(struct rusage), W},
     }
    },
    {{PACKNUM(-1,285),0},"ni_syscall", OK, RLONG, 0,},
    {{PACKNUM(248,286),0},"add_key", OK, RLONG, 5,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
         {2, -3, R},
     }
    },
    {{PACKNUM(249,287),0},"request_key", OK, RLONG, 4,
     {
         {0,0, R|CT, CSTRING},
         {1,0, R|CT, CSTRING},
         {2,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(250,288),0},"keyctl", OK, RLONG, 5,
     {
         {1,0, R|CT, CSTRING},
         {2, -3, R},
         {2, RET, R},
         {3,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(251,289),0},"ioprio_set", OK, RLONG, 3,},
    {{PACKNUM(252,290),0},"ioprio_get", OK, RLONG, 2,},
    {{PACKNUM(253,291),0},"inotify_init", OK, RLONG, 0,},
    {{PACKNUM(254,292),0},"inotify_add_watch", OK, RLONG, 3,
     {
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(255,293),0},"inotify_rm_watch", OK, RLONG, 2,},
    {{PACKNUM(256,294),0},"migrate_pages", OK, RLONG, 4, /* FIXME 2, sizeof(unsigned long), U, 3, sizeof(unsigned long), U, */},
    {{PACKNUM(257,295),0},"openat", OK, RLONG, 4,
     {
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(258,296),0},"mkdirat", OK, RLONG, 3,
     {
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(259,297),0},"mknodat", OK, RLONG, 4,
     {
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(260,298),0},"fchownat", OK, RLONG, 5,
     {
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(261,299),0},"futimesat", OK, RLONG, 3,
     {
         {1,0, R|CT, CSTRING},
         {2,2 * sizeof(struct timeval), R},
     }
    },
    {{PACKNUM(-1,300),0},"fstatat64", OK, RLONG, 4, /* FIXME 1, sizeof(char), U, 2, sizeof(struct stat64), U, */},
    {{PACKNUM(263,301),0},"unlinkat", OK, RLONG, 3,
     {
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(264,302),0},"renameat", OK, RLONG, 4,
     {
         {1,0, R|CT, CSTRING},
         {3,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(265,303),0},"linkat", OK, RLONG, 5,
     {
         {1,0, R|CT, CSTRING},
         {3,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(266,304),0},"symlinkat", OK, RLONG, 3,
     {
         {0,0, R|CT, CSTRING},
         {2,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(267,305),0},"readlinkat", OK, RLONG, 4,
     {
         {1,0, R|CT, CSTRING},
         {2, -3, W},
         {2, RET, W},
     }
    },
    {{PACKNUM(268,306),0},"fchmodat", OK, RLONG, 3,
     {
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(269,307),0},"faccessat", OK, RLONG, 3,
     {
         {1,0, R|CT, CSTRING},
     }
    },
    {{PACKNUM(270,308),0},"pselect6", OK, RLONG, 6, /* special-cased below */},
    {{PACKNUM(271,309),0},"ppoll", OK, RLONG, 5, /* FIXME 0, sizeof(struct pollfd), U,{2, sizeof(struct timespec), R},{3, sizeof(kernel_sigset_t), R}, 3,****** special-case:  (Addr)(&ufds[i].revents), sizeof(ufds[i].revents), R, */},
    {{PACKNUM(272,310),0},"unshare", OK, RLONG, 1,},
    {{PACKNUM(273,311),0},"set_robust_list", OK, RLONG, 2,
     {
         {0, -1, R},
     }
    },
    {{PACKNUM(274,312),0},"get_robust_list", OK, RLONG, 3,/*FIXME type: {{1, sizeof(struct robust_list_head), W},{2, sizeof(size_t), W},}*/},
    {{PACKNUM(275,313),0},"splice", OK, RLONG, 6, /* FIXME 1, sizeof(loff_t), U, 3, sizeof(loff_t), U, */},
    {{PACKNUM(277,314),0},"sync_file_range", OK, RLONG, 4,},
    {{PACKNUM(276,315),0},"tee", OK, RLONG, 4,},
    {{PACKNUM(278,316),0},"vmsplice", OK, RLONG, 4, /* FIXME 1, sizeof(struct iovec), U, */},
    {{PACKNUM(279,317),0},"move_pages", OK, RLONG, 6, /* FIXME 2, sizeof(void), U, 3, sizeof(int), U, 4, sizeof(int), U, */},
    {{PACKNUM(-1,318),0},"getcpu", OK, RLONG, 3, /* FIXME 0, sizeof(unsigned), U, 1, sizeof(unsigned), U, 2, sizeof(struct getcpu_cache), U, */},
    {{PACKNUM(281,319),0},"epoll_pwait", OK, RLONG, 6,
     {
         {1, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(struct epoll_event)},
         {1, RET, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(struct epoll_event)},
         {4, sizeof(kernel_sigset_t), R},
     }
    },
    {{PACKNUM(280,320),0},"utimensat", OK, RLONG, 4,
     {
         {1,0, R|CT, CSTRING},
         {2,2 * sizeof(struct timespec), R},
     }
    },
    {{PACKNUM(282,321),0},"signalfd", OK, RLONG, 3,
     {
         {1, sizeof(kernel_sigset_t), R},
     }
    },
    {{PACKNUM(283,322),0},"timerfd_create", OK, RLONG, 2,},
    {{PACKNUM(284,323),0},"eventfd", OK, RLONG, 1,},
    {{PACKNUM(285,324),0},"fallocate", OK, RLONG, 4,},
    {{PACKNUM(286,325),0},"timerfd_settime", OK, RLONG, 4,
     {
         {2, sizeof(struct itimerspec), R},
         {3, sizeof(struct itimerspec), W},
     }
    },
    {{PACKNUM(287,326),0},"timerfd_gettime", OK, RLONG, 2,
     {
         {1, sizeof(struct itimerspec), W},
     }
    },
    {{PACKNUM(289,327),0},"signalfd4", OK, RLONG, 4, /* FIXME 1, sizeof(kernel_sigset_t), U, */},
    {{PACKNUM(290,328),0},"eventfd2", OK, RLONG, 2,},
    {{PACKNUM(291,329),0},"epoll_create1", OK, RLONG, 1,},
    {{PACKNUM(292,330),0},"dup3", OK, RLONG, 3,},
    {{PACKNUM(293,331),0},"pipe2", OK, RLONG, 2,
     {
         {0, sizeof(int)*2, W},
         {1, sizeof(int), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{PACKNUM(294,332),0},"inotify_init1", OK, RLONG, 1,},

    /**************************************************/
    /* 64-bit only */
    {{PACKNUM(29,-1),0},"shmget", OK, RLONG, 3, },
    {{PACKNUM(30,-1),0},"shmat", OK, RLONG, 3, /*FIXME i#1018: mark the shared mem as defined*/ },
    {{PACKNUM(31,-1),0},"shmctl", OK, RLONG, 3, /*special-cased*/},
    {{PACKNUM(41,-1),0},"socket", OK, RLONG, 3, },
    {{PACKNUM(42,-1),0},"connect", OK, RLONG, 3,
     {
         {1, -2, R|CT, SYSARG_TYPE_SOCKADDR},
     }
    },
    {{PACKNUM(43,-1),0},"accept", OK, RLONG, 3,
     {
         {1, -2, WI|CT, SYSARG_TYPE_SOCKADDR},
         {2, sizeof(socklen_t), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{PACKNUM(44,-1),0},"sendto", OK, RLONG, 6,
     {
         {1, -2, R},
         {4, -5, R|CT, SYSARG_TYPE_SOCKADDR},
         {5, sizeof(socklen_t), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{PACKNUM(45,-1),0},"recvfrom", OK, RLONG, 6,
     {
         {1, -2, W},
         {4, -5, WI|CT, SYSARG_TYPE_SOCKADDR},
         {5, sizeof(socklen_t), R|W|HT|SYSARG_IGNORE_IF_PREV_NULL, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{PACKNUM(46,-1),0},"sendmsg", OK, RLONG, 3,
     {
         {1, sizeof(struct msghdr), R|CT, SYSARG_TYPE_MSGHDR},
     }
    },
    {{PACKNUM(47,-1),0},"recvmsg", OK, RLONG, 3,
     {
         {1, sizeof(struct msghdr), W|CT, SYSARG_TYPE_MSGHDR},
     }
    },
    {{PACKNUM(48,-1),0},"shutdown", OK, RLONG, 2, },
    {{PACKNUM(49,-1),0},"bind", OK, RLONG, 3,
     {
         {1, -2, R|CT, SYSARG_TYPE_SOCKADDR},
     }
    },
    {{PACKNUM(50,-1),0},"listen", OK, RLONG, 2, },
    {{PACKNUM(51,-1),0},"getsockname", OK, RLONG, 3,
     {
         {1, -2, WI|CT, SYSARG_TYPE_SOCKADDR},
         {2, sizeof(socklen_t), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{PACKNUM(52,-1),0},"getpeername", OK, RLONG, 3,
     {
         {1, -2, WI|CT, SYSARG_TYPE_SOCKADDR},
         {2, sizeof(socklen_t), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{PACKNUM(53,-1),0},"socketpair", OK, RLONG, 4,
     {
         {3,2*sizeof(int), W},
     }
    },
    {{PACKNUM(54,-1),0},"setsockopt", OK, RLONG, 5,
     {
         {3, -4, R},
     }
    },
    {{PACKNUM(55,-1),0},"getsockopt", OK, RLONG, 5,
     {
         {3, -4, WI},
         {4, sizeof(socklen_t), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{PACKNUM(64,-1),0},"semget", OK, RLONG, 3, },
    {{PACKNUM(65,-1),0},"semop", OK, RLONG, 3,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(struct sembuf)},
     }
    },
    {{PACKNUM(66,-1),0},"semctl", OK, RLONG, 4, /*special-cased*/},
    {{PACKNUM(67,-1),0},"shmdt", OK, RLONG, 1, /*FIXME i#1018: mark the un-shared mem as unaddr*/  },
    {{PACKNUM(68,-1),0},"msgget", OK, RLONG, 2, },
    {{PACKNUM(69,-1),0},"msgsnd", OK, RLONG, 4,
     {
         {1, -2, R|CT, SYSARG_TYPE_MSGBUF},
     }
    },
    {{PACKNUM(70,-1),0},"msgrcv", OK, RLONG, 5,
     {
         {1, -2, W|CT, SYSARG_TYPE_MSGBUF},
     }
    },
    {{PACKNUM(71,-1),0},"msgctl", OK, RLONG, 3, /*special-cased*/},
    /* FIXME i#1019: fill these in (merge w/ 32-bit parallel entries above if nec) */
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
    {{PACKNUM(220,-1),0},"semtimedop", OK, RLONG, 4,
     {
         {1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(struct sembuf)},
         {3,sizeof(struct timespec),R},
     }
    },
    {{PACKNUM(236,-1),0},"vserver", UNKNOWN, RLONG, 0, },
    {{PACKNUM(262,-1),0},"newfstatat", UNKNOWN, RLONG, 0, },
    {{PACKNUM(288,-1),0},"paccept", OK, RLONG, 4,
     {
         {1,-2,WI|CT,SYSARG_TYPE_SOCKADDR},
         {2,sizeof(int),W, DRSYS_TYPE_SIGNED_INT},
     }
    }, /* == accept4 */
    {{PACKNUM(306,344),0},"syncfs", OK, RLONG, 1,
     {
         {0, sizeof(int),SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{PACKNUM(310,347),0},"process_vm_readv", OK, RLONG, 6,
     {
         {0, sizeof(pid_t), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(struct iovec)},
         {2, sizeof(unsigned long), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, -4, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(struct iovec)},
         {4, sizeof(unsigned long), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(int), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{PACKNUM(311,348),0},"process_vm_writev", OK, RLONG, 6,
     {
         {0, sizeof(pid_t), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(struct iovec)},
         {2, sizeof(unsigned long), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, -4, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(struct iovec)},
         {4, sizeof(unsigned long), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(int), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    /* FIXME i#1019: add recently added linux syscalls */
    {{PACKNUM(313,350),0},"finit_module", OK, RLONG, 3,
     {
         {0, sizeof(int), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {1, 0, R|CT, CSTRING},
         {2, sizeof(int), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
/* FIXME i#1019: add recently added linux syscalls */
};

size_t count_syscall_info = sizeof(syscall_info)/sizeof(syscall_info[0]);
