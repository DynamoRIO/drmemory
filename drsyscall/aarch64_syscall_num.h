/* Derived from /usr/include/asm-generic/unistd.h */

#define AARCH64_ni -1

#define AARCH64_io_setup 0
#define AARCH64_io_destroy 1
#define AARCH64_io_submit 2
#define AARCH64_io_cancel 3
#define AARCH64_io_getevents 4
#define AARCH64_setxattr 5
#define AARCH64_lsetxattr 6
#define AARCH64_fsetxattr 7
#define AARCH64_getxattr 8
#define AARCH64_lgetxattr 9
#define AARCH64_fgetxattr 10
#define AARCH64_listxattr 11
#define AARCH64_llistxattr 12
#define AARCH64_flistxattr 13
#define AARCH64_removexattr 14
#define AARCH64_lremovexattr 15
#define AARCH64_fremovexattr 16
#define AARCH64_getcwd 17
#define AARCH64_lookup_dcookie 18
#define AARCH64_eventfd2 19
#define AARCH64_epoll_create1 20
#define AARCH64_epoll_ctl 21
#define AARCH64_epoll_pwait 22
#define AARCH64_dup 23
#define AARCH64_dup3 24
#define AARCH64_fcntl 25
#define AARCH64_inotify_init1 26
#define AARCH64_inotify_add_watch 27
#define AARCH64_inotify_rm_watch 28
#define AARCH64_ioctl 29
#define AARCH64_ioprio_set 30
#define AARCH64_ioprio_get 31
#define AARCH64_flock 32
#define AARCH64_mknodat 33
#define AARCH64_mkdirat 34
#define AARCH64_unlinkat 35
#define AARCH64_symlinkat 36
#define AARCH64_linkat 37
#define AARCH64_renameat 38
#define AARCH64_umount2 39
#define AARCH64_mount 40
#define AARCH64_pivot_root 41
#define AARCH64_nfsservctl 42
#define AARCH64_statfs 43
#define AARCH64_fstatfs 44
#define AARCH64_truncate 45
#define AARCH64_ftruncate 46
#define AARCH64_fallocate 47
#define AARCH64_faccessat 48
#define AARCH64_chdir 49
#define AARCH64_fchdir 50
#define AARCH64_chroot 51
#define AARCH64_fchmod 52
#define AARCH64_fchmodat 53
#define AARCH64_fchownat 54
#define AARCH64_fchown 55
#define AARCH64_openat 56
#define AARCH64_close 57
#define AARCH64_vhangup 58
#define AARCH64_pipe2 59
#define AARCH64_quotactl 60
#define AARCH64_getdents64 61
#define AARCH64_lseek 62
#define AARCH64_read 63
#define AARCH64_write 64
#define AARCH64_readv 65
#define AARCH64_writev 66
#define AARCH64_pread64 67
#define AARCH64_pwrite64 68
#define AARCH64_preadv 69
#define AARCH64_pwritev 70
#define AARCH64_sendfile 71
#define AARCH64_pselect6 72
#define AARCH64_ppoll 73
#define AARCH64_signalfd4 74
#define AARCH64_vmsplice 75
#define AARCH64_splice 76
#define AARCH64_tee 77
#define AARCH64_readlinkat 78
#define AARCH64_fstatat64 79
#define AARCH64_fstat 80
#define AARCH64_sync 81
#define AARCH64_fsync 82
#define AARCH64_fdatasync 83
#define AARCH64_sync_file_range2 84
#define AARCH64_sync_file_range 84
#define AARCH64_timerfd_create 85
#define AARCH64_timerfd_settime 86
#define AARCH64_timerfd_gettime 87
#define AARCH64_utimensat 88
#define AARCH64_acct 89
#define AARCH64_capget 90
#define AARCH64_capset 91
#define AARCH64_personality 92
#define AARCH64_exit 93
#define AARCH64_exit_group 94
#define AARCH64_waitid 95
#define AARCH64_set_tid_address 96
#define AARCH64_unshare 97
#define AARCH64_futex 98
#define AARCH64_set_robust_list 99
#define AARCH64_get_robust_list 100
#define AARCH64_nanosleep 101
#define AARCH64_getitimer 102
#define AARCH64_setitimer 103
#define AARCH64_kexec_load 104
#define AARCH64_init_module 105
#define AARCH64_delete_module 106
#define AARCH64_timer_create 107
#define AARCH64_timer_gettime 108
#define AARCH64_timer_getoverrun 109
#define AARCH64_timer_settime 110
#define AARCH64_timer_delete 111
#define AARCH64_clock_settime 112
#define AARCH64_clock_gettime 113
#define AARCH64_clock_getres 114
#define AARCH64_clock_nanosleep 115
#define AARCH64_syslog 116
#define AARCH64_ptrace 117
#define AARCH64_sched_setparam 118
#define AARCH64_sched_setscheduler 119
#define AARCH64_sched_getscheduler 120
#define AARCH64_sched_getparam 121
#define AARCH64_sched_setaffinity 122
#define AARCH64_sched_getaffinity 123
#define AARCH64_sched_yield 124
#define AARCH64_sched_get_priority_max 125
#define AARCH64_sched_get_priority_min 126
#define AARCH64_sched_rr_get_interval 127
#define AARCH64_restart_syscall 128
#define AARCH64_kill 129
#define AARCH64_tkill 130
#define AARCH64_tgkill 131
#define AARCH64_sigaltstack 132
#define AARCH64_rt_sigsuspend 133
#define AARCH64_rt_sigaction 134
#define AARCH64_rt_sigprocmask 135
#define AARCH64_rt_sigpending 136
#define AARCH64_rt_sigtimedwait 137
#define AARCH64_rt_sigqueueinfo 138
#define AARCH64_rt_sigreturn 139
#define AARCH64_setpriority 140
#define AARCH64_getpriority 141
#define AARCH64_reboot 142
#define AARCH64_setregid 143
#define AARCH64_setgid 144
#define AARCH64_setreuid 145
#define AARCH64_setuid 146
#define AARCH64_setresuid 147
#define AARCH64_getresuid 148
#define AARCH64_setresgid 149
#define AARCH64_getresgid 150
#define AARCH64_setfsuid 151
#define AARCH64_setfsgid 152
#define AARCH64_times 153
#define AARCH64_setpgid 154
#define AARCH64_getpgid 155
#define AARCH64_getsid 156
#define AARCH64_setsid 157
#define AARCH64_getgroups 158
#define AARCH64_setgroups 159
#define AARCH64_uname 160
#define AARCH64_sethostname 161
#define AARCH64_setdomainname 162
#define AARCH64_getrlimit 163
#define AARCH64_setrlimit 164
#define AARCH64_getrusage 165
#define AARCH64_umask 166
#define AARCH64_prctl 167
#define AARCH64_getcpu 168
#define AARCH64_gettimeofday 169
#define AARCH64_settimeofday 170
#define AARCH64_adjtimex 171
#define AARCH64_getpid 172
#define AARCH64_getppid 173
#define AARCH64_getuid 174
#define AARCH64_geteuid 175
#define AARCH64_getgid 176
#define AARCH64_getegid 177
#define AARCH64_gettid 178
#define AARCH64_sysinfo 179
#define AARCH64_mq_open 180
#define AARCH64_mq_unlink 181
#define AARCH64_mq_timedsend 182
#define AARCH64_mq_timedreceive 183
#define AARCH64_mq_notify 184
#define AARCH64_mq_getsetattr 185
#define AARCH64_msgget 186
#define AARCH64_msgctl 187
#define AARCH64_msgrcv 188
#define AARCH64_msgsnd 189
#define AARCH64_semget 190
#define AARCH64_semctl 191
#define AARCH64_semtimedop 192
#define AARCH64_semop 193
#define AARCH64_shmget 194
#define AARCH64_shmctl 195
#define AARCH64_shmat 196
#define AARCH64_shmdt 197
#define AARCH64_socket 198
#define AARCH64_socketpair 199
#define AARCH64_bind 200
#define AARCH64_listen 201
#define AARCH64_accept 202
#define AARCH64_connect 203
#define AARCH64_getsockname 204
#define AARCH64_getpeername 205
#define AARCH64_sendto 206
#define AARCH64_recvfrom 207
#define AARCH64_setsockopt 208
#define AARCH64_getsockopt 209
#define AARCH64_shutdown 210
#define AARCH64_sendmsg 211
#define AARCH64_recvmsg 212
#define AARCH64_readahead 213
#define AARCH64_brk 214
#define AARCH64_munmap 215
#define AARCH64_mremap 216
#define AARCH64_add_key 217
#define AARCH64_request_key 218
#define AARCH64_keyctl 219
#define AARCH64_clone 220
#define AARCH64_execve 221
#define AARCH64_mmap 222
#define AARCH64_fadvise64 223
#define AARCH64_swapon 224
#define AARCH64_swapoff 225
#define AARCH64_mprotect 226
#define AARCH64_msync 227
#define AARCH64_mlock 228
#define AARCH64_munlock 229
#define AARCH64_mlockall 230
#define AARCH64_munlockall 231
#define AARCH64_mincore 232
#define AARCH64_madvise 233
#define AARCH64_remap_file_pages 234
#define AARCH64_mbind 235
#define AARCH64_get_mempolicy 236
#define AARCH64_set_mempolicy 237
#define AARCH64_migrate_pages 238
#define AARCH64_move_pages 239
#define AARCH64_rt_tgsigqueueinfo 240
#define AARCH64_perf_event_open 241
#define AARCH64_accept4 242
#define AARCH64_recvmmsg 243
#define AARCH64_arch_specific_syscall 244
#define AARCH64_wait4 260
#define AARCH64_prlimit64 261
#define AARCH64_fanotify_init 262
#define AARCH64_fanotify_mark 263
#define AARCH64_name_to_handle_at         264
#define AARCH64_open_by_handle_at         265
#define AARCH64_clock_adjtime 266
#define AARCH64_syncfs 267
#define AARCH64_setns 268
#define AARCH64_sendmmsg 269
#define AARCH64_process_vm_readv 270
#define AARCH64_process_vm_writev 271
#define AARCH64_kcmp 272
#define AARCH64_finit_module 273
#define AARCH64_sched_setattr 274
#define AARCH64_sched_getattr 275
#define AARCH64_renameat2 276
#define AARCH64_seccomp 277
#define AARCH64_getrandom 278
#define AARCH64_memfd_create 279
#define AARCH64_bpf 280
#define AARCH64_execveat 281
#define AARCH64_userfaultfd 282
#define AARCH64_membarrier 283
#define AARCH64_mlock2 284
#define AARCH64_copy_file_range 285
#define AARCH64_preadv2 286
#define AARCH64_pwritev2 287
#define AARCH64_pkey_mprotect 288
#define AARCH64_pkey_alloc 289
#define AARCH64_pkey_free 290
#define AARCH64_statx 291
#define AARCH64_open 1024
#define AARCH64_link 1025
#define AARCH64_unlink 1026
#define AARCH64_mknod 1027
#define AARCH64_chmod 1028
#define AARCH64_chown 1029
#define AARCH64_mkdir 1030
#define AARCH64_rmdir 1031
#define AARCH64_lchown 1032
#define AARCH64_access 1033
#define AARCH64_rename 1034
#define AARCH64_readlink 1035
#define AARCH64_symlink 1036
#define AARCH64_utimes 1037
#define AARCH64_stat 1038
#define AARCH64_lstat 1039
#define AARCH64_pipe 1040
#define AARCH64_dup2 1041
#define AARCH64_epoll_create 1042
#define AARCH64_inotify_init 1043
#define AARCH64_eventfd 1044
#define AARCH64_signalfd 1045
#define AARCH64_sendfile64 1046
#define AARCH64_ftruncate64 1047
#define AARCH64_truncate64 1048
#define AARCH64_stat64 1049
#define AARCH64_lstat64 1050
#define AARCH64_fstat64 1051
#define AARCH64_fcntl64 1052
#define AARCH64_fadvise64_64 1053
#define AARCH64_newfstatat 1054
#define AARCH64_fstatfs64 1055
#define AARCH64_statfs64 1056
#define AARCH64_llseek 1057
#define AARCH64_mmap2 1058
#define AARCH64_alarm 1059
#define AARCH64_getpgrp 1060
#define AARCH64_pause 1061
#define AARCH64_time 1062
#define AARCH64_utime 1063
#define AARCH64_creat 1064
#define AARCH64_getdents 1065
#define AARCH64_futimesat 1066
#define AARCH64_select 1067
#define AARCH64_poll 1068
#define AARCH64_epoll_wait 1069
#define AARCH64_ustat 1070
#define AARCH64_vfork 1071
#define AARCH64_oldwait4 1072
#define AARCH64_recv 1073
#define AARCH64_send 1074
#define AARCH64_bdflush 1075
#define AARCH64_umount 1076
#define AARCH64_uselib 1077
#define AARCH64_sysctl 1078
#define AARCH64_fork 1079
