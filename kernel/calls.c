#include <string.h>
#include "debug.h"
#include "kernel/calls.h"
#include "emu/interrupt.h"
#include "emu/memory.h"
#include "kernel/signal.h"
#include "kernel/task.h"

dword_t syscall_stub(void) {
    return _ENOSYS;
}
// While identical, this version of the stub doesn't log below. Use this for
// syscalls that are optional (i.e. fallback on something else) but called
// frequently.
dword_t syscall_silent_stub(void) {
    return _ENOSYS;
}
dword_t syscall_success_stub(void) {
    return 0;
}

#if is_gcc(8)
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
syscall_t syscall_table[] = {
    [1]   = (syscall_t) sys_exit,
    [2]   = (syscall_t) sys_fork,
    [3]   = (syscall_t) sys_read,
    [4]   = (syscall_t) sys_write,
    [5]   = (syscall_t) sys_open,
    [6]   = (syscall_t) sys_close,
    [7]   = (syscall_t) sys_waitpid,
    //[8]   = (syscall_t) sys_creat,
    [9]   = (syscall_t) sys_link,
    [10]  = (syscall_t) sys_unlink,
    [11]  = (syscall_t) sys_execve,
    [12]  = (syscall_t) sys_chdir,
    [13]  = (syscall_t) sys_time,
    [14]  = (syscall_t) sys_mknod,
    [15]  = (syscall_t) sys_chmod,
    //[16]  = (syscall_t) sys_lchown,
    //[17]  = (syscall_t) sys_break, UNIMPLEMENTED
    //[18]  = (syscall_t) sys_oldstat,
    [19]  = (syscall_t) sys_lseek,
    [20]  = (syscall_t) sys_getpid,
    [21]  = (syscall_t) sys_mount,
    //[22]  = (syscall_t) sys_umount,
    [23]  = (syscall_t) sys_setuid,
    [24]  = (syscall_t) sys_getuid,
    [25]  = (syscall_t) sys_stime,
    [26]  = (syscall_t) sys_ptrace,
    [27]  = (syscall_t) sys_alarm,
    //[28]  = (syscall_t) sys_oldfstat,
    [29]  = (syscall_t) sys_pause,
    [30]  = (syscall_t) sys_utime,
    //[31]  = (syscall_t) sys_stty, UNIMPLEMENTED
    //[32]  = (syscall_t) sys_gtty, UNIMPLEMENTED
    [33]  = (syscall_t) sys_access,
    //[34]  = (syscall_t) sys_nice,
    //[35]  = (syscall_t) sys_ftime, UNIMPLEMENTED
    [36]  = (syscall_t) syscall_success_stub, // sync
    [37]  = (syscall_t) sys_kill,
    [38]  = (syscall_t) sys_rename,
    [39]  = (syscall_t) sys_mkdir,
    [40]  = (syscall_t) sys_rmdir,
    [41]  = (syscall_t) sys_dup,
    [42]  = (syscall_t) sys_pipe,
    [43]  = (syscall_t) sys_times,
    //[44]  = (syscall_t) sys_prof, UNIMPLEMENTED
    [45]  = (syscall_t) sys_brk,
    [46]  = (syscall_t) sys_setgid,
    [47]  = (syscall_t) sys_getgid,
    //[48]  = (syscall_t) sys_signal,
    [49]  = (syscall_t) sys_geteuid,
    [50]  = (syscall_t) sys_getegid,
    //[51]  = (syscall_t) sys_acct,
    [52]  = (syscall_t) sys_umount2,
    //[53]  = (syscall_t) sys_lock, UNIMPLEMENTED
    [54]  = (syscall_t) sys_ioctl,
    [55]  = (syscall_t) sys_fcntl32,
    //[56]  = (syscall_t) sys_mpx, UNIMPLEMENTED
    [57]  = (syscall_t) sys_setpgid,
    //[58]  = (syscall_t) sys_ulimit, UNIMPLEMENTED
    //[59]  = (syscall_t) sys_oldolduname,
    [60]  = (syscall_t) sys_umask,
    [61]  = (syscall_t) sys_chroot,
    //[62]  = (syscall_t) sys_ustat,
    [63]  = (syscall_t) sys_dup2,
    [64]  = (syscall_t) sys_getppid,
    [65]  = (syscall_t) sys_getpgrp,
    [66]  = (syscall_t) sys_setsid,
    //[67]  = (syscall_t) sys_sigaction,
    //[68]  = (syscall_t) sys_sgetmask,
    //[69]  = (syscall_t) sys_ssetmask,
    //[70]  = (syscall_t) sys_setreuid,
    //[71]  = (syscall_t) sys_setregid,
    //[72]  = (syscall_t) sys_sigsuspend,
    //[73]  = (syscall_t) sys_sigpending,
    [74]  = (syscall_t) sys_sethostname,
    [75]  = (syscall_t) sys_setrlimit32,
    [76]  = (syscall_t) sys_old_getrlimit32,
    [77]  = (syscall_t) sys_getrusage,
    [78]  = (syscall_t) sys_gettimeofday,
    [79]  = (syscall_t) sys_settimeofday,
    [80]  = (syscall_t) sys_getgroups,
    [81]  = (syscall_t) sys_setgroups,
    //[82]  = (syscall_t) sys_select,
    [83]  = (syscall_t) sys_symlink,
    //[84]  = (syscall_t) sys_oldlstat,
    [85]  = (syscall_t) sys_readlink,
    //[86]  = (syscall_t) sys_uselib,
    //[87]  = (syscall_t) sys_swapon,
    [88]  = (syscall_t) sys_reboot,
    //[89]  = (syscall_t) sys_readdir,
    [90]  = (syscall_t) sys_mmap,
    [91]  = (syscall_t) sys_munmap,
    //[92]  = (syscall_t) sys_truncate,
    //[93]  = (syscall_t) sys_ftruncate,
    [94]  = (syscall_t) sys_fchmod,
    //[95]  = (syscall_t) sys_fchown,
    [96]  = (syscall_t) sys_getpriority,
    [97]  = (syscall_t) sys_setpriority,
    //[98]  = (syscall_t) sys_profil, UNIMPLEMENTED
    [99]  = (syscall_t) sys_statfs,
    [100] = (syscall_t) sys_fstatfs,
    //[101]  = (syscall_t) sys_ioperm,
    [102] = (syscall_t) sys_socketcall,
    [103] = (syscall_t) sys_syslog,
    [104] = (syscall_t) sys_setitimer,
    //[105]  = (syscall_t) sys_getitimer,
    //[106]  = (syscall_t) sys_stat,
    //[107]  = (syscall_t) sys_lstat,
    //[108]  = (syscall_t) sys_fstat,
    //[109]  = (syscall_t) sys_olduname,
    //[110]  = (syscall_t) sys_iopl,
    //[111]  = (syscall_t) sys_vhangup,
    //[112]  = (syscall_t) sys_idle,
    //[113]  = (syscall_t) sys_vm86old,
    [114] = (syscall_t) sys_wait4,
    //[115]  = (syscall_t) sys_swapoff,
    [116] = (syscall_t) sys_sysinfo,
    [117] = (syscall_t) sys_ipc,
    [118] = (syscall_t) sys_fsync,
    [119] = (syscall_t) sys_sigreturn,
    [120] = (syscall_t) sys_clone,
    //[121]  = (syscall_t) sys_setdomainname,
    [122] = (syscall_t) sys_uname,
    //[123]  = (syscall_t) sys_modify_ltd,
    //[124]  = (syscall_t) sys_adjtimex,
    [125] = (syscall_t) sys_mprotect,
    //[126]  = (syscall_t) sys_sigprocmask,
    //[127]  = (syscall_t) sys_create_module,
    //[128]  = (syscall_t) sys_init_module,
    //[129]  = (syscall_t) sys_delete_module,
    //[130]  = (syscall_t) sys_get_kernel_syms,
    //[131]  = (syscall_t) sys_quotactl,
    [132] = (syscall_t) sys_getpgid,
    [133] = (syscall_t) sys_fchdir,
    //[134]  = (syscall_t) sys_bdflush,
    //[135]  = (syscall_t) sys_sysfs,
    [136] = (syscall_t) sys_personality,
    //[137]  = (syscall_t) sys_afs_syscall, UNIMPLEMENTED
    //[138]  = (syscall_t) sys_setfsuid,
    //[139]  = (syscall_t) sys_setfsgid,
    [140] = (syscall_t) sys__llseek,
    [141] = (syscall_t) sys_getdents,
    [142] = (syscall_t) sys_select,
    [143] = (syscall_t) sys_flock,
    [144] = (syscall_t) sys_msync,
    [145] = (syscall_t) sys_readv,
    [146] = (syscall_t) sys_writev,
    [147] = (syscall_t) sys_getsid,
    [148] = (syscall_t) sys_fsync, // fdatasync
    //[149]  = (syscall_t) sys__sysctl,
    [150] = (syscall_t) sys_mlock,
    //[151]  = (syscall_t) sys_munlock,
    //[152]  = (syscall_t) sys_mlockall,
    //[153]  = (syscall_t) sys_munlockall,
    //[154]  = (syscall_t) sys_sched_setparam,
    [155] = (syscall_t) sys_sched_getparam,
    [156] = (syscall_t) sys_sched_setscheduler,
    [157] = (syscall_t) sys_sched_getscheduler,
    [158] = (syscall_t) sys_sched_yield,
    [159] = (syscall_t) sys_sched_get_priority_max,
    //[160]  = (syscall_t) sys_sched_get_priority_min,
    //[161]  = (syscall_t) sys_sched_rr_get_interval,
    [162] = (syscall_t) sys_nanosleep,
    [163] = (syscall_t) sys_mremap,
    //[164]  = (syscall_t) sys_setresuid,
    //[165]  = (syscall_t) sys_getresuid,
    //[166]  = (syscall_t) sys_vm86,
    //[167]  = (syscall_t) sys_query_module,
    [168] = (syscall_t) sys_poll,
    //[169]  = (syscall_t) sys_nfsservctl,
    //[170]  = (syscall_t) sys_setresgid,
    //[171]  = (syscall_t) sys_getresgid,
    [172] = (syscall_t) sys_prctl,
    [173] = (syscall_t) sys_rt_sigreturn,
    [174] = (syscall_t) sys_rt_sigaction,
    [175] = (syscall_t) sys_rt_sigprocmask,
    [176] = (syscall_t) sys_rt_sigpending,
    [177] = (syscall_t) sys_rt_sigtimedwait,
    //[178]  = (syscall_t) sys_rt_sigqueueinfo,
    [179] = (syscall_t) sys_rt_sigsuspend,
    [180] = (syscall_t) sys_pread,
    [181] = (syscall_t) sys_pwrite,
    //[182]  = (syscall_t) sys_chown,
    [183] = (syscall_t) sys_getcwd,
    [184] = (syscall_t) sys_capget,
    [185] = (syscall_t) sys_capset,
    [186] = (syscall_t) sys_sigaltstack,
    [187] = (syscall_t) sys_sendfile,
    //[188]  = (syscall_t) sys_getpmsg, UNIMPLEMENTED
    //[189]  = (syscall_t) sys_putpmsg, UNIMPLEMENTED
    [190] = (syscall_t) sys_vfork,
    [191] = (syscall_t) sys_getrlimit32,
    [192] = (syscall_t) sys_mmap2,
    [193] = (syscall_t) sys_truncate64,
    [194] = (syscall_t) sys_ftruncate64,
    [195] = (syscall_t) sys_stat64,
    [196] = (syscall_t) sys_lstat64,
    [197] = (syscall_t) sys_fstat64,
    [198] = (syscall_t) sys_lchown,
    [199] = (syscall_t) sys_getuid32,
    [200] = (syscall_t) sys_getgid32,
    [201] = (syscall_t) sys_geteuid32,
    [202] = (syscall_t) sys_getegid32,
    [203] = (syscall_t) sys_setreuid,
    [204] = (syscall_t) sys_setregid,
    [205] = (syscall_t) sys_getgroups,
    [206] = (syscall_t) sys_setgroups,
    [207] = (syscall_t) sys_fchown32,
    [208] = (syscall_t) sys_setresuid,
    [209] = (syscall_t) sys_getresuid,
    [210] = (syscall_t) sys_setresgid,
    [211] = (syscall_t) sys_getresgid,
    [212] = (syscall_t) sys_chown32,
    [213] = (syscall_t) sys_setuid,
    [214] = (syscall_t) sys_setgid,
    //[215]  = (syscall_t) sys_setfsuid32,
    //[216]  = (syscall_t) sys_setfsgid32,
    //[217]  = (syscall_t) sys_pivot_root,
    //[218]  = (syscall_t) sys_mincore,
    [219] = (syscall_t) sys_madvise,
    [220] = (syscall_t) sys_getdents64,
    [221] = (syscall_t) sys_fcntl,
    //[222]  = (syscall_t) UNIMPLEMENTED,
    //[223]  = (syscall_t) UNIMPLEMENTED,
    [224] = (syscall_t) sys_gettid,
    [225] = (syscall_t) syscall_success_stub, // readahead
    [226 ... 237] = (syscall_t) sys_xattr_stub,
    [238] = (syscall_t) sys_tkill,
    [239] = (syscall_t) sys_sendfile64,
    [240] = (syscall_t) sys_futex,
    [241] = (syscall_t) sys_sched_setaffinity,
    [242] = (syscall_t) sys_sched_getaffinity,
    [243] = (syscall_t) sys_set_thread_area,
    //[244]  = (syscall_t) sys_get_thread_area,
    [245] = (syscall_t) syscall_stub, // io_setup
    //[246]  = (syscall_t) sys_io_destroy,
    //[247]  = (syscall_t) sys_io_getevents,
    //[248]  = (syscall_t) sys_io_submit,
    //[249]  = (syscall_t) sys_io_cancel,
    //[250]  = (syscall_t) sys_fadvise64,
    //[251]  = (syscall_t) UNIMPLEMENTED,
    [252] = (syscall_t) sys_exit_group,
    //[253]  = (syscall_t) sys_lookup_dcookie,
    [254] = (syscall_t) sys_epoll_create0,
    [255] = (syscall_t) sys_epoll_ctl,
    [256] = (syscall_t) sys_epoll_wait,
    //[257]  = (syscall_t) sys_remap_file_pages,
    [258] = (syscall_t) sys_set_tid_address,
    [259] = (syscall_t) sys_timer_create,
    [260] = (syscall_t) sys_timer_settime,
    //[261]  = (syscall_t) sys_timer_gettime,
    //[262]  = (syscall_t) sys_timer_getoverrun,
    [263] = (syscall_t) sys_timer_delete,
    [264] = (syscall_t) sys_clock_settime,
    [265] = (syscall_t) sys_clock_gettime,
    [266] = (syscall_t) sys_clock_getres,
    //[267]  = (syscall_t) sys_clock_nanosleep,
    [268] = (syscall_t) sys_statfs64,
    [269] = (syscall_t) sys_fstatfs64,
    [270] = (syscall_t) sys_tgkill,
    [271] = (syscall_t) sys_utimes,
    [272] = (syscall_t) syscall_success_stub,
    //[273]  = (syscall_t) sys_vserver, UNIMPLEMENTED
    [274] = (syscall_t) sys_mbind,
    //[275]  = (syscall_t) sys_get_mempolicy,
    //[276]  = (syscall_t) sys_set_mempolicy,
    //[277]  = (syscall_t) sys_mq_open,
    //[278]  = (syscall_t) sys_mq_unlink,
    //[279]  = (syscall_t) sys_mq_timedsend,
    //[280]  = (syscall_t) sys_mq_timedrecieve,
    //[281]  = (syscall_t) sys_mq_notify,
    //[282]  = (syscall_t) sys_mq_getsetattr,
    //[283]  = (syscall_t) sys_kexec_load,
    [284] = (syscall_t) sys_waitid,
    //[285]  = (syscall_t) UNIMPLEMENTED,
    //[286]  = (syscall_t) sys_add_key,
    //[287]  = (syscall_t) sys_request_key,
    //[288]  = (syscall_t) sys_keyctl,
    [289] = (syscall_t) sys_ioprio_set,
    [290] = (syscall_t) sys_ioprio_get,
    [291] = (syscall_t) syscall_stub, // inotify_init
    //[292]  = (syscall_t) sys_inotify_add_watch,
    //[293]  = (syscall_t) sys_inotify_rm_watch,
    //[294]  = (syscall_t) sys_migrate_pages,
    [295] = (syscall_t) sys_openat,
    [296] = (syscall_t) sys_mkdirat,
    [297] = (syscall_t) sys_mknodat,
    [298] = (syscall_t) sys_fchownat,
    //[299]  = (syscall_t) sys_futimesat,
    [300] = (syscall_t) sys_fstatat64,
    [301] = (syscall_t) sys_unlinkat,
    [302] = (syscall_t) sys_renameat,
    [303] = (syscall_t) sys_linkat,
    [304] = (syscall_t) sys_symlinkat,
    [305] = (syscall_t) sys_readlinkat,
    [306] = (syscall_t) sys_fchmodat,
    [307] = (syscall_t) sys_faccessat,
    [308] = (syscall_t) sys_pselect,
    [309] = (syscall_t) sys_ppoll,
    //[310]  = (syscall_t) sys_unshare,
    [311] = (syscall_t) sys_set_robust_list,
    [312] = (syscall_t) sys_get_robust_list,
    [313] = (syscall_t) sys_splice,
    //[314]  = (syscall_t) sys_sync_file_range,
    //[315]  = (syscall_t) sys_tee,
    //[316]  = (syscall_t) sys_vmsplice,
    //[317]  = (syscall_t) sys_move_pages,
    //[318]  = (syscall_t) sys_getcpu,
    [319] = (syscall_t) sys_epoll_pwait,
    [320] = (syscall_t) sys_utimensat,
    //[321]  = (syscall_t) sys_signalfd,
    [322] = (syscall_t) sys_timerfd_create,
    [323] = (syscall_t) sys_eventfd,
    [324] = (syscall_t) sys_fallocate,
    [325] = (syscall_t) sys_timerfd_settime,
    //[326]  = (syscall_t) sys_timerfd_gettime,
    //[327]  = (syscall_t) sys_signalfd4,
    [328] = (syscall_t) sys_eventfd2,
    [329] = (syscall_t) sys_epoll_create,
    [330] = (syscall_t) sys_dup3,
    [331] = (syscall_t) sys_pipe2,
    [332] = (syscall_t) syscall_stub, // inotify_init1
    //[333]  = (syscall_t) sys_preadv,
    //[334]  = (syscall_t) sys_pwritev,
    //[335]  = (syscall_t) sys_rt_tgsigqueueinfo,
    //[336]  = (syscall_t) sys_perf_event_open,
    //[337]  = (syscall_t) sys_recvmmsg,
    //[338]  = (syscall_t) sys_fanotify_init,
    //[339]  = (syscall_t) sys_fanotify_mark,
    [340] = (syscall_t) sys_prlimit64,
    //[341]  = (syscall_t) sys_name_to_handle_at,
    //[342]  = (syscall_t) sys_open_by_handle_at,
    //[343]  = (syscall_t) sys_clock_adjtime,
    //[344]  = (syscall_t) sys_syncfs,
    [345] = (syscall_t) sys_sendmmsg,
    //[346]  = (syscall_t) sys_setns,
    //[347]  = (syscall_t) sys_process_vm_readv,
    //[348]  = (syscall_t) sys_process_vm_writev,
    //[349]  = (syscall_t) sys_kcmp,
    //[350]  = (syscall_t) sys_finit_module,
    //[351]  = (syscall_t) sys_sched_setattr,
    [352] = (syscall_t) syscall_stub, // sched_getattr
    [353] = (syscall_t) sys_renameat2,
    //[354]  = (syscall_t) sys_seccomp,
    [355] = (syscall_t) sys_getrandom,
    //[356]  = (syscall_t) sys_memfd_create,
    //[357]  = (syscall_t) sys_bpf,
    //[358]  = (syscall_t) sys_execveat,
    [359] = (syscall_t) sys_socket,
    [360] = (syscall_t) sys_socketpair,
    [361] = (syscall_t) sys_bind,
    [362] = (syscall_t) sys_connect,
    [363] = (syscall_t) sys_listen,
    [364] = (syscall_t) syscall_stub, // accept4
    [365] = (syscall_t) sys_getsockopt,
    [366] = (syscall_t) sys_setsockopt,
    [367] = (syscall_t) sys_getsockname,
    [368] = (syscall_t) sys_getpeername,
    [369] = (syscall_t) sys_sendto,
    [370] = (syscall_t) sys_sendmsg,
    [371] = (syscall_t) sys_recvfrom,
    [372] = (syscall_t) sys_recvmsg,
    [373] = (syscall_t) sys_shutdown,
    //[374]  = (syscall_t) sys_userfaultfd,
    [375] = (syscall_t) syscall_silent_stub, // membarrier
    //[376]  = (syscall_t) sys_mlock2,
    [377] = (syscall_t) sys_copy_file_range,
    //[378]  = (syscall_t) sys_preadv2,
    //[379]  = (syscall_t) sys_pwritev2,
    //[380]  = (syscall_t) sys_pkey_mprotect,
    //[381]  = (syscall_t) sys_pkey_alloc,
    //[382]  = (syscall_t) sys_pkey_free,
    [383] = (syscall_t) syscall_silent_stub, // statx
    [384] = (syscall_t) sys_arch_prctl,
    //[385] UNIMPLEMENTED
    //[386]  = (syscall_t) sys_rseq,
    //[387 ... 402] UNIMPLEMENTED
    //[403]  = (syscall_t) sys_clock_gettime64,
    //[404]  = (syscall_t) sys_clock_settime64,
    //[405]  = (syscall_t) sys_clock_adjtime64,
    //[406]  = (syscall_t) sys_clock_getres_time64,
    //[407]  = (syscall_t) sys_clock_nanosleep_time64,
    //[408]  = (syscall_t) sys_timer_gettime64,
    //[409]  = (syscall_t) sys_timer_settime64,
    //[410]  = (syscall_t) sys_timerfd_gettime64,
    //[411]  = (syscall_t) sys_timerfd_settime64,
    //[412]  = (syscall_t) sys_utimensat_time64,
    //[413]  = (syscall_t) sys_pselect6_time64,
    //[414]  = (syscall_t) sys_ppoll_time64,
    //[415] UNIMPLEMENTED
    //[416]  = (syscall_t) sys_io_pgetevents_time64,
    //[417]  = (syscall_t) sys_recvmmsg_time64,
    //[418]  = (syscall_t) sys_mq_timedsend_time64,
    //[419]  = (syscall_t) sys_mq_timedrecieve_time64,
    //[420]  = (syscall_t) sys_semtimedop_time64,
    //[421]  = (syscall_t) sys_rt_sigtimed_wait_time64,
    //[422]  = (syscall_t) sys_futex_time64,
    //[423]  = (syscall_t) sys_sched_rr_get_interval_time64,
    //[424] UNIMPLEMENTED
    //[425]  = (syscall_t) sys_io_uring_setup,
    //[426]  = (syscall_t) sys_io_ring_enter,
    //[427 ... 433] UNIMPLEMENTED
    //[434]  = (syscall_t) sys_pidfd_open,
    //[435]  = (syscall_t) sys_clone3,
    //[436]  = (syscall_t) sys_close_range,
    //[437 ... 438] UNIMPLEMENTED
    [439] = (syscall_t) syscall_silent_stub, // faccessat2
};

#define NUM_SYSCALLS (sizeof(syscall_table) / sizeof(syscall_table[0]))

void dump_stack(int lines);

void handle_interrupt(int interrupt) {
    struct cpu_state *cpu = &current->cpu;
    if (interrupt == INT_SYSCALL) {
        unsigned syscall_num = cpu->eax;
        if (syscall_num >= NUM_SYSCALLS || syscall_table[syscall_num] == NULL) {
            printk("%d(%s) missing syscall %d\n", current->pid, current->comm, syscall_num);
            deliver_signal(current, SIGSYS_, SIGINFO_NIL);
        } else {
            if (syscall_table[syscall_num] == (syscall_t) syscall_stub) {
                printk("%d(%s) stub syscall %d\n", current->pid, current->comm, syscall_num);
            }
            STRACE("%d call %-3d ", current->pid, syscall_num);
            int result = syscall_table[syscall_num](cpu->ebx, cpu->ecx, cpu->edx, cpu->esi, cpu->edi, cpu->ebp);
            STRACE(" = 0x%x\n", result);
            cpu->eax = result;
        }
    } else if (interrupt == INT_GPF) {
        // some page faults, such as stack growing or CoW clones, are handled by mem_ptr
        read_wrlock(&current->mem->lock);
        void *ptr = mem_ptr(current->mem, cpu->segfault_addr, cpu->segfault_was_write ? MEM_WRITE : MEM_READ);
        read_wrunlock(&current->mem->lock);
        if (ptr == NULL) {
            printk("%d page fault on 0x%x at 0x%x\n", current->pid, cpu->segfault_addr, cpu->eip);
            struct siginfo_ info = {
                .code = mem_segv_reason(current->mem, cpu->segfault_addr),
                .fault.addr = cpu->segfault_addr,
            };
            dump_stack(8);
            deliver_signal(current, SIGSEGV_, info);
        }
    } else if (interrupt == INT_UNDEFINED) {
        printk("%d illegal instruction at 0x%x: ", current->pid, cpu->eip);
        for (int i = 0; i < 8; i++) {
            uint8_t b;
            if (user_get(cpu->eip + i, b))
                break;
            printk("%02x ", b);
        }
        printk("\n");
        dump_stack(8);
        struct siginfo_ info = {
            .code = SI_KERNEL_,
            .fault.addr = cpu->eip,
        };
        deliver_signal(current, SIGILL_, info);
    } else if (interrupt == INT_BREAKPOINT) {
        lock(&pids_lock);
        send_signal(current, SIGTRAP_, (struct siginfo_) {
            .sig = SIGTRAP_,
            .code = SI_KERNEL_,
        });
        unlock(&pids_lock);
    } else if (interrupt == INT_DEBUG) {
        lock(&pids_lock);
        send_signal(current, SIGTRAP_, (struct siginfo_) {
            .sig = SIGTRAP_,
            .code = TRAP_TRACE_,
        });
        unlock(&pids_lock);
    } else if (interrupt != INT_TIMER) {
        printk("%d unhandled interrupt %d\n", current->pid, interrupt);
        sys_exit(interrupt);
    }

    receive_signals();
    struct tgroup *group = current->group;
    lock(&group->lock);
    while (group->stopped)
        wait_for_ignore_signals(&group->stopped_cond, &group->lock, NULL);
    unlock(&group->lock);
}

void dump_maps(void) {
    extern void proc_maps_dump(struct task *task, struct proc_data *buf);
    struct proc_data buf = {};
    proc_maps_dump(current, &buf);
    // go a line at a time because it can be fucking enormous
    char *orig_data = buf.data;
    while (buf.size > 0) {
        size_t chunk_size = buf.size;
        if (chunk_size > 1024)
            chunk_size = 1024;
        printk("%.*s", chunk_size, buf.data);
        buf.data += chunk_size;
        buf.size -= chunk_size;
    }
    free(orig_data);
}

void dump_mem(addr_t start, uint_t len) {
    const int width = 8;
    for (addr_t addr = start; addr < start + len; addr += sizeof(dword_t)) {
        unsigned from_left = (addr - start) / sizeof(dword_t) % width;
        if (from_left == 0)
            printk("%08x: ", addr);
        dword_t word;
        if (user_get(addr, word))
            break;
        printk("%08x ", word);
        if (from_left == width - 1)
            printk("\n");
    }
}

void dump_stack(int lines) {
    printk("stack at %x, base at %x, ip at %x\n", current->cpu.esp, current->cpu.ebp, current->cpu.eip);
    dump_mem(current->cpu.esp, lines * sizeof(dword_t) * 8);
}

// TODO find a home for this
#ifdef LOG_OVERRIDE
int log_override = 0;
#endif
