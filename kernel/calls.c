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
    //[16]  = (syscall_t) sys_?,
    //[17]  = (syscall_t) sys_?,
    //[18]  = (syscall_t) sys_?,
    [19]  = (syscall_t) sys_lseek,
    [20]  = (syscall_t) sys_getpid,
    [21]  = (syscall_t) sys_mount,
    //[22]  = (syscall_t) sys_?,
    [23]  = (syscall_t) sys_setuid,
    [24]  = (syscall_t) sys_getuid,
    [25]  = (syscall_t) sys_stime,
    [26]  = (syscall_t) sys_ptrace,
    [27]  = (syscall_t) sys_alarm,
    //[28]  = (syscall_t) sys_?,
    [29]  = (syscall_t) sys_pause,
    [30]  = (syscall_t) sys_utime,
    //[31]  = (syscall_t) sys_?,
    //[32]  = (syscall_t) sys_?,
    [33]  = (syscall_t) sys_access,
    //[34]  = (syscall_t) sys_?,
    //[35]  = (syscall_t) sys_?,
    [36]  = (syscall_t) syscall_success_stub, // sync
    [37]  = (syscall_t) sys_kill,
    [38]  = (syscall_t) sys_rename,
    [39]  = (syscall_t) sys_mkdir,
    [40]  = (syscall_t) sys_rmdir,
    [41]  = (syscall_t) sys_dup,
    [42]  = (syscall_t) sys_pipe,
    [43]  = (syscall_t) sys_times,
    //[44]  = (syscall_t) sys_?,
    [45]  = (syscall_t) sys_brk,
    [46]  = (syscall_t) sys_setgid,
    [47]  = (syscall_t) sys_getgid,
    //[48]  = (syscall_t) sys_?,
    [49]  = (syscall_t) sys_geteuid,
    [50]  = (syscall_t) sys_getegid,
    //[51]  = (syscall_t) sys_?,
    [52]  = (syscall_t) sys_umount2,
    //[53]  = (syscall_t) sys_?,
    [54]  = (syscall_t) sys_ioctl,
    [55]  = (syscall_t) sys_fcntl32,
    //[56]  = (syscall_t) sys_?,
    [57]  = (syscall_t) sys_setpgid,
    //[58]  = (syscall_t) sys_?,
    //[59]  = (syscall_t) sys_?,
    [60]  = (syscall_t) sys_umask,
    [61]  = (syscall_t) sys_chroot,
    //[62]  = (syscall_t) sys_?,
    [63]  = (syscall_t) sys_dup2,
    [64]  = (syscall_t) sys_getppid,
    [65]  = (syscall_t) sys_getpgrp,
    [66]  = (syscall_t) sys_setsid,
    //[67]  = (syscall_t) sys_?,
    //[68]  = (syscall_t) sys_?,
    //[69]  = (syscall_t) sys_?,
    //[70]  = (syscall_t) sys_?,
    //[71]  = (syscall_t) sys_?,
    //[72]  = (syscall_t) sys_?,
    //[73]  = (syscall_t) sys_?,
    [74]  = (syscall_t) sys_sethostname,
    [75]  = (syscall_t) sys_setrlimit32,
    [76]  = (syscall_t) sys_old_getrlimit32,
    [77]  = (syscall_t) sys_getrusage,
    [78]  = (syscall_t) sys_gettimeofday,
    [79]  = (syscall_t) sys_settimeofday,
    [80]  = (syscall_t) sys_getgroups,
    [81]  = (syscall_t) sys_setgroups,
    //[82]  = (syscall_t) sys_?,
    [83]  = (syscall_t) sys_symlink,
    //[84]  = (syscall_t) sys_?,
    [85]  = (syscall_t) sys_readlink,
    //[86]  = (syscall_t) sys_?,
    //[87]  = (syscall_t) sys_?,
    [88]  = (syscall_t) sys_reboot,
    //[89]  = (syscall_t) sys_?,
    [90]  = (syscall_t) sys_mmap,
    [91]  = (syscall_t) sys_munmap,
    //[92]  = (syscall_t) sys_?,
    //[93]  = (syscall_t) sys_?,
    [94]  = (syscall_t) sys_fchmod,
    //[95]  = (syscall_t) sys_?,
    [96]  = (syscall_t) sys_getpriority,
    [97]  = (syscall_t) sys_setpriority,
    //[98]  = (syscall_t) sys_?,
    [99]  = (syscall_t) sys_statfs,
    [100] = (syscall_t) sys_fstatfs,
    //[101]  = (syscall_t) sys_?,
    [102] = (syscall_t) sys_socketcall,
    [103] = (syscall_t) sys_syslog,
    [104] = (syscall_t) sys_setitimer,
    //[105]  = (syscall_t) sys_?,
    //[106]  = (syscall_t) sys_?,
    //[107]  = (syscall_t) sys_?,
    //[108]  = (syscall_t) sys_?,
    //[109]  = (syscall_t) sys_?,
    //[110]  = (syscall_t) sys_?,
    //[111]  = (syscall_t) sys_?,
    //[112]  = (syscall_t) sys_?,
    //[113]  = (syscall_t) sys_?,
    [114] = (syscall_t) sys_wait4,
    //[115]  = (syscall_t) sys_?,
    [116] = (syscall_t) sys_sysinfo,
    [117] = (syscall_t) sys_ipc,
    [118] = (syscall_t) sys_fsync,
    [119] = (syscall_t) sys_sigreturn,
    [120] = (syscall_t) sys_clone,
    //[121]  = (syscall_t) sys_?,
    [122] = (syscall_t) sys_uname,
    //[123]  = (syscall_t) sys_?,
    //[124]  = (syscall_t) sys_?,
    [125] = (syscall_t) sys_mprotect,
    //[126]  = (syscall_t) sys_?,
    //[127]  = (syscall_t) sys_?,
    //[128]  = (syscall_t) sys_?,
    //[129]  = (syscall_t) sys_?,
    //[130]  = (syscall_t) sys_?,
    //[131]  = (syscall_t) sys_?,
    [132] = (syscall_t) sys_getpgid,
    [133] = (syscall_t) sys_fchdir,
    //[134]  = (syscall_t) sys_?,
    //[135]  = (syscall_t) sys_?,
    [136] = (syscall_t) sys_personality,
    //[137]  = (syscall_t) sys_?,
    //[138]  = (syscall_t) sys_?,
    //[139]  = (syscall_t) sys_?,
    [140] = (syscall_t) sys__llseek,
    [141] = (syscall_t) sys_getdents,
    [142] = (syscall_t) sys_select,
    [143] = (syscall_t) sys_flock,
    [144] = (syscall_t) sys_msync,
    [145] = (syscall_t) sys_readv,
    [146] = (syscall_t) sys_writev,
    [147] = (syscall_t) sys_getsid,
    [148] = (syscall_t) sys_fsync, // fdatasync
    //[149]  = (syscall_t) sys_?,
    [150] = (syscall_t) sys_mlock,
    //[151]  = (syscall_t) sys_?,
    //[152]  = (syscall_t) sys_?,
    //[153]  = (syscall_t) sys_?,
    //[154]  = (syscall_t) sys_?,
    [155] = (syscall_t) sys_sched_getparam,
    [156] = (syscall_t) sys_sched_setscheduler,
    [157] = (syscall_t) sys_sched_getscheduler,
    [158] = (syscall_t) sys_sched_yield,
    [159] = (syscall_t) sys_sched_get_priority_max,
    //[160]  = (syscall_t) sys_?,
    //[161]  = (syscall_t) sys_?,
    [162] = (syscall_t) sys_nanosleep,
    [163] = (syscall_t) sys_mremap,
    //[164]  = (syscall_t) sys_?,
    //[165]  = (syscall_t) sys_?,
    //[166]  = (syscall_t) sys_?,
    //[167]  = (syscall_t) sys_?,
    [168] = (syscall_t) sys_poll,
    //[169]  = (syscall_t) sys_?,
    //[170]  = (syscall_t) sys_?,
    //[171]  = (syscall_t) sys_?,
    [172] = (syscall_t) sys_prctl,
    [173] = (syscall_t) sys_rt_sigreturn,
    [174] = (syscall_t) sys_rt_sigaction,
    [175] = (syscall_t) sys_rt_sigprocmask,
    [176] = (syscall_t) sys_rt_sigpending,
    [177] = (syscall_t) sys_rt_sigtimedwait,
    //[178]  = (syscall_t) sys_?,
    [179] = (syscall_t) sys_rt_sigsuspend,
    [180] = (syscall_t) sys_pread,
    [181] = (syscall_t) sys_pwrite,
    //[182]  = (syscall_t) sys_?,
    [183] = (syscall_t) sys_getcwd,
    [184] = (syscall_t) sys_capget,
    [185] = (syscall_t) sys_capset,
    [186] = (syscall_t) sys_sigaltstack,
    [187] = (syscall_t) sys_sendfile,
    //[188]  = (syscall_t) sys_?,
    //[189]  = (syscall_t) sys_?,
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
    //[215]  = (syscall_t) sys_?,
    //[216]  = (syscall_t) sys_?,
    //[217]  = (syscall_t) sys_?,
    //[218]  = (syscall_t) sys_?,
    [219] = (syscall_t) sys_madvise,
    [220] = (syscall_t) sys_getdents64,
    [221] = (syscall_t) sys_fcntl,
    //[222]  = (syscall_t) sys_?,
    //[223]  = (syscall_t) sys_?,
    [224] = (syscall_t) sys_gettid,
    [225] = (syscall_t) syscall_success_stub, // readahead
    [226 ... 237] = (syscall_t) sys_xattr_stub,
    [238] = (syscall_t) sys_tkill,
    [239] = (syscall_t) sys_sendfile64,
    [240] = (syscall_t) sys_futex,
    [241] = (syscall_t) sys_sched_setaffinity,
    [242] = (syscall_t) sys_sched_getaffinity,
    [243] = (syscall_t) sys_set_thread_area,
    //[244]  = (syscall_t) sys_?,
    [245] = (syscall_t) syscall_stub, // io_setup
    //[246]  = (syscall_t) sys_?,
    //[247]  = (syscall_t) sys_?,
    //[248]  = (syscall_t) sys_?,
    //[249]  = (syscall_t) sys_?,
    //[250]  = (syscall_t) sys_?,
    //[251]  = (syscall_t) sys_?,
    [252] = (syscall_t) sys_exit_group,
    //[253]  = (syscall_t) sys_?,
    [254] = (syscall_t) sys_epoll_create0,
    [255] = (syscall_t) sys_epoll_ctl,
    [256] = (syscall_t) sys_epoll_wait,
    //[257]  = (syscall_t) sys_?,
    [258] = (syscall_t) sys_set_tid_address,
    [259] = (syscall_t) sys_timer_create,
    [260] = (syscall_t) sys_timer_settime,
    //[261]  = (syscall_t) sys_?,
    //[262]  = (syscall_t) sys_?,
    [263] = (syscall_t) sys_timer_delete,
    [264] = (syscall_t) sys_clock_settime,
    [265] = (syscall_t) sys_clock_gettime,
    [266] = (syscall_t) sys_clock_getres,
    //[267]  = (syscall_t) sys_?,
    [268] = (syscall_t) sys_statfs64,
    [269] = (syscall_t) sys_fstatfs64,
    [270] = (syscall_t) sys_tgkill,
    [271] = (syscall_t) sys_utimes,
    [272] = (syscall_t) syscall_success_stub,
    //[273]  = (syscall_t) sys_?,
    [274] = (syscall_t) sys_mbind,
    //[275]  = (syscall_t) sys_?,
    //[276]  = (syscall_t) sys_?,
    //[277]  = (syscall_t) sys_?,
    //[278]  = (syscall_t) sys_?,
    //[279]  = (syscall_t) sys_?,
    //[280]  = (syscall_t) sys_?,
    //[281]  = (syscall_t) sys_?,
    //[282]  = (syscall_t) sys_?,
    //[283]  = (syscall_t) sys_?,
    [284] = (syscall_t) sys_waitid,
    //[285]  = (syscall_t) sys_?,
    //[286]  = (syscall_t) sys_?,
    //[287]  = (syscall_t) sys_?,
    //[288]  = (syscall_t) sys_?,
    [289] = (syscall_t) sys_ioprio_set,
    [290] = (syscall_t) sys_ioprio_get,
    [291] = (syscall_t) syscall_stub, // inotify_init
    //[292]  = (syscall_t) sys_?,
    //[293]  = (syscall_t) sys_?,
    //[294]  = (syscall_t) sys_?,
    [295] = (syscall_t) sys_openat,
    [296] = (syscall_t) sys_mkdirat,
    [297] = (syscall_t) sys_mknodat,
    [298] = (syscall_t) sys_fchownat,
    //[299]  = (syscall_t) sys_?,
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
    //[310]  = (syscall_t) sys_?,
    [311] = (syscall_t) sys_set_robust_list,
    [312] = (syscall_t) sys_get_robust_list,
    [313] = (syscall_t) sys_splice,
    //[314]  = (syscall_t) sys_?,
    //[315]  = (syscall_t) sys_?,
    //[316]  = (syscall_t) sys_?,
    //[317]  = (syscall_t) sys_?,
    //[318]  = (syscall_t) sys_?,
    [319] = (syscall_t) sys_epoll_pwait,
    [320] = (syscall_t) sys_utimensat,
    //[321]  = (syscall_t) sys_?,
    [322] = (syscall_t) sys_timerfd_create,
    [323] = (syscall_t) sys_eventfd,
    [324] = (syscall_t) sys_fallocate,
    [325] = (syscall_t) sys_timerfd_settime,
    //[326]  = (syscall_t) sys_?,
    //[327]  = (syscall_t) sys_?,
    [328] = (syscall_t) sys_eventfd2,
    [329] = (syscall_t) sys_epoll_create,
    [330] = (syscall_t) sys_dup3,
    [331] = (syscall_t) sys_pipe2,
    [332] = (syscall_t) syscall_stub, // inotify_init1
    //[333]  = (syscall_t) sys_?,
    //[334]  = (syscall_t) sys_?,
    //[335]  = (syscall_t) sys_?,
    //[336]  = (syscall_t) sys_?,
    //[337]  = (syscall_t) sys_?,
    //[338]  = (syscall_t) sys_?,
    //[339]  = (syscall_t) sys_?,
    [340] = (syscall_t) sys_prlimit64,
    //[341]  = (syscall_t) sys_?,
    //[342]  = (syscall_t) sys_?,
    //[343]  = (syscall_t) sys_?,
    //[344]  = (syscall_t) sys_?,
    [345] = (syscall_t) sys_sendmmsg,
    //[346]  = (syscall_t) sys_?,
    //[347]  = (syscall_t) sys_?,
    //[348]  = (syscall_t) sys_?,
    //[349]  = (syscall_t) sys_?,
    //[350]  = (syscall_t) sys_?,
    //[351]  = (syscall_t) sys_?,
    [352] = (syscall_t) syscall_stub, // sched_getattr
    [353] = (syscall_t) sys_renameat2,
    //[354]  = (syscall_t) sys_?,
    [355] = (syscall_t) sys_getrandom,
    //[356]  = (syscall_t) sys_?,
    //[357]  = (syscall_t) sys_?,
    //[358]  = (syscall_t) sys_?,
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
    //[374]  = (syscall_t) sys_?,
    [375] = (syscall_t) syscall_silent_stub, // membarrier
    //[376]  = (syscall_t) sys_?,
    [377] = (syscall_t) sys_copy_file_range,
    //[378]  = (syscall_t) sys_?,
    //[379]  = (syscall_t) sys_?,
    //[380]  = (syscall_t) sys_?,
    //[381]  = (syscall_t) sys_?,
    //[382]  = (syscall_t) sys_?,
    [383] = (syscall_t) syscall_silent_stub, // statx
    [384] = (syscall_t) sys_arch_prctl,
    //to be continued
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
