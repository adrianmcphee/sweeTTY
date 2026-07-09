//go:build linux && (amd64 || arm64)

package main

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Offsets into the kernel's seccomp_data struct (linux/seccomp.h): the syscall
// number leads, the audit arch follows.
const (
	seccompDataNR   = 0
	seccompDataArch = 4
)

// lockdownSyscalls installs a seccomp-bpf filter that permanently denies the
// syscalls a honeypot never issues but a memory-corruption RCE in a dependency or
// the Go runtime would need to break out of the process: exec (no second-stage
// binary or shell), ptrace (no sibling-process code injection), and the kernel
// module / kexec loaders (no kernel persistence). It is the runtime backstop the
// import guard cannot provide and that systemd cannot either: SystemCallFilter
// cannot drop execve for the main service, since systemd needs execve to launch it,
// but the binary can drop it once its own runtime is up. It also protects when the
// binary runs outside systemd (a container, a dev box).
//
// The filter is default-ALLOW, so clone/futex/mmap/mprotect/epoll/accept and every
// other syscall the Go scheduler and network stack rely on keep working untouched;
// only the named entries are killed. TSYNC applies it to every Go M-thread, not
// just the calling one. The leading arch check kills any syscall arriving on a
// non-native ABI, closing the x32/compat number-aliasing bypass.
func lockdownSyscalls() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}

	insn := func(code uint16, jt, jf uint8, k uint32) unix.SockFilter {
		return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
	}
	denied := []uint32{
		unix.SYS_EXECVE, unix.SYS_EXECVEAT, unix.SYS_PTRACE,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
		unix.SYS_KEXEC_LOAD,
	}

	filter := []unix.SockFilter{
		// Load the audit arch; if it is not this build's native arch, kill.
		insn(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0, 0, seccompDataArch),
		insn(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 1, 0, auditArch),
		insn(unix.BPF_RET|unix.BPF_K, 0, 0, unix.SECCOMP_RET_KILL_PROCESS),
		// Load the syscall number for the comparisons that follow.
		insn(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0, 0, seccompDataNR),
	}
	for _, nr := range denied {
		filter = append(filter,
			insn(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 1, nr),
			insn(unix.BPF_RET|unix.BPF_K, 0, 0, unix.SECCOMP_RET_KILL_PROCESS),
		)
	}
	filter = append(filter, insn(unix.BPF_RET|unix.BPF_K, 0, 0, unix.SECCOMP_RET_ALLOW))

	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(&prog)),
	); errno != 0 {
		return errno
	}
	return nil
}
