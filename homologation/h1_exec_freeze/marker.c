/* Binário estático benigno sem libc: grava marcador por syscall direta em _start. */
#include <fcntl.h>
#include <stdint.h>

static long sys3(long nr, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static long sys4(long nr, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

__attribute__((noreturn))
void c_entry(long argc, char **argv) {
    const char *path = (argc >= 2 && argv[1]) ? argv[1] : "/tmp/mintsec-marker.txt";
    /* x86_64 syscalls: openat=257, write=1, close=3, exit_group=231 */
    long fd = sys4(257, AT_FDCWD, (long)path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        static const char msg[] = "H1_MARKER_OK\n";
        sys3(1, fd, (long)msg, (long)(sizeof(msg) - 1));
        sys3(3, fd, 0, 0);
    }
    sys3(231, fd >= 0 ? 0 : 1, 0, 0);
    __builtin_unreachable();
}

__asm__(
    ".global _start\n"
    "_start:\n"
    "  mov (%rsp), %rdi\n"
    "  lea 8(%rsp), %rsi\n"
    "  and $-16, %rsp\n"
    "  call c_entry\n"
);
