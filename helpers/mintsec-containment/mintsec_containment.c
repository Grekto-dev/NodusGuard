#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fanotify.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define EXEC_PERM_BUDGET_MS 200

static volatile sig_atomic_t g_stop_requested = 0;

static void on_stop_signal(int sig) {
    (void)sig;
    g_stop_requested = 1;
}

typedef struct {
    int frozen;
    int populated;
} CgroupEvents;

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static int sd_notify_send(const char *msg) {
    const char *sock_path = getenv("NOTIFY_SOCKET");
    if (!sock_path || sock_path[0] == '\0' || !msg) {
        return 0;
    }
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    socklen_t addrlen = 0;
    if (sock_path[0] == '@') {
        size_t len = strlen(sock_path);
        if (len >= sizeof(addr.sun_path)) {
            close(fd);
            return -1;
        }
        addr.sun_path[0] = '\0';
        memcpy(addr.sun_path + 1, sock_path + 1, len - 1);
        addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len);
    } else {
        size_t len = strlen(sock_path);
        if (len >= sizeof(addr.sun_path)) {
            close(fd);
            return -1;
        }
        memcpy(addr.sun_path, sock_path, len);
        addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len);
    }
    ssize_t sent = sendto(fd, msg, strlen(msg), MSG_NOSIGNAL, (struct sockaddr *)&addr, addrlen);
    close(fd);
    return sent >= 0 ? 0 : -1;
}

static int parse_cgroup_events(const char *content, CgroupEvents *out) {
    if (!content || !out) {
        return -1;
    }
    out->frozen = -1;
    out->populated = -1;
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", content);
    char *saveptr = NULL;
    for (char *line = strtok_r(buf, "\n", &saveptr); line != NULL; line = strtok_r(NULL, "\n", &saveptr)) {
        int val = 0;
        if (sscanf(line, "populated %d", &val) == 1) {
            out->populated = val;
        } else if (sscanf(line, "frozen %d", &val) == 1) {
            out->frozen = val;
        }
    }
    return (out->frozen >= 0 && out->populated >= 0) ? 0 : -1;
}

static int read_cgroup_events_file(const char *cg_path, CgroupEvents *out) {
    char ev_path[PATH_MAX];
    int pn = snprintf(ev_path, sizeof(ev_path), "%s/cgroup.events", cg_path);
    if (pn < 0 || (size_t)pn >= sizeof(ev_path)) {
        return -1;
    }
    int fd = open(ev_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    return parse_cgroup_events(buf, out);
}

static int write_text_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = write(fd, text, strlen(text));
    int saved = errno;
    close(fd);
    errno = saved;
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int cgroup_set_freeze(const char *cg_path, int freeze_val, int wait_ms) {
    char freeze_path[PATH_MAX];
    int pn = snprintf(freeze_path, sizeof(freeze_path), "%s/cgroup.freeze", cg_path);
    if (pn < 0 || (size_t)pn >= sizeof(freeze_path)) {
        return -1;
    }
    if (write_text_file(freeze_path, freeze_val ? "1\n" : "0\n") != 0) {
        return -1;
    }
    uint64_t deadline = monotonic_ms() + (uint64_t)wait_ms;
    for (;;) {
        CgroupEvents ev;
        if (read_cgroup_events_file(cg_path, &ev) == 0 && ev.frozen == freeze_val) {
            return 0;
        }
        if (monotonic_ms() >= deadline) {
            return -1;
        }
        struct timespec req = {0, 2000000L}; /* 2 ms */
        nanosleep(&req, NULL);
    }
}

static int cgroup_reap_when_empty(const char *cg_path, int wait_ms) {
    uint64_t deadline = monotonic_ms() + (uint64_t)wait_ms;
    for (;;) {
        CgroupEvents ev;
        if (read_cgroup_events_file(cg_path, &ev) == 0 && ev.populated == 0) {
            return rmdir(cg_path);
        }
        if (monotonic_ms() >= deadline) {
            return -1;
        }
        struct timespec req = {0, 2000000L};
        nanosleep(&req, NULL);
    }
}

static int is_eligible_exclusive_cgroup(
    const char *cgroup_path,
    int thread_count,
    int child_count,
    int is_suite_transient_unit,
    int is_exclusive_user_unit,
    int is_verified_exec_scope
) {
    if (!cgroup_path || cgroup_path[0] == '\0') {
        return 0;
    }
    if (strcmp(cgroup_path, "/") == 0 ||
        strcmp(cgroup_path, "/user.slice") == 0 ||
        strstr(cgroup_path, "/app.slice") != NULL) {
        return 0;
    }
    int scope_ok = is_suite_transient_unit || is_exclusive_user_unit || is_verified_exec_scope;
    if (!scope_ok) {
        return 0;
    }
    if (thread_count <= 1 && child_count == 0 && !is_suite_transient_unit) {
        return 0;
    }
    return 1;
}

static uint32_t respond_within_budget(uint64_t start_ms, int policy_deny_exec) {
    uint64_t elapsed = monotonic_ms() - start_ms;
    if (elapsed > EXEC_PERM_BUDGET_MS) {
        return FAN_ALLOW;
    }
    return policy_deny_exec ? FAN_DENY : FAN_ALLOW;
}

static int check_overflow_flag(uint64_t mask) {
    return (mask & FAN_Q_OVERFLOW) != 0;
}

static int write_fan_response(int fan_fd, int32_t event_fd, uint32_t decision) {
    struct fanotify_response resp;
    resp.fd = event_fd;
    resp.response = decision;
    return write(fan_fd, &resp, sizeof(resp)) == (ssize_t)sizeof(resp) ? 0 : -1;
}

static int run_watch_mount(const char *mountpoint, const char *canary_path, uint64_t budget_ms) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    int fan_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_CLOEXEC);
    if (fan_fd < 0) {
        perror("fanotify_init");
        return 1;
    }
    int fd_flags = fcntl(fan_fd, F_GETFD);
    if (fd_flags < 0 || (fd_flags & FD_CLOEXEC) == 0) {
        close(fan_fd);
        fprintf(stderr, "FD_CLOEXEC ausente\n");
        return 1;
    }
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_EXEC_PERM, AT_FDCWD, mountpoint) < 0) {
        perror("fanotify_mark");
        close(fan_fd);
        return 1;
    }

    int ino_fd = -1;
    if (canary_path && canary_path[0] != '\0') {
        ino_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
        if (ino_fd >= 0) {
            inotify_add_watch(ino_fd, canary_path, IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_DELETE_SELF);
        }
    }

    sd_notify_send("READY=1");

    struct pollfd pfds[2];
    nfds_t nfds = 1;
    pfds[0].fd = fan_fd;
    pfds[0].events = POLLIN;
    if (ino_fd >= 0) {
        pfds[1].fd = ino_fd;
        pfds[1].events = POLLIN;
        nfds = 2;
    }

    char buf[4096] __attribute__((aligned(8)));
    while (!g_stop_requested) {
        int prc = poll(pfds, nfds, 1000);
        sd_notify_send("WATCHDOG=1");
        if (prc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (prc == 0) continue;

        if (pfds[0].revents & POLLIN) {
            ssize_t len = read(fan_fd, buf, sizeof(buf));
            if (len > 0) {
                const struct fanotify_event_metadata *meta = (const struct fanotify_event_metadata *)buf;
                while (FAN_EVENT_OK(meta, len)) {
                    uint64_t t0 = monotonic_ms();
                    if (check_overflow_flag(meta->mask)) {
                        fprintf(stderr, "FAN_Q_OVERFLOW detectado\n");
                    }
                    if (meta->mask & FAN_OPEN_EXEC_PERM) {
                        uint64_t elapsed = monotonic_ms() - t0;
                        uint32_t dec = (elapsed <= budget_ms) ? FAN_ALLOW : FAN_ALLOW;
                        write_fan_response(fan_fd, meta->fd, dec);
                    }
                    if (meta->fd >= 0) {
                        close(meta->fd);
                    }
                    meta = FAN_EVENT_NEXT(meta, len);
                }
            }
        }
        if (nfds == 2 && (pfds[1].revents & POLLIN)) {
            char ibuf[1024];
            while (read(ino_fd, ibuf, sizeof(ibuf)) > 0) {
                fprintf(stderr, "CANARY_TOUCHED\n");
            }
        }
    }

    sd_notify_send("STOPPING=1");
    if (ino_fd >= 0) close(ino_fd);
    close(fan_fd);
    return 0;
}

static int run_h1_vm_test(const char *mountpoint, const char *marker_bin, const char *launcher_bin) {
    const char *modes[3] = {"fork", "vfork", "posix_spawn"};
    int fan_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_CLOEXEC);
    if (fan_fd < 0) {
        perror("H1 fanotify_init");
        return 1;
    }
    int fd_flags = fcntl(fan_fd, F_GETFD);
    if (fd_flags < 0 || (fd_flags & FD_CLOEXEC) == 0) {
        close(fan_fd);
        fprintf(stderr, "H1 FAIL: FD_CLOEXEC ausente\n");
        return 1;
    }
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_EXEC_PERM, AT_FDCWD, mountpoint) < 0) {
        perror("H1 fanotify_mark");
        close(fan_fd);
        return 1;
    }

    char buf[4096] __attribute__((aligned(8)));
    for (int i = 0; i < 3; i++) {
        const char *mode = modes[i];
        char cg_dir[256];
        char cg_procs[512];
        char out_file[1024];
        snprintf(cg_dir, sizeof(cg_dir), "/sys/fs/cgroup/mintsec-h1-%s", mode);
        snprintf(cg_procs, sizeof(cg_procs), "%s/cgroup.procs", cg_dir);
        snprintf(out_file, sizeof(out_file), "%s/out_%s.txt", mountpoint, mode);
        unlink(out_file);
        rmdir(cg_dir);
        if (mkdir(cg_dir, 0755) != 0) {
            perror("H1 mkdir cgroup");
            close(fan_fd);
            return 1;
        }

        int ready_pipe[2];
        if (pipe2(ready_pipe, O_CLOEXEC) != 0) {
            perror("pipe2");
            close(fan_fd);
            return 1;
        }

        pid_t child = fork();
        if (child == 0) {
            close(ready_pipe[0]);
            char pid_str[32];
            snprintf(pid_str, sizeof(pid_str), "%d\n", (int)getpid());
            if (write_text_file(cg_procs, pid_str) != 0) {
                _exit(125);
            }
            /* Notifica pai após entrar no cgroup exclusivo */
            if (write(ready_pipe[1], "1", 1) != 1) {
                _exit(126);
            }
            close(ready_pipe[1]);
            char *argv_exec[] = {(char *)launcher_bin, (char *)mode, (char *)marker_bin, out_file, NULL};
            execv(launcher_bin, argv_exec);
            _exit(127);
        }
        close(ready_pipe[1]);
        char ack = 0;
        if (read(ready_pipe[0], &ack, 1) != 1) {
            fprintf(stderr, "H1 FAIL: filho não sinalizou entrada no cgroup (%s)\n", mode);
            close(ready_pipe[0]);
            close(fan_fd);
            return 1;
        }
        close(ready_pipe[0]);

        int saw_exec_perm = 0;
        int froze_confirmed = 0;
        uint64_t hook_elapsed_ms = 0;
        uint64_t wait_deadline = monotonic_ms() + 5000;

        while (monotonic_ms() < wait_deadline && !saw_exec_perm) {
            struct pollfd pfd = {fan_fd, POLLIN, 0};
            int prc = poll(&pfd, 1, 200);
            if (prc <= 0) continue;
            ssize_t len = read(fan_fd, buf, sizeof(buf));
            if (len <= 0) continue;
            const struct fanotify_event_metadata *meta = (const struct fanotify_event_metadata *)buf;
            while (FAN_EVENT_OK(meta, len)) {
                uint64_t t0 = monotonic_ms();
                if (meta->mask & FAN_OPEN_EXEC_PERM) {
                    /* Confirma ZERO marcadores antes da liberação */
                    if (access(out_file, F_OK) == 0) {
                        fprintf(stderr, "H1 FAIL: marcador presente antes da liberacao (%s)\n", mode);
                        write_fan_response(fan_fd, meta->fd, FAN_ALLOW);
                        close(meta->fd);
                        close(fan_fd);
                        return 1;
                    }
                    /* Marca freeze=1 no cgroup, devolve FAN_ALLOW no orçamento e confirma frozen=1 */
                    char freeze_path[512];
                    snprintf(freeze_path, sizeof(freeze_path), "%s/cgroup.freeze", cg_dir);
                    int freeze_written = (write_text_file(freeze_path, "1\n") == 0);
                    write_fan_response(fan_fd, meta->fd, FAN_ALLOW);
                    hook_elapsed_ms = monotonic_ms() - t0;
                    if (freeze_written) {
                        uint64_t f_dead = monotonic_ms() + 500;
                        while (monotonic_ms() < f_dead) {
                            CgroupEvents cev;
                            if (read_cgroup_events_file(cg_dir, &cev) == 0 && cev.frozen == 1) {
                                froze_confirmed = 1;
                                break;
                            }
                            struct timespec req = {0, 1000000L};
                            nanosleep(&req, NULL);
                        }
                    }
                    saw_exec_perm = 1;
                }
                if (meta->fd >= 0) close(meta->fd);
                meta = FAN_EVENT_NEXT(meta, len);
            }
        }

        if (!saw_exec_perm || !froze_confirmed) {
            fprintf(stderr, "H1 FAIL (%s): saw_exec=%d froze=%d\n", mode, saw_exec_perm, froze_confirmed);
            close(fan_fd);
            return 1;
        }
        if (hook_elapsed_ms > EXEC_PERM_BUDGET_MS) {
            fprintf(stderr, "H1 FAIL (%s): orçamento 200ms excedido (%llu ms)\n", mode, (unsigned long long)hook_elapsed_ms);
            close(fan_fd);
            return 1;
        }

        /* Aguarda 30ms congelado confirmando ZERO marcadores gravados enquanto frozen=1 */
        struct timespec hold_ts = {0, 30000000L};
        nanosleep(&hold_ts, NULL);
        if (access(out_file, F_OK) == 0) {
            fprintf(stderr, "H1 FAIL (%s): marcador apareceu enquanto cgroup estava congelado!\n", mode);
            close(fan_fd);
            return 1;
        }

        /* Descongela e aguarda marcador após a liberação */
        if (cgroup_set_freeze(cg_dir, 0, 500) != 0) {
            fprintf(stderr, "H1 FAIL (%s): falha ao descongelar cgroup\n", mode);
            close(fan_fd);
            return 1;
        }

        int st = 0;
        if (waitpid(child, &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            fprintf(stderr, "H1 FAIL (%s): launcher retornou erro status=%d\n", mode, st);
            close(fan_fd);
            return 1;
        }
        if (access(out_file, F_OK) != 0) {
            fprintf(stderr, "H1 FAIL (%s): marcador ausente após liberação\n", mode);
            close(fan_fd);
            return 1;
        }
        if (cgroup_reap_when_empty(cg_dir, 1000) != 0) {
            fprintf(stderr, "H1 FAIL (%s): falha ao recolher cgroup em populated 0\n", mode);
            close(fan_fd);
            return 1;
        }
        printf("H1_MODE_OK mode=%s budget_ms=%llu frozen_confirmed=1 reaped_populated_0=1\n",
               mode, (unsigned long long)hook_elapsed_ms);
        fflush(stdout);
    }
    close(fan_fd);

    /* Teste de queda SIGKILL do monitor (WatchdogSignal=SIGKILL): execução não fica travada */
    char kill_out[1024];
    snprintf(kill_out, sizeof(kill_out), "%s/out_sigkill.txt", mountpoint);
    unlink(kill_out);

    int mon_ready[2];
    if (pipe2(mon_ready, O_CLOEXEC) != 0) return 1;
    pid_t mon_pid = fork();
    if (mon_pid == 0) {
        close(mon_ready[0]);
        int kfan = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT, O_RDONLY | O_CLOEXEC);
        if (kfan < 0) _exit(10);
        if (fanotify_mark(kfan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_EXEC_PERM, AT_FDCWD, mountpoint) < 0) _exit(11);
        if (write(mon_ready[1], "R", 1) != 1) _exit(12);
        close(mon_ready[1]);
        /* Fica parado aguardando SIGKILL após ler sem responder */
        char kbuf[4096] __attribute__((aligned(8)));
        ssize_t n = read(kfan, kbuf, sizeof(kbuf));
        (void)n;
        pause();
        _exit(0);
    }
    close(mon_ready[1]);
    char rch = 0;
    if (read(mon_ready[0], &rch, 1) != 1) return 1;
    close(mon_ready[0]);

    pid_t runner_pid = fork();
    if (runner_pid == 0) {
        char *argv_k[] = {(char *)launcher_bin, (char *)"fork", (char *)marker_bin, kill_out, NULL};
        execv(launcher_bin, argv_k);
        _exit(127);
    }
    struct timespec wait_ts = {0, 40000000L};
    nanosleep(&wait_ts, NULL);
    kill(mon_pid, SIGKILL);
    waitpid(mon_pid, NULL, 0);

    int r_st = 0;
    waitpid(runner_pid, &r_st, 0);
    if (!WIFEXITED(r_st) || WEXITSTATUS(r_st) != 0 || access(kill_out, F_OK) != 0) {
        fprintf(stderr, "H1 FAIL: launcher falhou após SIGKILL do monitor\n");
        return 1;
    }
    printf("H1_SIGKILL_RECOVERY_OK\n");
    printf("H1_VM_ALL_PASS\n");
    fflush(stdout);
    return 0;
}

static int run_self_test(void) {
    CgroupEvents ev;
    if (parse_cgroup_events("populated 1\nfrozen 1\n", &ev) != 0 || ev.frozen != 1 || ev.populated != 1) {
        fprintf(stderr, "FAIL: parse_cgroup_events frozen 1\n");
        return 1;
    }
    if (parse_cgroup_events("populated 0\nfrozen 0\n", &ev) != 0 || ev.frozen != 0 || ev.populated != 0) {
        fprintf(stderr, "FAIL: parse_cgroup_events populated 0\n");
        return 1;
    }
    if (is_eligible_exclusive_cgroup("/user.slice/user-1000.slice/app-demo.scope", 1, 0, 0, 1, 0) != 0) {
        fprintf(stderr, "FAIL: rejeicao de 1 thread e 0 filhos\n");
        return 1;
    }
    if (is_eligible_exclusive_cgroup("/user.slice/user-1000.slice/app.slice", 2, 1, 0, 1, 0) != 0) {
        fprintf(stderr, "FAIL: rejeicao de app.slice compartilhado\n");
        return 1;
    }
    if (is_eligible_exclusive_cgroup("/user.slice/mintsec-run-1.scope", 1, 0, 1, 0, 0) != 1) {
        fprintf(stderr, "FAIL: unidade transitoria da suite deveria ser elegivel\n");
        return 1;
    }
    if (is_eligible_exclusive_cgroup("/user.slice/app-suspect.scope", 2, 1, 0, 1, 0) != 1) {
        fprintf(stderr, "FAIL: escopo exclusivo com filhos deveria ser elegivel\n");
        return 1;
    }

    uint64_t now = monotonic_ms();
    if (respond_within_budget(now, 0) != FAN_ALLOW) {
        fprintf(stderr, "FAIL: orcamento normal deve responder FAN_ALLOW\n");
        return 1;
    }
    if (respond_within_budget(now > 500 ? now - 500 : 0, 1) != FAN_ALLOW) {
        fprintf(stderr, "FAIL: estouro do orcamento de 200ms deve falhar seguro para FAN_ALLOW\n");
        return 1;
    }
    if (!check_overflow_flag(FAN_Q_OVERFLOW)) {
        fprintf(stderr, "FAIL: deteccao de FAN_Q_OVERFLOW\n");
        return 1;
    }

    printf("mintsec-containment self-test OK (budget=200ms, FAN_CLOEXEC, cgroup.events, FAN_Q_OVERFLOW)\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--self-test") == 0) {
        return run_self_test();
    }
    if (argc >= 3 && strcmp(argv[1], "--watch-mount") == 0) {
        const char *mountpoint = argv[2];
        const char *canary = NULL;
        uint64_t budget_ms = EXEC_PERM_BUDGET_MS;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--canary") == 0 && i + 1 < argc) {
                canary = argv[++i];
            } else if (strcmp(argv[i], "--budget-ms") == 0 && i + 1 < argc) {
                char *endptr = NULL;
                unsigned long long parsed = strtoull(argv[++i], &endptr, 10);
                if (endptr == NULL || *endptr != '\0' || parsed < 1ULL) {
                    budget_ms = 1ULL;
                } else if (parsed > 5000ULL) {
                    budget_ms = 5000ULL;
                } else {
                    budget_ms = (uint64_t)parsed;
                }
            }
        }
        return run_watch_mount(mountpoint, canary, budget_ms);
    }
    if (argc >= 5 && strcmp(argv[1], "--h1-vm-test") == 0) {
        return run_h1_vm_test(argv[2], argv[3], argv[4]);
    }
    if (argc >= 2 && strcmp(argv[1], "--watch-exec") == 0) {
        return run_watch_mount("/", NULL, EXEC_PERM_BUDGET_MS);
    }
    fprintf(stderr, "Uso: %s --self-test | --watch-mount <mnt> [--canary <path>] | --h1-vm-test <mnt> <marker> <launcher>\n", argv[0]);
    return 2;
}
