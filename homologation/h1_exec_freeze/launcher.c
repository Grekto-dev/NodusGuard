#define _GNU_SOURCE
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    int arg_off = 1;
    int use_gate = 0;
    if (argc >= 2 && strcmp(argv[1], "--gate") == 0) {
        use_gate = 1;
        arg_off = 2;
    }
    if (argc - arg_off < 3) {
        fprintf(stderr, "Uso: %s [--gate] <fork|vfork|posix_spawn> <marker_bin> <out_file>\n", argv[0]);
        return 2;
    }
    const char *mode = argv[arg_off];
    char *marker_bin = argv[arg_off + 1];
    char *out_file = argv[arg_off + 2];
    char *child_argv[] = {marker_bin, out_file, NULL};
    pid_t pid = -1;
    int status = 0;

    if (use_gate) {
        printf("READY\n");
        fflush(stdout);
        int ch = getchar();
        if (ch == EOF) {
            fprintf(stderr, "Gate fechado antes da liberacao\n");
            return 1;
        }
    }

    if (strcmp(mode, "fork") == 0) {
        pid = fork();
        if (pid == 0) {
            execve(marker_bin, child_argv, environ);
            _exit(127);
        }
    } else if (strcmp(mode, "vfork") == 0) {
        pid = vfork();
        if (pid == 0) {
            execve(marker_bin, child_argv, environ);
            _exit(127);
        }
    } else if (strcmp(mode, "posix_spawn") == 0) {
        int rc = posix_spawn(&pid, marker_bin, NULL, NULL, child_argv, environ);
        if (rc != 0) {
            fprintf(stderr, "posix_spawn failed: %d\n", rc);
            return 1;
        }
    } else {
        fprintf(stderr, "Modo invalido: %s\n", mode);
        return 2;
    }

    if (pid < 0) {
        perror("spawn");
        return 1;
    }
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "Child falhou status=%d\n", status);
        return 1;
    }
    return 0;
}
