/*
 * pretty_verifier.c
 * Implementation of the pretty-verifier C wrapper.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include "../include/pretty_verifier.h"

#define TEMP_CHUNK_SIZE 4096

int pretty_verifier(const char *raw_log, 
                           const struct pretty_verifier_opts *opts, 
                           char *buffer, 
                           size_t buffer_size) {
    int pipe_stdin[2];
    int pipe_stdout[2];
    pid_t pid;

    if (!raw_log || !buffer || buffer_size == 0) {
        return -1;
    }

    if (pipe(pipe_stdin) == -1 || pipe(pipe_stdout) == -1) {
        return -1;
    }

    pid = fork();
    if (pid == -1) {
        perror("pretty-verifier: fork failed");
        return -1;
    }

    // --- CHILD PROCESS ---
    if (pid == 0) {
        close(pipe_stdin[1]);
        close(pipe_stdout[0]);

        dup2(pipe_stdin[0], STDIN_FILENO); 
        dup2(pipe_stdout[1], STDOUT_FILENO);
        
        close(pipe_stdin[0]);
        close(pipe_stdout[1]);

        char *argv[10]; 
        int argc = 0;

        argv[argc++] = "pretty-verifier";

        if (opts) {
            if (opts->source_path) {
                argv[argc++] = "-c";
                argv[argc++] = (char *)opts->source_path;
            }
            if (opts->bytecode_path) {
                argv[argc++] = "-o";
                argv[argc++] = (char *)opts->bytecode_path;
            }
            if (opts->enumerate) {
                argv[argc++] = "-n";
            }
        }
        
        argv[argc] = NULL;

        execvp("pretty-verifier", argv);

        if (errno == ENOENT) {
            exit(127); // cmmand not found
        } else if (errno == EACCES) {
            exit(126); // permission denied
        } else {
            exit(1); 
        }
    } 
    
    // --- PARENT PROCESS ---
    else {

        close(pipe_stdin[0]); 
        close(pipe_stdout[1]);

        if (raw_log && strlen(raw_log) > 0) {
            write(pipe_stdin[1], raw_log, strlen(raw_log));
        }
        
        close(pipe_stdin[1]);

        size_t current_len = 0;
        size_t max_content_len = buffer_size - 1;
        ssize_t n_read;
        int truncated = 0;

        while (current_len < max_content_len) {
            n_read = read(pipe_stdout[0], buffer + current_len, max_content_len - current_len);
            if (n_read > 0) {
                current_len += n_read;
            } else {
                break; 
            }
        }

        char temp_buf[TEMP_CHUNK_SIZE];
        while ((n_read = read(pipe_stdout[0], temp_buf, sizeof(temp_buf))) > 0) {
            truncated = 1;

            size_t bytes_to_keep = (size_t)n_read;
            if (bytes_to_keep > max_content_len) {
                bytes_to_keep = max_content_len;
            }

            memmove(buffer, buffer + bytes_to_keep, max_content_len - bytes_to_keep);

            const char *src_ptr = temp_buf + (n_read - bytes_to_keep);
            memcpy(buffer + (max_content_len - bytes_to_keep), src_ptr, bytes_to_keep);
            
            current_len = max_content_len;
        }
        
        buffer[current_len] = '\0';
        
        close(pipe_stdout[0]);

        int status;
        waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);

            if (exit_code == 0) {
                if (truncated) return PV_ERR_TRUNCATED;
                return (int)current_len;
            }
            
            else if (exit_code == 127) {
                return PV_ERR_NOT_FOUND; 
            }
            else if (exit_code == 126) {
                return PV_ERR_NO_ACCESS;
            }
            else {
                return PV_ERR_GENERIC;
            }
        } else {
            return PV_ERR_GENERIC;
        }
    }
}