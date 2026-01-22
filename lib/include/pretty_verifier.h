/*
 * pretty_verifier.h
 * Public API for the pretty-verifier C wrapper.
 */

#ifndef PRETTY_VERIFIER_H
#define PRETTY_VERIFIER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes */
enum {
    PV_SUCCESS          =  0, /* Success */
    PV_ERR_GENERIC      = -1, /* Generic error */
    PV_ERR_TRUNCATED    = -2, /* Success, but output was truncated */
    PV_ERR_NOT_FOUND    = -3, /* 'pretty-verifier' command not found in PATH */
    PV_ERR_NO_ACCESS    = -4  /* Command found but permission denied */
};

/* Configuration options */
struct pretty_verifier_opts {
    const char *source_paths;   /* Path to C source files, separated by a space */
    const char *bytecode_path; /* Path to ELF/Bytecode file */
    int enumerate;             /* 1 to enable error enumeration, 0 to disable */
};

/**
 * Formats a raw eBPF verifier log using the pretty-verifier tool.
 *
 * @param raw_log      The raw verifier log string.
 * @param opts         Options struct (can be NULL).
 * @param buffer       Destination buffer.
 * @param buffer_size  Size of the destination buffer.
 *
 * @return Bytes written (>=0) or a negative PV_ERR_* code.
 */
int pretty_verifier(const char *raw_log, 
                           const struct pretty_verifier_opts *opts, 
                           char *buffer, 
                           size_t buffer_size);


#ifdef __cplusplus
}
#endif

#endif // PRETTY_VERIFIER_H