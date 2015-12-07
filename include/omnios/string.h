#ifndef SPDK_STRING_H
#define SPDK_STRING_H

/**
 * sprintf with automatic buffer allocation.
 *
 * The return value is the formatted string,
 * which should be passed to free() when no longer needed,
 * or NULL on failure.
 */
char *sprintf_alloc(const char *format, ...) __attribute__((format(printf, 1, 2)));

#endif
