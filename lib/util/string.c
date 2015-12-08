#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "omnios/string.h"

char *
sprintf_alloc(const char *format, ...)
{
	va_list args;
	char *buf;
	size_t bufsize;
	int rc;

	/* Try with a small buffer first. */
	bufsize = 32;

	/* Limit maximum buffer size to something reasonable so we don't loop forever. */
	while (bufsize <= 1024 * 1024) {
		buf = malloc(bufsize);
		if (buf == NULL) {
			return NULL;
		}

		va_start(args, format);
		rc = vsnprintf(buf, bufsize, format, args);
		va_end(args);

		/*
		 * If vsnprintf() returned a count within our current buffer size, we are done.
		 * The count does not include the \0 terminator, so rc == bufsize is not OK.
		 */
		if (rc >= 0 && (size_t)rc < bufsize) {
			return buf;
		}

		/*
		 * vsnprintf() should return the required space, but some libc versions do not
		 * implement this correctly, so just double the buffer size and try again.
		 *
		 * We don't need the data in buf, so rather than realloc(), use free() and malloc()
		 * again to avoid a copy.
		 */
		free(buf);
		bufsize *= 2;
	}

	return NULL;
}
