#ifndef SPDK_QUEUE_H
#define SPDK_QUEUE_H

#include <sys/cdefs.h>
#include <sys/queue.h>

/*
 * The SPDK NVMe driver was originally ported from FreeBSD, which makes
 *  use of features in FreeBSD's queue.h that do not exist on Linux.
 *  Include a header with these additional features on Linux only.
 */
#ifndef __FreeBSD__
#include <spdk/queue_extras.h>
#endif

#endif
