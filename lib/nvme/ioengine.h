#ifndef FIO_IOENGINE_H
#define FIO_IOENGINE_H
#include <libaio.h>

typedef struct iocb_ses_ctx {
	TAILQ_HEAD(aio_iocb_queue,iocb_entry) iocb_q;
	rte_rwlock_t slock;
	int aio_mode;
}iocb_ses_ctx_t;

struct iocb_new {
	__u64   aio_data; 
	short		aio_lio_opcode;	
	short		aio_reqprio;
	int		aio_fildes;
	 __u32   aio_flags;
	union {
		struct io_iocb_common		c;
		struct io_iocb_vector		v;
		struct io_iocb_poll		poll;
		struct io_iocb_sockaddr	saddr;
	} u;
};


struct iocb_entry {
	TAILQ_ENTRY(iocb_entry) next;
	struct iocb_new iocb;
};

#endif
