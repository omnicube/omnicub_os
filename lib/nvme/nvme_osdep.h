#ifndef _NVME_OSDEP_H
#define _NVME_OSDEP_H

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/hdreg.h>
#include <rte_spinlock.h>
#include <rte_atomic.h>
#include <dlfcn.h>
#include <sys/sysinfo.h>
#define PCI_VENDOR_ID_INTEL 0x8086
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;
typedef int bool;
struct bio;
struct rcu_head;
struct work_struct;
struct notifier_block;
struct scatterlist;
typedef struct cpumask cpumask_t;
typedef unsigned long fmode_t;
#define	NOTIFY_DONE	0x0000
#define	NOTIFY_OK	0x0001

enum irqreturn {
	IRQ_NONE = (0 << 0),
	IRQ_HANDLED = (1 << 0),
	IRQ_WAKE_THREAD = (1 << 1),
};

struct kref {
	rte_atomic16_t refcount;
};

typedef rte_atomic16_t atomic_t;
#define kref_init(kref) rte_atomic16_init(kref.refcount)
#define kref_get(kref) rte_atomic16_inc(kref.refcount)

static inline void kref_put(struct kref *kref, void (*fn)(struct kref *))
{
	rte_atomic16_dec(&kref->refcount);

	if(rte_atomic16_read(&kref->refcount) == 0)
		fn(kref);
}

typedef	enum irqreturn irqreturn_t;
/*
* Kernel backward-compatibility defintions
*/
#ifndef ioread8
#define ioread8 readb
#endif
#ifndef ioread16
#define ioread16 readw
#endif
#ifndef ioread32
#define ioread32 readl
#endif
#ifndef iowrite8
#define iowrite8 writeb
#endif
#ifndef iowrite16
#define iowrite16 writew
#endif
#ifndef iowrite32
#define iowrite32 writel
#endif
#ifndef ioread64
#define ioread64 readq
#endif
#define readl(a) (*(unsigned volatile int *)(a))
#define readw(a) (*(unsigned volatile short *)(a))
#define readb(a) (*(unsigned volatile char *)(a))
#define readq(a) (*(unsigned volatile long *)(a))
#define writel(v, a) *(unsigned volatile int *)(a) = (v)
#define writew(v, a) *(unsigned volatile short *)(a) = (v)
#define writeb(v, a) *(unsigned volatile char *)(a) = (v)
#define writeq(v, a) *(unsigned volatile long *)(a) = (v)
#define HZ rte_get_timer_hz()
//#define jiffies rte_get_timer_cycles()
#define	jiffies	0
typedef unsigned long long dma_addr_t;
#define __iomem volatile
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BITS_PER_BYTE 8
typedef u64 sector_t;
#define __user
#define __bitwise__
typedef unsigned __bitwise__ gfp_t;
typedef struct pci_dev rte_pci_device;
typedef struct pci_device_id rte_pci_id;
#define	kcalloc(n, sz, val) calloc(n, sz)
#define kfree	free
#define kzalloc(sz, flag) calloc(1, sz)
#define kmalloc(sz, flag) malloc(sz)
#define	true	1
#define	false	0
#define msleep(n) rte_delay_us(n*1000)
#define typecheck(type,x) \
({ type __dummy; \
typeof(x) __dummy2; \
(void)(&__dummy == &__dummy2); \
1; \
})
#define min_t(type, x, y) ({ \
type __min1 = (x); \
type __min2 = (y); \
__min1 < __min2 ? __min1: __min2; })
#define min(a,b) (((a) < (b)) ? (a) : (b))
#define time_after(a,b) \
(typecheck(unsigned long, a) && \
typecheck(unsigned long, b) && \
((long)((b) - (a)) < 0))

struct msix_entry {
	u32 vector; /* kernel uses to write allocated vector */
	u16 entry; /* driver uses to specify entry, OS writes */
};

#define POISON_POINTER_DELTA 0
#define LIST_POISON1 ((void *) 0x00100100 + POISON_POINTER_DELTA)
#define LIST_POISON2 ((void *) 0x00200200 + POISON_POINTER_DELTA)

struct list_head {
	struct list_head *next, *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline __list_add(struct list_head *_new,
struct list_head *prev,

struct list_head *next)
{
	next->prev = _new;
	_new->next = next;
	_new->prev = prev;
	prev->next = _new;
}

#define container_of(ptr, type, member) ({ \
const typeof( ((type *)0)->member ) *__mptr = (ptr); \
(type *)( (char *)__mptr - offsetof(type, member) ); })
#define list_entry(ptr, type, member) \
container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
list_entry((ptr)->next, type, member)
#define list_next_entry(pos, member) \
list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_for_each_entry(pos, head, member) \
for (pos = list_entry((head)->next, typeof(*pos), member); \
&pos->member != (head); \
pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member) \
for (pos = list_first_entry(head, typeof(*pos), member), \
n = list_next_entry(pos, member); \
&pos->member != (head); \
pos = n, n = list_next_entry(n, member))

static inline void list_add_tail(struct list_head *_new, struct list_head *head)
{
	__list_add(_new, head->prev, head);
}

static inline void list_add(struct list_head *_new, struct list_head *head)
{
	__list_add(_new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = (struct list_head *) LIST_POISON1;
	entry->prev = (struct list_head *) LIST_POISON2;
}

static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static inline void list_del_init(struct list_head *entry)
{
	__list_del_entry(entry);
	INIT_LIST_HEAD(entry);
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

#define rcu_read_lock() { }
#define rcu_read_unlock() { }
#define dummy_lock(lock) { }
#define dummy_unlock(lock) { }
#ifdef __KERNEL__
#define	spinlock_t	rte_spinlock_t	
#define	spin_lock_init	rte_spinlock_init
#define	spin_lock	rte_spinlock_lock
#define	spin_unlock	rte_spinlock_unlock
#define	spin_lock_irq	spin_lock
#define	spin_unlock_irq	spin_unlock
#else
#define	spinlock_t	rte_spinlock_t	
#define	spin_lock_init	rte_spinlock_init
#define	spin_lock	dummy_lock
#define	spin_unlock dummy_unlock
#define	spin_lock_irq	dummy_lock
#define	spin_unlock_irq	dummy_unlock
/*
#define spinlock_t rte_atomic64_t
#define spin_lock_init rte_atomic64_init
#define spin_lock(lock) rte_atomic64_set(lock, 1)
#define spin_unlock(lock) rte_atomic64_set(lock, 0)
#define spin_lock_irq(lock) rte_atomic64_set(lock, 1)
#define spin_unlock_irq(lock) rte_atomic64_set(lock, 0) */
#endif
#define spin_lock_irqsave(lock, flags) \
{}
//spin_lock(lock)
#define spin_unlock_irqrestore(lock, flags) \
{}
//spin_unlock(lock)
#define	schedule_timeout(n) \
struct timespec dts = { 0, 0}; \
pthread_cond_t cond; \
pthread_mutex_t mutex; \
dts.tv_sec = time(NULL) + n; \
pthread_mutex_lock(&mutex); \
pthread_cond_timedwait(&cond, &mutex, &dts); \
pthread_mutex_unlock(&mutex);
#define cpu_to_le16(x) ((unsigned short)(x))
#define cpu_to_le32(x) ((unsigned int)(x))
#define cpu_to_le64(x) ((unsigned long long)(x))
#define le16_to_cpu(x) ((unsigned short)(x))
#define le32_to_cpu(x) ((unsigned int)(x))
#define le64_to_cpu(x) ((unsigned long long)(x))
#define le64_to_cpup(x) ((unsigned long long)(*x))
#define le32_to_cpup(x) ((unsigned int)(*x))
#define le16_to_cpup(x) ((unsigned short)(*x))
#define BITOP_WORD(nr) ((nr) / BITS_PER_LONG)
#define BITS_PER_LONG 64
unsigned long
find_next_zero_bit(const unsigned long *, unsigned long,
unsigned long);
unsigned long
find_first_zero_bit(const unsigned long *, unsigned long);
#define asm_volatile_goto(x...) do { asm goto(x); asm (""); } while (0)
#define __GEN_RMWcc(fullop, var, cc, ...) \
do { \
	asm_volatile_goto (fullop "; j" cc " %l[cc_label]" \
	: : "m" (var), ## __VA_ARGS__ \
	: "memory" : cc_label); \
	return 0; \
	cc_label: \
	return 1; \
} while (0)

#define GEN_BINARY_RMWcc(op, var, vcon, val, arg0, cc) \
__GEN_RMWcc(op " %1, " arg0, var, cc, vcon (val))

#define LOCK_PREFIX_HERE \
".pushsection .smp_locks,\"a\"\n" \
".balign 4\n" \
".long 671f - .\n" /* offset */ \
".popsection\n" \
"671:"

#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "
static inline int test_and_set_bit(long nr, volatile unsigned long *addr)
{
	GEN_BINARY_RMWcc(LOCK_PREFIX "bts", *addr, "Ir", nr, "%0", "c");
}

#define rdtscl(val) __asm__ __volatile__ ("rdtsc" : "=A" (val))
#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)
static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline void * ERR_PTR(long error)
{
	return (void *) error;
}

#define	current	pthread_self()
#define	DEFINE_SPINLOCK(x) rte_spinlock_t x = RTE_SPINLOCK_INITIALIZER
//#define DEFINE_SPINLOCK(x) rte_atomic64_t x = {0};

typedef struct wait_queue_head {
	spinlock_t lock;
	struct list_head task_list;
} wait_queue_head_t;

#define uninitialized_var(x) x = x
#define	GFP_KERNEL	0
#define PAGE_MASK (~(PAGE_SIZE-1))
#define offset_in_page(p) ((unsigned long)(p) & ~PAGE_MASK)
//#define min(x, y) x < y ? x : y;
#define	dev_err(dev, format, arg ...) \
printf(format, ##arg)
#define	dev_warn(dev, format, arg ...) \
printf(format, ##arg)
#include <assert.h>
#define	BUG_ON	assert
#define num_online_cpus()  sysconf(_SC_NPROCESSORS_ONLN)
#define num_possible_cpus() sysconf(_SC_NPROCESSORS_ONLN)
#define	PAGE_SHIFT	12
//#define PAGE_SIZE getpagesize()
#define	PAGE_SIZE	4096
#define rcu_dereference(p) p
#define rcu_dereference_raw(p) p
#include <rte_memzone.h>
#include <rte_ethdev.h>
static void * dma_alloc_coherent(struct pci_dev *dev, const char *ring_name, uint16_t qid,
				uint32_t ring_size, int sockid, dma_addr_t *addr)
{
	const struct rte_memzone *mz;
	mz = rte_memzone_lookup(ring_name);
	if (mz) {
	*addr = mz->phys_addr;
	return (mz->addr);
	}

	mz = rte_memzone_reserve_aligned(ring_name, ring_size, sockid, 0,
	PAGE_SIZE);
	//mz = rte_memzone_reserve(ring_name, ring_size, sockid, 0);
	if (!mz) {
		perror("memory reserve failed \n");
		printf("ring_size is %d\n", ring_size);
		assert(0);
	}

	*addr = mz->phys_addr;
	return (mz->addr);
}

struct hd_struct {
	sector_t nr_sects;
};

struct gendisk {
	char	disk_name[32];
	char disk_num;
	void	*private_data;
	struct hd_struct part0;
};

struct block_device {
	struct list_head list;
	struct	gendisk *bd_disk;
	unsigned long bd_private;
};

struct nvme_iostats {
    unsigned int read_ios;
    unsigned int read_sectors;
    uint64_t read_ticks;

    unsigned int write_ios;
    unsigned int write_sectors;
    uint64_t write_ticks;

    unsigned int in_flight;
    uint64_t io_ticks;
    uint64_t time_in_queue;
};

static inline sector_t get_capacity(struct gendisk *disk)
{
	return disk->part0.nr_sects;
}

static inline void set_capacity(struct gendisk *disk, sector_t size)
{
	disk->part0.nr_sects = size;
}

static struct gendisk *alloc_disk(int num)
{
	return (malloc(sizeof(struct gendisk)));
}

static void add_disk(struct gendisk *disk)
{
	if (open(disk->disk_name, O_RDWR | O_CREAT, 0644) < 0) {
		perror("open failed..\n");
	}
}

struct getcpu_cache {
	unsigned long blob[128 / sizeof(long)];
};

typedef long (*vgetcpu_fn)(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache);
static vgetcpu_fn  vgetcpu;

static int init_vgetcpu(void)
{
	void *vdso;
	dlerror();
	vdso = dlopen("linux-vdso.so.1", RTLD_LAZY);
	if (vdso == NULL)
	return -1;
	vgetcpu = dlsym(vdso, "__vdso_getcpu");
	dlclose(vdso);
	return vgetcpu == NULL ? -1 : 0;
}
#endif
