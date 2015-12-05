#include <rte_nvm_interface.h>
#include <assert.h>
#include <rte_memzone.h>
#include <rte_atomic.h>
#include <linux/hdreg.h>
#include <sys/queue.h>
#include "uapi_nvme.h"
#include "nvme_osdep.h"

#define IO_MEMS (256)
#define DEV_BLOCK_SIZE 512

#define BUFF_SIZE	4096
#define SECTOR_SIZE 512
#define KEY_SIZE	128

extern struct list_head block_dev_list;
extern int nvme_ioctl(uint64_t, fmode_t, unsigned int, unsigned long);
static nvm_hdl_t nvmhdl[IO_MEMS] = {0};
static int hdlcnt = 0;
pthread_spinlock_t lock;

static uint64_t nvm_open(const char *devname, int flags, fmode_t mode)
{
	struct block_device *bdev;
	char dev_path[PATH_MAX];
	sprintf(dev_path, "%s", devname);

	list_for_each_entry(bdev, &block_dev_list, list) {

		if (strncmp(bdev->bd_disk->disk_name, dev_path,
		    strlen(dev_path)) == 0)
		{
			nvme_open(bdev, mode);
			return ((uint64_t)bdev);
		}
	}

	return 0;
}

static int nvm_close(nvmhdl_t hdl)
{
	struct block_device *bdev = (struct block_device *)hdl;
	nvme_release(bdev->bd_disk, 0);
	return 0;
}

static int nvm_get_iostats(nvmhdl_t hdl, nvm_iostats_t *io_stats)
{
	struct block_device *bdev = (struct block_device *)hdl;
    int status = 0;

    nvme_get_iostats(bdev->bd_disk, io_stats);

    if (status == 0) {
        return status;
    }
    else {
        return 0;
    }
}

void *nvm_malloc(char const *name, uint32_t size)
{
	void *ptr = NULL;
	int i = 0;
	dma_addr_t phys_addr;char buf[IO_MEMS];

	pthread_spin_lock(&lock);

	for (i = 0; i < IO_MEMS; i++) {
		if (nvmhdl[i].phys_addr != 0) {
			continue;
		}

		sprintf(buf, "%d\n", i);
		ptr = dma_alloc_coherent(NULL, buf, 0, size, -1, &phys_addr);
		nvmhdl[i].phys_addr = phys_addr;
		nvmhdl[i].addr = ptr;
		break;
	}

	pthread_spin_unlock(&lock);

	if (!ptr) {
		assert(0);
	}

	return ptr;
}

int nvm_free(void *ptr)
{
	int i;
	pthread_spin_lock(&lock);
	for (i = 0; i < IO_MEMS; i++) {

		if (nvmhdl[i].addr == ptr) {

			nvmhdl[i].phys_addr = 0;
			nvmhdl[i].addr = 0;
			pthread_spin_unlock(&lock);
			return (0);
		}
	}
	pthread_spin_unlock(&lock);
	return 0;
}

static int nvm_flush(nvmhdl_t hdl)
{
	struct block_device *bdev = (struct block_device *)hdl;
	struct nvme_ns *ns = bdev->bd_disk->private_data;
	int iocode = NVME_IOCTL_CMD_FLUSH;
	return nvme_ioctl(hdl, 0, iocode, 0);
}

static int nvm_ioctl(nvmhdl_t hdl, nvm_cmd_t *cmdhdl, void *addr)
{
	int iocode = NVME_IOCTL_ADMIN_CMD;
	cmdhdl->opcode = nvme_admin_identify;
	return nvme_ioctl(hdl, (uint64_t)cmdhdl, iocode, (uint64_t)addr);
}

static uint64_t get_physical_addr(void *addr)
{
    int i;

    for (i = 0; i < IO_MEMS; i++) {
        if (nvmhdl[i].addr == addr) {
            return nvmhdl[i].phys_addr;
        }
    }

    return rte_mem_virt2phy(addr);
}



static aio_ses_ctx_t *nvm_aio_ses_init(void)
{

	aio_ses_ctx_t *p_ses_ctx = (aio_ses_ctx_t *)malloc(sizeof(aio_ses_ctx_t));

	if (!p_ses_ctx)
		return NULL;

	TAILQ_INIT(&p_ses_ctx->aio_comp_q);

	rte_rwlock_init(&p_ses_ctx->slock);

	return p_ses_ctx;
}

static void nvm_aio_ses_free(aio_ses_ctx_t *p_ses_ctx)
{
	if (p_ses_ctx)
		free(p_ses_ctx);
}

/* Return upto "n_events" number of  aio completions*/
static int  nvm_aio_get_completions(aio_ses_ctx_t *p_ses_ctx,
				    struct aio_completion_data *as_data,
				    unsigned int n_events)
{
	struct aio_completion_data *a_data, *next;
	int i = 0;
	int cpu;

	while (i != n_events)
	{
		for (a_data = TAILQ_FIRST(&p_ses_ctx->aio_comp_q); a_data != NULL;
			a_data = next)
		{
			if (i == n_events)
				return i;
			next = TAILQ_NEXT(a_data, next);

			memcpy((as_data +i), a_data, sizeof(struct aio_completion_data));

			i++;
			rte_rwlock_write_lock(&p_ses_ctx->slock);

			TAILQ_REMOVE(&p_ses_ctx->aio_comp_q, a_data, next);

			rte_rwlock_write_unlock(&p_ses_ctx->slock);
		}
	}
	return i;

}

static int  nvm_aio_get_completions_sync(aio_ses_ctx_t *p_ses_ctx,
				    struct aio_completion_data *as_data,
				    unsigned int n_events)
{
 
	
	struct aio_completion_data *a_data, *next;
	int i = 0;
	int cpu;

    nvme_command_processing(NULL);

	while (i != n_events)
	{
		for (a_data = TAILQ_FIRST(&p_ses_ctx->aio_comp_q); a_data != NULL;
			a_data = next)
		{
			if (i == n_events)
				return i;
			next = TAILQ_NEXT(a_data, next);
			memcpy((as_data +i), a_data, sizeof(struct aio_completion_data));
	
			i++;
			rte_rwlock_write_lock(&p_ses_ctx->slock);
	
			TAILQ_REMOVE(&p_ses_ctx->aio_comp_q, a_data, next);
			rte_rwlock_write_unlock(&p_ses_ctx->slock);
		}
	}
	
	return i;
}

static int nvm_aio_read(nvmhdl_t hdl, void *addr, size_t count, off_t offset,
			struct aio_ctx *async_ctx)
{
	nvm_cmd_t cmdhdl;
	int status;
	int iocode = NVME_IOCTL_SUBMIT_AIO;
	cmdhdl.opcode = nvme_cmd_read;
	cmdhdl.slba = offset/DEV_BLOCK_SIZE;
	cmdhdl.nblocks = count/DEV_BLOCK_SIZE;

	if (async_ctx) {
		async_ctx->aio_data.aio_type = O_READ;
		async_ctx->aio_data.buf_len = count;
		async_ctx->aio_data.databuf = addr;
		async_ctx->aio_data.offset = offset;
	}

	cmdhdl.cmd_ctx = async_ctx;
	status = nvme_ioctl(hdl, (uint64_t)&cmdhdl, iocode, get_physical_addr(addr));

	return status;
}

static int nvm_aio_write(nvmhdl_t hdl, void *addr, size_t count, off_t offset,
			struct aio_ctx *async_ctx)
{
	nvm_cmd_t cmdhdl;
	int status;
	int iocode = NVME_IOCTL_SUBMIT_AIO;
	cmdhdl.opcode = nvme_cmd_write;
	cmdhdl.slba = offset/DEV_BLOCK_SIZE;
	cmdhdl.nblocks = count/DEV_BLOCK_SIZE;

	if (async_ctx) {
		async_ctx->aio_data.aio_type = O_WRITE;
		async_ctx->aio_data.buf_len = count;
		async_ctx->aio_data.databuf = addr;
		async_ctx->aio_data.offset = offset;
	}

	cmdhdl.cmd_ctx  = async_ctx;

	status = nvme_ioctl(hdl, (uint64_t)&cmdhdl, iocode, get_physical_addr(addr));

	return status;
}

static int nvm_pread(nvmhdl_t hdl, void *addr, size_t count, off_t offset)
{
	nvm_cmd_t cmdhdl;
	int status;
	int iocode = NVME_IOCTL_SUBMIT_IO;
	cmdhdl.opcode = nvme_cmd_read;
	cmdhdl.slba = offset/DEV_BLOCK_SIZE;
	cmdhdl.nblocks = count/DEV_BLOCK_SIZE;

	status = nvme_ioctl(hdl, (uint64_t)&cmdhdl, iocode, get_physical_addr(addr));

	if (status == 0) {
		return count;
	}
    else {
        return 0;
    }
}

static int nvm_pread_epic(nvmhdl_t hdl, void *key_addr, void *value_addr, 
		size_t key_size, size_t value_size)
{
    int status = -1;
    struct nvme_passthru_cmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = nvme_cmd_kv_get;
    cmd.flags = 0;
    cmd.rsvd1 = 0;
    cmd.cdw2 = 0;
    cmd.cdw3 = 0;

    // metadata = DWORD 4-5
    cmd.metadata = 0;

    // addr = DWORD 6-7
    cmd.addr = get_physical_addr(value_addr);
    //printf("value address = %lu\n", value_addr);

    // metadata_len = DWORD 8
    cmd.metadata_len = 0;

    // data_len = DWORD 9
    cmd.data_len = 0;

    cmd.cdw10 = key_size;
    cmd.cdw11 = 0;
    cmd.cdw12 = 0;
    cmd.cdw13 = value_size;
    cmd.cdw14 = 0;
    cmd.cdw15 = 0;

    // cmd.cdw10 = key size
    // if cmd.cdw10 <= 8 bytes, then store the key content in DWORD4-5 (metadata)
    // only one PRP entry, page offset = 0
    if (cmd.cdw10 <= 8)
				memcpy(&cmd.metadata, key_addr, cmd.cdw10);
    else {
        cmd.metadata = get_physical_addr(key_addr);
        cmd.metadata_len = cmd.cdw10;
    }
    cmd.data_len = cmd.cdw13;

    //printf("key = %s\n", key_addr);
    //printf("metadata = %s\n", (char *)&cmd.metadata);
    //printf("value = %s\n", value_addr);

		status = nvme_ioctl(hdl, 0, NVME_IOCTL_IO_CMD, (uint64_t)&cmd);

    //printf("key = %s\n", key_addr);
    //printf("value = %s\n", value_addr);

		if (status == 0) {
				return key_size+value_size;
		}
    else {
        return 0;
    }
}

static int nvm_pwrite(nvmhdl_t hdl, void *addr, size_t count, off_t offset)
{
	nvm_cmd_t cmdhdl;
	int status;
	int iocode= NVME_IOCTL_SUBMIT_IO;
	cmdhdl.opcode = nvme_cmd_write;
	cmdhdl.slba = offset/DEV_BLOCK_SIZE;
	cmdhdl.nblocks = count/DEV_BLOCK_SIZE;

	status = nvme_ioctl(hdl, (uint64_t)&cmdhdl, iocode, get_physical_addr(addr));

	if (status == 0) {
		return count;
    }
    else {
		return 0;
	}
}

static int nvm_pwrite_epic(nvmhdl_t hdl, void *key_addr, void *value_addr,
		size_t key_size, size_t value_size)
{
    int status = -1;

    struct nvme_passthru_cmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = nvme_cmd_kv_put;
    cmd.flags = 0;
    cmd.rsvd1 = 0;
    cmd.cdw2 = 0;
    cmd.cdw3 = 0;

    // metadata = DWORD 4-5
    cmd.metadata = 0;

    // addr = DWORD 6-7
    cmd.addr = get_physical_addr(value_addr);

    // metadata_len = DWORD 8
    cmd.metadata_len = 0;

    // data_len = DWORD 9
    cmd.data_len = 0;

    cmd.cdw10 = key_size;
    cmd.cdw11 = 0;
    cmd.cdw12 = 0;
    cmd.cdw13 = value_size;
    cmd.cdw14 = 0;
    cmd.cdw15 = 0;

		// cmd.cdw10 = key size
		// if cmd.cdw10 <= 8 bytes, then store the key content in DWORD4-5 (metadata)
		// store value in the data buffer and DWORD6-9 host buffer PRP entries
		if (cmd.cdw10 <= 8) {
			memcpy(&cmd.metadata, key_addr, cmd.cdw10);
			cmd.data_len = cmd.cdw13;
		}
		else {
			cmd.data_len = cmd.cdw13 + cmd.cdw10;
		}

		status = nvme_ioctl(hdl, 0, NVME_IOCTL_IO_CMD, (uint64_t)&cmd);

		if (status == 0) {
				return key_size+value_size;
		}
    else {
				return 0;
		}
}

static int nvm_premove_epic(nvmhdl_t hdl, void *key_addr, void *value_addr,
		size_t key_size, size_t value_size)
{
    int status = -1;

    struct nvme_passthru_cmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = nvme_cmd_kv_put;
    cmd.flags = 0;
    cmd.rsvd1 = 0;
    cmd.cdw2 = 0;
    cmd.cdw3 = 0;

    // metadata = DWORD 4-5
    cmd.metadata = 0;

    // addr = DWORD 6-7
    cmd.addr = get_physical_addr(value_addr);
    //cmd.addr = 0;

    // metadata_len = DWORD 8
    cmd.metadata_len = 0;

    // data_len = DWORD 9
    cmd.data_len = 0;

    cmd.cdw10 = key_size;
    cmd.cdw11 = 0;
    cmd.cdw12 = 0;
    cmd.cdw13 = 0;
    cmd.cdw14 = 0;
    cmd.cdw15 = 0;

		if(cmd.cdw10 > 24) {
				memcpy(value_addr, key_addr, cmd.cdw10);
				//sprintf(value_addr, "key%d", count);
				cmd.data_len = cmd.cdw13 + cmd.cdw10;
		}
		else {
				//memcpy(&cmd.kvprp1, key_addr, cmd.cdw10);
				//sprintf((char *)&cmd.kvprp1, "key%d", count);
				if (cmd.cdw10 <= 8) {
					memcpy(&cmd.metadata, key_addr, cmd.cdw10);
				}
				else {
					memcpy(&cmd.metadata, key_addr, 8);
					memcpy(&cmd.kvprp1, key_addr+8, (cmd.cdw10-8));
				}
				cmd.data_len = 0;
		}

		/*
    printf("key = %s\n", key_addr);
    printf("metadata = %s\n", (char *)&cmd.metadata);
    printf("value = %s\n", value_addr);
    printf("kvprp1 = %s\n", (char *)&cmd.kvprp1);
		*/
		status = nvme_ioctl(hdl, 0, NVME_IOCTL_IO_CMD, (uint64_t)&cmd);

		if (status == 0) {
				return key_size+value_size;
		}
    else {
				return 0;
		}
}

static nvmdriver_op_t nvm_fops = {
	.open   = nvm_open,
	.close  = nvm_close,
	.ioctl  = nvm_ioctl,
	.pread  = nvm_pread,
	.pwrite = nvm_pwrite,
	.malloc = nvm_malloc,
	.free	= nvm_free,
	.flush	= nvm_flush,
	.aio_read = nvm_aio_read,
	.aio_write = nvm_aio_write,
	.aio_init = nvm_aio_ses_init,
	.aio_free = nvm_aio_ses_free,
	.aio_get_completions = nvm_aio_get_completions,
	.aio_get_completions_sync = nvm_aio_get_completions_sync,
	.get_iostats= nvm_get_iostats,
	.pread_epic  = nvm_pread_epic,
	.pwrite_epic = nvm_pwrite_epic,
	.premove_epic = nvm_premove_epic,
};

nvmdriver_op_t * nvm_register(int argc, char *argv[])
{
	nvme_init();

	if (rte_eal_init(argc, argv) < 0) {

	}

	pthread_spin_init(&lock, PTHREAD_PROCESS_SHARED);
	return &nvm_fops;
}
