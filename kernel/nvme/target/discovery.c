
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/slab.h>
#include "nvmet.h"

static DEFINE_MUTEX(nvmet_core_addrs_mutex);
static LIST_HEAD(nvmet_core_addrs);

static DEFINE_MUTEX(nvmet_referral_addrs_mutex);
static LIST_HEAD(nvmet_referral_addrs);

static struct nvmet_subsys *nvmet_disc_subsys;

/*
 * For now define genctr as global and common for all hosts.
 * When host NQN auhterntication is implemented, genctr will
 * become host specific.
 */
atomic64_t nvmet_genctr = ATOMIC_INIT(0);

void nvmet_addr_enable(struct nvmet_addr *addr)
{
	mutex_lock(&nvmet_core_addrs_mutex);
	if (list_empty(&addr->entry)) {
		list_add_tail(&addr->entry, &nvmet_core_addrs);
		atomic64_inc(&nvmet_genctr);
	}
	mutex_unlock(&nvmet_core_addrs_mutex);
}

bool nvmet_addr_disable(struct nvmet_addr *addr)
{
	mutex_lock(&nvmet_core_addrs_mutex);
	if (!list_empty(&addr->entry)) {
		list_del_init(&addr->entry);
		atomic64_inc(&nvmet_genctr);
		mutex_unlock(&nvmet_core_addrs_mutex);
		return true;
	}
	mutex_unlock(&nvmet_core_addrs_mutex);
	return false;
}

void nvmet_ref_addr_enable(struct nvmet_addr *addr)
{
	mutex_lock(&nvmet_referral_addrs_mutex);
	if (list_empty(&addr->entry)) {
		list_add_tail(&addr->entry, &nvmet_referral_addrs);
		atomic64_inc(&nvmet_genctr);
	}
	mutex_unlock(&nvmet_referral_addrs_mutex);
}

void nvmet_ref_addr_disable(struct nvmet_addr *addr)
{
	mutex_lock(&nvmet_referral_addrs_mutex);
	if (!list_empty(&addr->entry)) {
		list_del_init(&addr->entry);
		atomic64_inc(&nvmet_genctr);
	}
	mutex_unlock(&nvmet_referral_addrs_mutex);
}

static void nvmet_format_discovery_entry(struct nvmf_disc_rsp_page_hdr *hdr,
		struct nvmet_addr *addr, char *subsys_nqn, u8 type, u32 numrec)
{
	struct nvmf_disc_rsp_page_entry *e = &hdr->entries[numrec];

	e->trtype = addr->disc_addr.trtype;
	e->adrfam = addr->disc_addr.adrfam;
	e->treq = addr->disc_addr.treq;
	e->portid = addr->disc_addr.portid;
	/* we support only dynamic controllers */
	e->cntlid = cpu_to_le16(NVME_CNTLID_DYNAMIC);
	e->nqntype = type;
	memcpy(e->trsvcid, addr->disc_addr.trsvcid, NVMF_TRSVCID_SIZE);
	memcpy(e->traddr, addr->disc_addr.traddr, NVMF_TRADDR_SIZE);
	memcpy(e->tsas.common, addr->disc_addr.tsas.common, NVMF_TSAS_SIZE);
	memcpy(e->subnqn, subsys_nqn, NVMF_NQN_SIZE);
}

static void nvmet_execute_get_disc_log_page(struct nvmet_req *req)
{
	const int entry_size = sizeof(struct nvmf_disc_rsp_page_entry);
	struct nvmf_disc_rsp_page_hdr *hdr;
	size_t data_len = nvmet_get_log_page_len(req->cmd);
	size_t alloc_len = max(data_len, sizeof(*hdr));
	int residual_len = data_len - sizeof(*hdr);
	struct nvmet_subsys *subsys;
	struct nvmet_addr *addr;
	u32 numrec = 0;
	u16 status = 0;

	/*
	 * Make sure we're passing at least a buffer of response header size.
	 * If host provided data len is less than the header size, only the
	 * number of bytes requested by host will be sent to host.
	 */
	hdr = kzalloc(alloc_len, GFP_KERNEL);
	if (!hdr) {
		status = NVME_SC_INTERNAL;
		goto out;
	}

	mutex_lock(&nvmet_referral_addrs_mutex);
	list_for_each_entry(addr, &nvmet_referral_addrs, entry) {
		if (residual_len >= entry_size) {
			nvmet_format_discovery_entry(hdr, addr,
					NVME_DISC_SUBSYS_NAME,
					NVME_NQN_DISC, numrec);
			residual_len -= entry_size;
		}
		numrec++;
	}
	mutex_unlock(&nvmet_referral_addrs_mutex);

	/*
	 * TODO: For now get log page discovery data will return
	 * all the addresses available on a target system assigned
	 * to all the subsystems on a target system.
	 * Eventually we need to implement host nqn
	 * "authentication", host nqn provisions support and
	 * address assignment to subsystems.
	 */
	mutex_lock(&nvmet_subsystem_mutex);
	list_for_each_entry(subsys, &nvmet_subsystems, entry) {
		if (subsys->type == NVME_NQN_DISC)
			continue;

		mutex_lock(&nvmet_core_addrs_mutex);
		list_for_each_entry(addr, &nvmet_core_addrs, entry) {
			if (residual_len >= entry_size) {
				nvmet_format_discovery_entry(hdr, addr,
						subsys->subsys_name,
						NVME_NQN_NVME, numrec);
				residual_len -= entry_size;
			}
			numrec++;
		}
		mutex_unlock(&nvmet_core_addrs_mutex);
	}
	mutex_unlock(&nvmet_subsystem_mutex);

	hdr->numrec = cpu_to_le32(numrec);
	hdr->recfmt = cpu_to_le16(0);
	hdr->genctr = cpu_to_le64(atomic64_read(&nvmet_genctr));

	status = nvmet_copy_to_sgl(req, 0, hdr, data_len);
	kfree(hdr);
out:
	nvmet_req_complete(req, status);
}

static void nvmet_execute_identify_disc_ctrl(struct nvmet_req *req)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct nvme_id_ctrl *id;
	u16 status = 0;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id) {
		status = NVME_SC_INTERNAL;
		goto out;
	}

	memset(id->fr, ' ', sizeof(id->fr));

	/* no limit on data transfer sizes for now */
	id->mdts = 0;
	id->cntlid = cpu_to_le16(ctrl->cntlid);
	id->ver = cpu_to_le32(ctrl->subsys->ver);

	req->ops->identify_attrs(ctrl, id);

	status = nvmet_copy_to_sgl(req, 0, id, sizeof(*id));

	kfree(id);
out:
	nvmet_req_complete(req, status);
}

int nvmet_parse_discovery_cmd(struct nvmet_req *req)
{
	struct nvme_command *cmd = req->cmd;

	req->ns = NULL;

	if (unlikely(!(req->sq->ctrl->csts & NVME_CSTS_RDY))) {
		pr_err("nvmet: got cmd %d while not ready\n",
				cmd->common.opcode);
		return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
	}

	switch (cmd->common.opcode) {
	case nvme_admin_get_log_page:
		req->data_len = nvmet_get_log_page_len(cmd);

		switch (cmd->get_log_page.lid) {
		case NVME_LOG_DISC:
			req->execute = nvmet_execute_get_disc_log_page;
			return 0;
		default:
			pr_err("nvmet: unsupported get_log_page lid %d\n",
				cmd->get_log_page.lid);
		return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
		}
	case nvme_admin_identify:
		req->data_len = 4096;
		switch (le32_to_cpu(cmd->identify.cns)) {
		case 0x01:
			req->execute =
				nvmet_execute_identify_disc_ctrl;
			return 0;
		default:
			pr_err("nvmet: unsupported identify cns %d\n",
				le32_to_cpu(cmd->identify.cns));
			return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
		}
	default:
		pr_err("nvmet: unsupported cmd %d\n",
				cmd->common.opcode);
		return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
	}

	pr_err("nvmet: unhandled cmd %d\n", cmd->common.opcode);
	return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
}

int __init nvmet_init_discovery(void)
{
	nvmet_disc_subsys =
		nvmet_subsys_alloc(NVME_DISC_SUBSYS_NAME, NVME_NQN_DISC);
	if (!nvmet_disc_subsys)
		return -ENOMEM;
	return 0;
}

void nvmet_exit_discovery(void)
{
	nvmet_subsys_put(nvmet_disc_subsys);
}
