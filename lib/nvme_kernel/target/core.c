/*
 * Copyright (c) 2015 HGST, a Western Digital Company.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/blkdev.h>
#include <linux/module.h>
#include "nvmet.h"

static DEFINE_MUTEX(nvme_transport_mutex);
static struct nvmet_fabrics_ops *nvmet_transports[NVMF_TRTYPE_MAX];

DEFINE_MUTEX(nvmet_subsystem_mutex);
LIST_HEAD(nvmet_subsystems);

static struct nvmet_subsys *nvmet_find_get_subsys(const char *subsys_name);


u16 nvmet_copy_to_sgl(struct nvmet_req *req, off_t off, const void *buf,
		size_t len)
{
	if (sg_pcopy_from_buffer(req->sg, req->sg_cnt, buf, len, off) != len)
		return NVME_SC_SGL_INVALID_DATA | NVME_SC_DNR;
	return 0;
}

u16 nvmet_copy_from_sgl(struct nvmet_req *req, off_t off, void *buf, size_t len)
{
	if (sg_pcopy_to_buffer(req->sg, req->sg_cnt, buf, len, off) != len)
		return NVME_SC_SGL_INVALID_DATA | NVME_SC_DNR;
	return 0;
}

static u32 nvmet_async_event_result(struct nvmet_async_event *aen)
{
	return aen->event_type | (aen->event_info << 8) | (aen->log_page << 16);
}

static void nvmet_async_events_free(struct nvmet_ctrl *ctrl)
{
	struct nvmet_req *req;

	while (1) {
		mutex_lock(&ctrl->lock);
		if (!ctrl->nr_async_event_cmds) {
			mutex_unlock(&ctrl->lock);
			return;
		}

		req = ctrl->async_event_cmds[--ctrl->nr_async_event_cmds];
		mutex_unlock(&ctrl->lock);
		nvmet_req_complete(req, NVME_SC_INTERNAL | NVME_SC_DNR);
	}
}

static void nvmet_async_event_work(struct work_struct *work)
{
	struct nvmet_ctrl *ctrl =
		container_of(work, struct nvmet_ctrl, async_event_work);
	struct nvmet_async_event *aen;
	struct nvmet_req *req;

	while (1) {
		mutex_lock(&ctrl->lock);
		aen = list_first_entry_or_null(&ctrl->async_events,
				struct nvmet_async_event, entry);
		if (!aen || !ctrl->nr_async_event_cmds) {
			mutex_unlock(&ctrl->lock);
			return;
		}

		req = ctrl->async_event_cmds[--ctrl->nr_async_event_cmds];
		nvmet_set_result(req, nvmet_async_event_result(aen));

		list_del(&aen->entry);
		kfree(aen);

		mutex_unlock(&ctrl->lock);
		nvmet_req_complete(req, 0);
	}
}

static void nvmet_add_async_event(struct nvmet_ctrl *ctrl, u8 event_type,
		u8 event_info, u8 log_page)
{
	struct nvmet_async_event *aen;

	aen = kmalloc(sizeof(*aen), GFP_KERNEL);
	if (!aen) {
		pr_warn("failed to allocate asynchronous event.\n");
		return;
	}

	aen->event_type = event_type;
	aen->event_info = event_info;
	aen->log_page = log_page;

	mutex_lock(&ctrl->lock);
	list_add_tail(&aen->entry, &ctrl->async_events);
	mutex_unlock(&ctrl->lock);

	schedule_work(&ctrl->async_event_work);
}

int nvmet_register_transport(struct nvmet_fabrics_ops *ops)
{
	int ret = 0;

	mutex_lock(&nvme_transport_mutex);
	if (nvmet_transports[ops->type])
		ret = -EINVAL;
	else
		nvmet_transports[ops->type] = ops;
	mutex_unlock(&nvme_transport_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(nvmet_register_transport);

void nvmet_unregister_transport(struct nvmet_fabrics_ops *ops)
{
	mutex_lock(&nvme_transport_mutex);
	nvmet_transports[ops->type] = NULL;
	mutex_unlock(&nvme_transport_mutex);
}
EXPORT_SYMBOL_GPL(nvmet_unregister_transport);

int nvmet_enable_port(struct nvmet_addr *addr)
{
	struct nvmet_fabrics_ops *ops;
	int ret = 0;

	mutex_lock(&nvme_transport_mutex);
	ops = nvmet_transports[addr->disc_addr.trtype];
	if (!ops) {
		pr_err("transport type %d not supported\n",
			addr->disc_addr.trtype);
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!try_module_get(ops->owner)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = ops->add_port(addr);
	if (ret) {
		module_put(ops->owner);
		goto out_unlock;
	}

	nvmet_addr_enable(addr);
out_unlock:
	mutex_unlock(&nvme_transport_mutex);
	return ret;
}

void nvmet_disable_port(struct nvmet_addr *addr)
{
	struct nvmet_fabrics_ops *ops;

	mutex_lock(&nvme_transport_mutex);
	ops = nvmet_transports[addr->disc_addr.trtype];
	if (nvmet_addr_disable(addr)) {
		ops->remove_port(addr);
		module_put(ops->owner);
	}
	mutex_unlock(&nvme_transport_mutex);
}

static struct nvmet_ns *__nvmet_find_namespace(struct nvmet_ctrl *ctrl,
		__le32 nsid)
{
	struct nvmet_ns *ns;

	list_for_each_entry_rcu(ns, &ctrl->subsys->namespaces, dev_link) {
		if (ns->nsid == le32_to_cpu(nsid))
			return ns;
	}

	return NULL;
}

struct nvmet_ns *nvmet_find_namespace(struct nvmet_ctrl *ctrl, __le32 nsid)
{
	struct nvmet_ns *ns;

	rcu_read_lock();
	ns = __nvmet_find_namespace(ctrl, nsid);
	if (ns)
		percpu_ref_get(&ns->ref);
	rcu_read_unlock();

	return ns;
}

static void nvmet_destroy_namespace(struct percpu_ref *ref)
{
	struct nvmet_ns *ns = container_of(ref, struct nvmet_ns, ref);

	complete(&ns->disable_done);
}

void nvmet_put_namespace(struct nvmet_ns *ns)
{
	percpu_ref_put(&ns->ref);
}

int nvmet_ns_enable(struct nvmet_ns *ns)
{
	struct nvmet_subsys *subsys = ns->subsys;
	struct nvmet_ctrl *ctrl;
	int ret = 0;

	mutex_lock(&subsys->lock);
	if (!list_empty(&ns->dev_link))
		goto out_unlock;

	ns->bdev = blkdev_get_by_path(ns->device_path, FMODE_READ | FMODE_WRITE,
			NULL);
	if (IS_ERR(ns->bdev)) {
		pr_err("nvmet: failed to open block device %s: (%ld)\n",
			ns->device_path, PTR_ERR(ns->bdev));
		ret = PTR_ERR(ns->bdev);
		ns->bdev = NULL;
		goto out_unlock;
	}

	ns->size = i_size_read(ns->bdev->bd_inode);
	ns->blksize_shift = blksize_bits(bdev_logical_block_size(ns->bdev));

	ret = percpu_ref_init(&ns->ref, nvmet_destroy_namespace,
				0, GFP_KERNEL);
	if (ret)
		goto out_blkdev_put;

	if (ns->nsid > subsys->max_nsid)
		subsys->max_nsid = ns->nsid;

	/*
	 * The namespaces list needs to be sorted to simplify the implementation
	 * of the Identify Namepace List subcommand.
	 */
	if (list_empty(&subsys->namespaces)) {
		list_add_tail_rcu(&ns->dev_link, &subsys->namespaces);
	} else {
		struct nvmet_ns *old;

		list_for_each_entry_rcu(old, &subsys->namespaces, dev_link) {
			BUG_ON(ns->nsid == old->nsid);
			if (ns->nsid < old->nsid)
				break;
		}

		list_add_tail_rcu(&ns->dev_link, &old->dev_link);
	}

	list_for_each_entry(ctrl, &subsys->ctrls, subsys_entry)
		nvmet_add_async_event(ctrl, NVME_AER_TYPE_NOTICE, 0, 0);

	ret = 0;
out_unlock:
	mutex_unlock(&subsys->lock);
	return ret;
out_blkdev_put:
	blkdev_put(ns->bdev, FMODE_WRITE|FMODE_READ);
	ns->bdev = NULL;
	goto out_unlock;
}

void nvmet_ns_disable(struct nvmet_ns *ns)
{
	struct nvmet_subsys *subsys = ns->subsys;
	struct nvmet_ctrl *ctrl;

	mutex_lock(&subsys->lock);
	if (list_empty(&ns->dev_link)) {
		mutex_unlock(&subsys->lock);
		return;
	}
	list_del_init(&ns->dev_link);
	mutex_unlock(&subsys->lock);

	/*
	 * Now that we removed the namespaces from the lookup list, we
	 * can kill the per_cpu ref and wait for any remaining references
	 * to be dropped, as well as a RCU grace period for anyone only
	 * using the namepace under rcu_read_lock().  Note that we can't
	 * use call_rcu here as we need to ensure the namespaces have
	 * been fully destroyed before unloading the module.
	 */
	percpu_ref_kill(&ns->ref);
	synchronize_rcu();
	wait_for_completion(&ns->disable_done);
	percpu_ref_exit(&ns->ref);

	mutex_lock(&subsys->lock);
	list_for_each_entry(ctrl, &subsys->ctrls, subsys_entry)
		nvmet_add_async_event(ctrl, NVME_AER_TYPE_NOTICE, 0, 0);

	if (ns->bdev)
		blkdev_put(ns->bdev, FMODE_WRITE|FMODE_READ);
	mutex_unlock(&subsys->lock);
}

void nvmet_ns_free(struct nvmet_ns *ns)
{
	nvmet_ns_disable(ns);

	kfree(ns->device_path);
	kfree(ns);
}

struct nvmet_ns *nvmet_ns_alloc(struct nvmet_subsys *subsys, u32 nsid)
{
	struct nvmet_ns *ns;

	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns)
		return NULL;

	INIT_LIST_HEAD(&ns->dev_link);
	init_completion(&ns->disable_done);

	ns->nsid = nsid;
	ns->subsys = subsys;

	/* XXX: Hacking nguids with uuid  */
	uuid_le_gen(&ns->nguid);

	return ns;
}

static void __nvmet_req_complete(struct nvmet_req *req, u16 status)
{
	if (status)
		nvmet_set_status(req, status);

	/* XXX: need to fill in something useful for sq_head */
	req->rsp->sq_head = 0;
	req->rsp->sq_id = cpu_to_le16(req->sq->qid);
	req->rsp->command_id = req->cmd->common.command_id;

	if (req->ns)
		nvmet_put_namespace(req->ns);
	req->ops->queue_response(req);
}

void nvmet_req_complete(struct nvmet_req *req, u16 status)
{
	__nvmet_req_complete(req, status);
	percpu_ref_put(&req->sq->ref);
}
EXPORT_SYMBOL_GPL(nvmet_req_complete);

void nvmet_cq_setup(struct nvmet_ctrl *ctrl, struct nvmet_cq *cq,
		u16 qid, u16 size)
{
	cq->qid = qid;
	cq->size = size;

	ctrl->cqs[qid] = cq;
}

void nvmet_sq_setup(struct nvmet_ctrl *ctrl, struct nvmet_sq *sq,
		u16 qid, u16 size)
{
	sq->qid = qid;
	sq->size = size;

	ctrl->sqs[qid] = sq;
}

void nvmet_sq_destroy(struct nvmet_sq *sq)
{
	/*
	 * If this is the admin queue, complete all AERs so that our
	 * queue doesn't have outstanding requests on it.
	 */
	if (sq->ctrl && sq->ctrl->sqs && sq->ctrl->sqs[0] == sq)
		nvmet_async_events_free(sq->ctrl);
	percpu_ref_kill(&sq->ref);
	wait_for_completion(&sq->free_done);
	percpu_ref_exit(&sq->ref);

	if (sq->ctrl)
		nvmet_ctrl_put(sq->ctrl);
}
EXPORT_SYMBOL_GPL(nvmet_sq_destroy);

static void nvmet_sq_free(struct percpu_ref *ref)
{
	struct nvmet_sq *sq = container_of(ref, struct nvmet_sq, ref);

	complete(&sq->free_done);
}

int nvmet_sq_init(struct nvmet_sq *sq)
{
	int ret;

	ret = percpu_ref_init(&sq->ref, nvmet_sq_free, 0, GFP_KERNEL);
	if (ret) {
		printk("percpu_ref init failed!\n");
		return ret;
	}
	init_completion(&sq->free_done);

	return 0;
}
EXPORT_SYMBOL_GPL(nvmet_sq_init);

bool nvmet_req_init(struct nvmet_req *req, struct nvmet_cq *cq,
		struct nvmet_sq *sq, struct nvmet_fabrics_ops *ops)
{
	u16 status;

	req->flags = 0;
	req->cq = cq;
	req->sq = sq;
	req->ops = ops;
	req->sg = NULL;
	req->sg_cnt = 0;
	req->rsp->status = 0;

	if (unlikely(!req->sq->ctrl))
		/* will return an error for any Non-connect command: */
		status = nvmet_parse_connect_cmd(req);
	else if (likely(req->sq->qid != 0))
		status = nvmet_parse_io_cmd(req);
	else if (req->cmd->common.opcode == nvme_fabrics_command)
		status = nvmet_parse_fabrics_cmd(req);
	else if (req->sq->ctrl->subsys->type == NVME_NQN_DISC)
		status = nvmet_parse_discovery_cmd(req);
	else
		status = nvmet_parse_admin_cmd(req);

	if (status)
		goto fail;

	if (unlikely(!percpu_ref_tryget_live(&sq->ref))) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		goto fail;
	}

	return true;

fail:
	__nvmet_req_complete(req, status);
	return false;
}
EXPORT_SYMBOL_GPL(nvmet_req_init);

static inline bool nvmet_cc_en(u32 cc)
{
	return cc & 0x1;
}

static inline u8 nvmet_cc_css(u32 cc)
{
	return (cc >> 4) & 0x7;
}

static inline u8 nvmet_cc_mps(u32 cc)
{
	return (cc >> 7) & 0xf;
}

static inline u8 nvmet_cc_ams(u32 cc)
{
	return (cc >> 11) & 0x7;
}

static inline u8 nvmet_cc_shn(u32 cc)
{
	return (cc >> 14) & 0x3;
}

static inline u8 nvmet_cc_iosqes(u32 cc)
{
	return (cc >> 16) & 0xf;
}

static inline u8 nvmet_cc_iocqes(u32 cc)
{
	return (cc >> 20) & 0xf;
}

static void nvmet_start_ctrl(struct nvmet_ctrl *ctrl)
{
	lockdep_assert_held(&ctrl->lock);

	if (nvmet_cc_iosqes(ctrl->cc) != NVME_NVM_IOSQES ||
	    nvmet_cc_iocqes(ctrl->cc) != NVME_NVM_IOCQES ||
	    nvmet_cc_mps(ctrl->cc) != 0 ||
	    nvmet_cc_ams(ctrl->cc) != 0 ||
	    nvmet_cc_css(ctrl->cc) != 0) {
		ctrl->csts = NVME_CSTS_CFS;
		return;
	}

	ctrl->csts = NVME_CSTS_RDY;
}

static void nvmet_clear_ctrl(struct nvmet_ctrl *ctrl)
{
	lockdep_assert_held(&ctrl->lock);

	/* XXX: tear down queues? */
	ctrl->csts &= ~NVME_CSTS_RDY;
	ctrl->cc = 0;
}

void nvmet_update_cc(struct nvmet_ctrl *ctrl, u32 new)
{
	u32 old;

	mutex_lock(&ctrl->lock);
	old = ctrl->cc;
	ctrl->cc = new;

	if (nvmet_cc_en(new) && !nvmet_cc_en(old))
		nvmet_start_ctrl(ctrl);
	if (!nvmet_cc_en(new) && nvmet_cc_en(old))
		nvmet_clear_ctrl(ctrl);
	if (nvmet_cc_shn(new) && !nvmet_cc_shn(old)) {
		nvmet_clear_ctrl(ctrl);
		ctrl->csts |= NVME_CSTS_SHST_CMPLT;
	}
	if (!nvmet_cc_shn(new) && nvmet_cc_shn(old))
		ctrl->csts &= ~NVME_CSTS_SHST_CMPLT;
	mutex_unlock(&ctrl->lock);
}

static void nvmet_init_cap(struct nvmet_ctrl *ctrl)
{
	/* command sets supported: NVMe command set: */
	ctrl->cap = (1ULL << 37);
	/* CC.EN timeout in 500msec units: */
	ctrl->cap |= (15ULL << 24);
	/* maximum queue entries supported: */
	ctrl->cap |= NVMET_QUEUE_SIZE - 1;
}

u16 nvmet_ctrl_find_get(const char *subsysnqn, const char *hostnqn, u16 cntlid,
		struct nvmet_ctrl **ret)
{
	struct nvmet_subsys *subsys;
	struct nvmet_ctrl *ctrl;
	u16 status = 0;

	subsys = nvmet_find_get_subsys(subsysnqn);
	if (!subsys) {
		pr_warn("connect request for invalid subsystem!\n");
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;
	}

	mutex_lock(&subsys->lock);
	list_for_each_entry(ctrl, &subsys->ctrls, subsys_entry) {
		if (ctrl->cntlid == cntlid) {
			if (strncmp(hostnqn, ctrl->hostnqn, NVMF_NQN_SIZE)) {
				pr_warn("hostnqn mismatch.\n");
				continue;
			}
			if (!kref_get_unless_zero(&ctrl->ref))
				continue;

			*ret = ctrl;
			goto out;
		}
	}

	pr_warn("could not find controller %d for subsys %s / host %s\n",
		cntlid, subsysnqn, hostnqn);
	status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;

out:
	mutex_unlock(&subsys->lock);
	nvmet_subsys_put(subsys);
	return status;
}

u16 nvmet_alloc_ctrl(const char *subsysnqn, const char *hostnqn,
		struct nvmet_ctrl **ctrlp)
{
	struct nvmet_subsys *subsys;
	struct nvmet_ctrl *ctrl;
	int ret;
	u16 status;

	status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
	subsys = nvmet_find_get_subsys(subsysnqn);
	if (!subsys) {
		pr_warn("connect request for invalid subsystem!\n");
		goto out;
	}

	status = NVME_SC_INTERNAL;
	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		goto out_put_subsystem;
	mutex_init(&ctrl->lock);

	nvmet_init_cap(ctrl);

	INIT_WORK(&ctrl->async_event_work, nvmet_async_event_work);
	INIT_LIST_HEAD(&ctrl->async_events);

	memcpy(ctrl->subsys_name, subsysnqn, NVMF_NQN_SIZE);
	memcpy(ctrl->hostnqn, hostnqn, NVMF_NQN_SIZE);

	kref_init(&ctrl->ref);
	ctrl->subsys = subsys;

	ctrl->cqs = kcalloc(subsys->max_qid + 1,
			sizeof(struct nvmet_cq *),
			GFP_KERNEL);
	if (!ctrl->cqs)
		goto out_free_ctrl;

	ctrl->sqs = kcalloc(subsys->max_qid + 1,
			sizeof(struct nvmet_sq *),
			GFP_KERNEL);
	if (!ctrl->sqs)
		goto out_free_cqs;

	ret = ida_simple_get(&subsys->cntlid_ida, 0, 0xffef, GFP_KERNEL);
	if (ret < 0) {
		status = NVME_SC_CONNECT_CTRL_BUSY | NVME_SC_DNR;
		goto out_free_sqs;
	}
	ctrl->cntlid = ret;

	mutex_lock(&subsys->lock);
	list_add_tail(&ctrl->subsys_entry, &subsys->ctrls);
	mutex_unlock(&subsys->lock);

	*ctrlp = ctrl;
	return 0;

out_free_sqs:
	kfree(ctrl->sqs);
out_free_cqs:
	kfree(ctrl->cqs);
out_free_ctrl:
	kfree(ctrl);
out_put_subsystem:
	nvmet_subsys_put(subsys);
out:
	return status;
}

static void nvmet_ctrl_free(struct kref *ref)
{
	struct nvmet_ctrl *ctrl = container_of(ref, struct nvmet_ctrl, ref);
	struct nvmet_subsys *subsys = ctrl->subsys;

	mutex_lock(&subsys->lock);
	list_del(&ctrl->subsys_entry);
	mutex_unlock(&subsys->lock);

	nvmet_subsys_put(subsys);
	ida_simple_remove(&subsys->cntlid_ida, ctrl->cntlid);

	kfree(ctrl->sqs);
	kfree(ctrl->cqs);
	kfree(ctrl);
}

void nvmet_ctrl_put(struct nvmet_ctrl *ctrl)
{
	kref_put(&ctrl->ref, nvmet_ctrl_free);
}

static struct nvmet_subsys *nvmet_find_get_subsys(const char *subsys_name)
{
	struct nvmet_subsys *subsys;

	mutex_lock(&nvmet_subsystem_mutex);
	list_for_each_entry(subsys, &nvmet_subsystems, entry) {
		if (!strncmp(subsys->subsys_name, subsys_name,
				NVMF_NQN_SIZE)) {
			if (!kref_get_unless_zero(&subsys->ref))
				break;
			mutex_unlock(&nvmet_subsystem_mutex);
			return subsys;
		}
	}
	mutex_unlock(&nvmet_subsystem_mutex);
	return NULL;
}

struct nvmet_subsys *nvmet_subsys_alloc(const char *subsys_name,
		enum nvme_subsys_type type)
{
	struct nvmet_subsys *subsys;

	subsys = kzalloc(sizeof(*subsys), GFP_KERNEL);
	if (!subsys)
		return NULL;

	subsys->ver = (1 << 16) | (2 << 8) | 1; /* NVMe 1.2.1 */

	switch (type) {
	case NVME_NQN_NVME:
		subsys->max_qid = NVMET_NR_QUEUES;
		break;
	case NVME_NQN_DISC:
		subsys->max_qid = 0;
		break;
	default:
		pr_err("%s: Unknown Subsystem type - %d\n", __func__, type);
		kfree(subsys);
		return NULL;
	}
	subsys->type = type;
	subsys->subsys_name = kstrndup(subsys_name, NVMF_NQN_SIZE,
			GFP_KERNEL);
	if (IS_ERR(subsys->subsys_name)) {
		kfree(subsys);
		return NULL;
	}

	kref_init(&subsys->ref);

	mutex_init(&subsys->lock);
	INIT_LIST_HEAD(&subsys->namespaces);
	INIT_LIST_HEAD(&subsys->ctrls);

	ida_init(&subsys->cntlid_ida);

	mutex_lock(&nvmet_subsystem_mutex);
	list_add_tail(&subsys->entry, &nvmet_subsystems);
	mutex_unlock(&nvmet_subsystem_mutex);

	atomic64_inc(&nvmet_genctr);

	return subsys;
}

static void nvmet_subsys_free(struct kref *ref)
{
	struct nvmet_subsys *subsys = container_of(ref, struct nvmet_subsys, ref);

	WARN_ON_ONCE(!list_empty(&subsys->namespaces));

	mutex_lock(&nvmet_subsystem_mutex);
	list_del(&subsys->entry);
	mutex_unlock(&nvmet_subsystem_mutex);

	ida_destroy(&subsys->cntlid_ida);

	atomic64_inc(&nvmet_genctr);

	kfree(subsys->subsys_name);
	kfree(subsys);
}

void nvmet_subsys_put(struct nvmet_subsys *subsys)
{
	kref_put(&subsys->ref, nvmet_subsys_free);
}

static int __init nvmet_init(void)
{
	int error;

	error = nvmet_init_discovery();
	if (error)
		goto out;

	error = nvmet_init_configfs();
	if (error)
		goto out_exit_discovery;
	return 0;

out_exit_discovery:
	nvmet_exit_discovery();
out:
	return error;
}

static void __exit nvmet_exit(void)
{
	nvmet_exit_configfs();
	nvmet_exit_discovery();
}

module_init(nvmet_init);
module_exit(nvmet_exit);

MODULE_LICENSE("GPL v2");
