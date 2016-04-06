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
#include <linux/scatterlist.h>
#include <linux/delay.h>
#include <linux/blk-mq.h>
#include <linux/nvme.h>
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/t10-pi.h>
#include "nvmet.h"
#include "../host/nvme.h"
#include "../host/fabrics.h"

#define NVME_LOOP_AQ_DEPTH		256

#define NVME_LOOP_MAX_SEGMENTS		256

/*
 * We handle AEN commands ourselves and don't even let the
 * block layer know about them.
 */
#define NVME_LOOP_NR_AEN_COMMANDS	1
#define NVME_LOOP_AQ_BLKMQ_DEPTH	\
	(NVME_LOOP_AQ_DEPTH - NVME_LOOP_NR_AEN_COMMANDS)

struct nvme_loop_iod {
	struct nvme_command	cmd;
	struct nvme_completion	rsp;
	struct nvmet_req	req;
	struct nvme_loop_queue	*queue;
	struct work_struct	work;
	struct sg_table		sg_table;
	struct scatterlist	first_sgl[];
};

struct nvme_loop_ctrl {
	spinlock_t		lock;
	struct nvme_loop_queue	*queues;
	u32			queue_count;

	struct blk_mq_tag_set	admin_tag_set;

	struct list_head	list;
	u64			cap;
	struct blk_mq_tag_set	tag_set;
	struct work_struct	scan_work;
	struct nvme_loop_iod	async_event_iod;
	struct work_struct	async_event_work;
	struct nvme_ctrl	ctrl;

	struct nvmet_ctrl	*target_ctrl;
	struct work_struct	delete_work;
	struct work_struct	reset_work;
	bool			io_incapable;
};

static inline struct nvme_loop_ctrl *to_loop_ctrl(struct nvme_ctrl *ctrl)
{
	return container_of(ctrl, struct nvme_loop_ctrl, ctrl);
}

struct nvme_loop_queue {
	struct nvmet_cq		nvme_cq;
	struct nvmet_sq		nvme_sq;
	struct nvme_loop_ctrl	*ctrl;
};

static LIST_HEAD(nvme_loop_ctrl_list);
static DEFINE_MUTEX(nvme_loop_ctrl_mutex);

static void nvme_loop_queue_response(struct nvmet_req *nvme_req);
static void nvme_loop_identify_attrs(struct nvmet_ctrl *ctrl,
				struct nvme_id_ctrl *id);

static struct nvmet_fabrics_ops nvme_loop_ops = {
	.queue_response = nvme_loop_queue_response,
	.identify_attrs = nvme_loop_identify_attrs,
};

static void nvme_loop_identify_attrs(struct nvmet_ctrl *ctrl,
				struct nvme_id_ctrl *id)
{
	/* Maximum capsule size is only the sqe */
	id->ioccsz = cpu_to_le32(sizeof(struct nvme_command) / 16);
	/* Max response capsule size is cqe */
	id->iorcsz = cpu_to_le32(sizeof(struct nvme_completion) / 16);
	/* in-capsule data offset is irrelevant */
	id->icdoff = 0;
	/* We support SGLs, but nothing fancy */
	id->sgls = cpu_to_le32((1 << 0));
	/* no enforcement soft-limit for maxcmd - pick arbitrary high value */
	id->maxcmd = cpu_to_le16(NVMET_MAX_CMD);
}

static inline int nvme_loop_queue_idx(struct nvme_loop_queue *queue)
{
	return queue - queue->ctrl->queues;
}

static void nvme_loop_complete_async_event(struct nvme_loop_ctrl *ctrl,
		struct nvme_completion *cqe)
{
	u16 status = le16_to_cpu(cqe->status) >> 1;
	u32 result = le32_to_cpu(cqe->result);

	if (status == NVME_SC_SUCCESS || status == NVME_SC_ABORT_REQ) {
		schedule_work(&ctrl->async_event_work);
	}

	if (status != NVME_SC_SUCCESS)
		return;

	switch (result & 0xff07) {
	case NVME_AER_NOTICE_NS_CHANGED:
		dev_info(ctrl->ctrl.dev, "rescanning\n");
		schedule_work(&ctrl->scan_work);
		break;
	default:
		dev_warn(ctrl->ctrl.dev, "async event result %08x\n", result);
	}
}

static void nvme_loop_complete_rq(struct request *req)
{
	struct nvme_loop_iod *iod = blk_mq_rq_to_pdu(req);
	int error = 0;

	nvme_cleanup_cmd(req);
	sg_free_table_chained(&iod->sg_table, true);

	if (unlikely(req->errors)) {
		if (nvme_req_needs_retry(req, req->errors)) {
			nvme_requeue_req(req);
			return;
		}

		if (req->cmd_type == REQ_TYPE_DRV_PRIV)
			error = req->errors;
		else
			error = nvme_error_status(req->errors);
	}

	blk_mq_end_request(req, error);
}

static void nvme_loop_queue_response(struct nvmet_req *nvme_req)
{
	struct nvme_loop_iod *iod =
		container_of(nvme_req, struct nvme_loop_iod, req);
	struct nvme_completion *cqe = &iod->rsp;

	/*
	 * AEN requests are special as they don't time out and can
	 * survive any kind of queue freeze and often don't respond to
	 * aborts.  We don't even bother to allocate a struct request
	 * for them but rather special case them here.
	 */
	if (unlikely(nvme_loop_queue_idx(iod->queue) == 0 &&
			cqe->command_id >= NVME_LOOP_AQ_BLKMQ_DEPTH)) {
		nvme_loop_complete_async_event(iod->queue->ctrl, cqe);
	} else {
		struct request *req = blk_mq_rq_from_pdu(iod);

		if (req->cmd_type == REQ_TYPE_DRV_PRIV && req->special)
			memcpy(req->special, cqe, sizeof(*cqe));
		blk_mq_complete_request(req, le16_to_cpu(cqe->status) >> 1);
	}
}

static void nvme_loop_execute_work(struct work_struct *work)
{
	struct nvme_loop_iod *iod =
		container_of(work, struct nvme_loop_iod, work);

	iod->req.execute(&iod->req);
}

static int nvme_loop_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct nvme_ns *ns = hctx->queue->queuedata;
	struct nvme_loop_queue *queue = hctx->driver_data;
	struct request *req = bd->rq;
	struct nvme_loop_iod *iod = blk_mq_rq_to_pdu(req);
	int ret;

	ret = nvme_setup_cmd(ns, req, &iod->cmd);
	if (ret)
		return ret;

	if (!nvmet_req_init(&iod->req, &queue->nvme_cq,
			&queue->nvme_sq, &nvme_loop_ops)) {
		nvme_cleanup_cmd(req);
		blk_mq_start_request(req);
		nvme_loop_queue_response(&iod->req);
		return 0;
	}

	if (blk_rq_bytes(req)) {
		iod->sg_table.sgl = iod->first_sgl;
		ret = sg_alloc_table_chained(&iod->sg_table,
			req->nr_phys_segments, iod->sg_table.sgl);
		if (ret)
			return BLK_MQ_RQ_QUEUE_BUSY;

		iod->req.sg = iod->sg_table.sgl;
		iod->req.sg_cnt = blk_rq_map_sg(req->q, req, iod->sg_table.sgl);
		BUG_ON(iod->req.sg_cnt > req->nr_phys_segments);
	}

	iod->cmd.common.command_id = req->tag;
	blk_mq_start_request(req);

	schedule_work(&iod->work);
	return 0;
}

static void nvme_loop_async_event_work(struct work_struct *work)
{
	struct nvme_loop_ctrl *ctrl =
		container_of(work, struct nvme_loop_ctrl, async_event_work);
	struct nvme_loop_queue *queue = &ctrl->queues[0];
	struct nvme_loop_iod *iod = &ctrl->async_event_iod;

	memset(&iod->cmd, 0, sizeof(iod->cmd));
	iod->cmd.common.opcode = nvme_admin_async_event;
	iod->cmd.common.command_id = NVME_LOOP_AQ_BLKMQ_DEPTH;

	if (!nvmet_req_init(&iod->req, &queue->nvme_cq, &queue->nvme_sq,
			&nvme_loop_ops)) {
		dev_err(ctrl->ctrl.dev, "failed async event work\n");
		return;
	}

	schedule_work(&iod->work);
}

static int nvme_loop_init_iod(struct nvme_loop_ctrl *ctrl,
		struct nvme_loop_iod *iod, unsigned int queue_idx)
{
	BUG_ON(queue_idx >= ctrl->queue_count);

	iod->req.cmd = &iod->cmd;
	iod->req.rsp = &iod->rsp;
	iod->queue = &ctrl->queues[queue_idx];
	INIT_WORK(&iod->work, nvme_loop_execute_work);
	return 0;
}

static int nvme_loop_init_request(void *data, struct request *req,
				unsigned int hctx_idx, unsigned int rq_idx,
				unsigned int numa_node)
{
	return nvme_loop_init_iod(data, blk_mq_rq_to_pdu(req), hctx_idx + 1);
}

static int nvme_loop_init_admin_request(void *data, struct request *req,
				unsigned int hctx_idx, unsigned int rq_idx,
				unsigned int numa_node)
{
	return nvme_loop_init_iod(data, blk_mq_rq_to_pdu(req), 0);
}

static int nvme_loop_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_loop_ctrl *ctrl = data;
	struct nvme_loop_queue *queue = &ctrl->queues[hctx_idx + 1];

	BUG_ON(hctx_idx >= ctrl->queue_count);

	hctx->driver_data = queue;
	return 0;
}

static int nvme_loop_init_admin_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_loop_ctrl *ctrl = data;
	struct nvme_loop_queue *queue = &ctrl->queues[0];

	BUG_ON(hctx_idx != 0);

	hctx->driver_data = queue;
	return 0;
}

static struct blk_mq_ops nvme_loop_mq_ops = {
	.queue_rq	= nvme_loop_queue_rq,
	.complete	= nvme_loop_complete_rq,
	.map_queue	= blk_mq_map_queue,
	.init_request	= nvme_loop_init_request,
	.init_hctx	= nvme_loop_init_hctx,
};

static struct blk_mq_ops nvme_loop_admin_mq_ops = {
	.queue_rq	= nvme_loop_queue_rq,
	.complete	= nvme_loop_complete_rq,
	.map_queue	= blk_mq_map_queue,
	.init_request	= nvme_loop_init_admin_request,
	.init_hctx	= nvme_loop_init_admin_hctx,
};

static void nvme_loop_destroy_admin_queue(struct nvme_loop_ctrl *ctrl)
{
	blk_cleanup_queue(ctrl->ctrl.admin_q);
	blk_mq_free_tag_set(&ctrl->admin_tag_set);
	nvmet_sq_destroy(&ctrl->queues[0].nvme_sq);
}

static void nvme_loop_free_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_loop_ctrl *ctrl = to_loop_ctrl(nctrl);

	if (list_empty(&ctrl->list))
		goto free_ctrl;

	mutex_lock(&nvme_loop_ctrl_mutex);
	list_del(&ctrl->list);
	mutex_unlock(&nvme_loop_ctrl_mutex);

	blk_cleanup_queue(ctrl->ctrl.connect_q);
	blk_mq_free_tag_set(&ctrl->tag_set);
	kfree(ctrl->queues);
	nvmf_free_options(nctrl->opts);
free_ctrl:
	kfree(ctrl);
}

static int nvme_loop_configure_admin_queue(struct nvme_loop_ctrl *ctrl)
{
	int error;

	memset(&ctrl->admin_tag_set, 0, sizeof(ctrl->admin_tag_set));
	ctrl->admin_tag_set.ops = &nvme_loop_admin_mq_ops;
	ctrl->admin_tag_set.queue_depth = NVME_LOOP_AQ_BLKMQ_DEPTH;;
	ctrl->admin_tag_set.reserved_tags = 1; /* fabric connect */
	ctrl->admin_tag_set.numa_node = NUMA_NO_NODE;
	ctrl->admin_tag_set.cmd_size = sizeof(struct nvme_loop_iod) +
		SG_CHUNK_SIZE * sizeof(struct scatterlist);
	ctrl->admin_tag_set.driver_data = ctrl;
	ctrl->admin_tag_set.nr_hw_queues = 1;
	ctrl->admin_tag_set.timeout = ADMIN_TIMEOUT;

	error = blk_mq_alloc_tag_set(&ctrl->admin_tag_set);
	if (error)
		return error;

	ctrl->ctrl.admin_q = blk_mq_init_queue(&ctrl->admin_tag_set);
	if (IS_ERR(ctrl->ctrl.admin_q)) {
		error = PTR_ERR(ctrl->ctrl.admin_q);
		goto out_free_tagset;
	}

	error = nvmf_connect_admin_queue(&ctrl->ctrl,
			ctrl->ctrl.opts->subsysnqn, &ctrl->ctrl.cntlid);
	if (error)
		goto out_cleanup_queue;

	error = nvmf_reg_read64(&ctrl->ctrl, NVME_REG_CAP, &ctrl->cap);
	if (error) {
		dev_err(ctrl->ctrl.dev,
			"prop_get NVME_REG_CAP failed\n");
		goto out_cleanup_queue;
	}

	ctrl->ctrl.sqsize =
		min_t(int, NVME_CAP_MQES(ctrl->cap) + 1, ctrl->ctrl.sqsize);

	error = nvme_enable_ctrl(&ctrl->ctrl, ctrl->cap);
	if (error)
		goto out_cleanup_queue;

	ctrl->ctrl.max_hw_sectors =
		(NVME_LOOP_MAX_SEGMENTS - 1) << (PAGE_SHIFT - 9);

	error = nvme_init_identify(&ctrl->ctrl);
	if (error)
		goto out_cleanup_queue;

	return 0;

out_cleanup_queue:
        blk_cleanup_queue(ctrl->ctrl.admin_q);
out_free_tagset:
	blk_mq_free_tag_set(&ctrl->admin_tag_set);
	return error;
}

static bool nvme_loop_io_incapable(struct nvme_ctrl *ctrl)
{
	return to_loop_ctrl(ctrl)->io_incapable;
}

static void nvme_loop_shutdown_ctrl(struct nvme_loop_ctrl *ctrl)
{
	int i;

	flush_work(&ctrl->async_event_work);
	flush_work(&ctrl->scan_work);

	nvme_stop_queues(&ctrl->ctrl);

	for (i = 1; i < ctrl->queue_count; i++)
		nvmet_sq_destroy(&ctrl->queues[i].nvme_sq);

	nvme_shutdown_ctrl(&ctrl->ctrl);
	nvme_loop_destroy_admin_queue(ctrl);
}

static void nvme_loop_del_ctrl_work(struct work_struct *work)
{
	struct nvme_loop_ctrl *ctrl = container_of(work,
				struct nvme_loop_ctrl, delete_work);

	nvme_remove_namespaces(&ctrl->ctrl);
	nvme_loop_shutdown_ctrl(ctrl);
	nvme_uninit_ctrl(&ctrl->ctrl);
	nvme_put_ctrl(&ctrl->ctrl);
}

static int __nvme_loop_del_ctrl(struct nvme_loop_ctrl *ctrl)
{
	if (!schedule_work(&ctrl->delete_work))
		return -EBUSY;

	return 0;
}

static int nvme_loop_del_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_loop_ctrl *ctrl = to_loop_ctrl(nctrl);
	int ret;

	ret = __nvme_loop_del_ctrl(ctrl);
	if (ret)
		return ret;

	flush_work(&ctrl->delete_work);

	return 0;
}

static void nvme_loop_reset_ctrl_work(struct work_struct *work)
{
	struct nvme_loop_ctrl *ctrl = container_of(work,
					struct nvme_loop_ctrl, reset_work);
	int i, ret;

	nvme_loop_shutdown_ctrl(ctrl);

	for (i = 0; i < ctrl->queue_count; i++) {
		ctrl->queues[i].ctrl = ctrl;
		/* reset the nvmet sqs */
		ctrl->queues[i].nvme_sq.ctrl = NULL;
		ctrl->queues[i].nvme_sq.qid = 0;
		ctrl->queues[i].nvme_sq.size = 0;
		ret = nvmet_sq_init(&ctrl->queues[i].nvme_sq);
		if (ret)
			goto out_free_queues;
	}

	ret = nvme_loop_configure_admin_queue(ctrl);
	if (ret)
		goto out_free_queues;

	for (i = 1; i < ctrl->queue_count; i++) {
		ret = nvmf_connect_io_queue(&ctrl->ctrl,
				ctrl->ctrl.opts->subsysnqn,
				ctrl->ctrl.cntlid, i);
		if (ret)
			goto out_destroy_admin_q;
	}

	schedule_work(&ctrl->scan_work);
	schedule_work(&ctrl->async_event_work);

	nvme_start_queues(&ctrl->ctrl);

	return;

out_free_queues:
	for (i = 1; i < ctrl->queue_count; i++)
		nvmet_sq_destroy(&ctrl->queues[i].nvme_sq);
out_destroy_admin_q:
	nvme_loop_destroy_admin_queue(ctrl);

	dev_warn(ctrl->ctrl.dev, "Removing after reset failure\n");
	ctrl->io_incapable = true;
	nvme_remove_namespaces(&ctrl->ctrl);
	nvme_uninit_ctrl(&ctrl->ctrl);
	nvme_put_ctrl(&ctrl->ctrl);
}

static int nvme_loop_reset_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_loop_ctrl *ctrl = to_loop_ctrl(nctrl);

	if (!schedule_work(&ctrl->reset_work))
		return -EBUSY;

	flush_work(&ctrl->reset_work);

	return 0;
}

static const struct nvme_ctrl_ops nvme_loop_ctrl_ops = {
	.name			= "loop",
	.module			= THIS_MODULE,
	.reg_read32		= nvmf_reg_read32,
	.reg_read64		= nvmf_reg_read64,
	.reg_write32		= nvmf_reg_write32,
	.io_incapable		= nvme_loop_io_incapable,
	.reset_ctrl		= nvme_loop_reset_ctrl,
	.free_ctrl		= nvme_loop_free_ctrl,
	.delete_ctrl		= nvme_loop_del_ctrl,
	.get_subsysnqn		= nvmf_get_subsysnqn,
	.identify_attrs		= nvmf_identify_attrs,
};

static void nvme_loop_scan_work(struct work_struct *work)
{
        struct nvme_loop_ctrl *ctrl =
		container_of(work, struct nvme_loop_ctrl, scan_work);

	nvme_scan_namespaces(&ctrl->ctrl);
}

static int nvme_loop_create_ctrl(struct device *dev,
		struct nvmf_ctrl_options *opts)
{
	struct nvme_loop_ctrl *ctrl;
	int nr_io_queues, ret, i;

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;
	ctrl->ctrl.opts = opts;
	INIT_LIST_HEAD(&ctrl->list);

	INIT_WORK(&ctrl->delete_work, nvme_loop_del_ctrl_work);
	INIT_WORK(&ctrl->reset_work, nvme_loop_reset_ctrl_work);

	ret = nvme_init_ctrl(&ctrl->ctrl, dev, &nvme_loop_ctrl_ops,
				0 /* no quirks, we're perfect! */);
	if (ret)
		goto out_put_ctrl;

	spin_lock_init(&ctrl->lock);
	INIT_WORK(&ctrl->scan_work, nvme_loop_scan_work);

	ret = -ENOMEM;

	ctrl->ctrl.sqsize = opts->queue_size;

	ctrl->queues = kcalloc(opts->nr_io_queues + 1,
			sizeof(*ctrl->queues), GFP_KERNEL);
	if (!ctrl->queues)
		goto out_uninit_ctrl;

	for (i = 0; i < opts->nr_io_queues + 1; i++) {
		ctrl->queues[i].ctrl = ctrl;
		ret = nvmet_sq_init(&ctrl->queues[i].nvme_sq);
		if (ret)
			goto out_free_queues;
		ctrl->queue_count++;
	}

	ret = nvme_loop_configure_admin_queue(ctrl);
	if (ret)
		goto out_free_queues;

	if (opts->queue_size > ctrl->ctrl.maxcmd) {
		/* warn if maxcmd is lower than queue_size */
		dev_warn(ctrl->ctrl.dev,
			"queue_size %zu > ctrl maxcmd %u, clamping down\n",
			opts->queue_size, ctrl->ctrl.maxcmd);
		opts->queue_size = ctrl->ctrl.maxcmd;
	}

	nr_io_queues = ctrl->queue_count - 1;
	ret = nvme_set_queue_count(&ctrl->ctrl, &nr_io_queues);
	if (ret) {
		dev_err(ctrl->ctrl.dev,
			"set_queue_count failed: %d\n", ret);
		goto out_remove_admin_queue;
	}
	ctrl->queue_count = nr_io_queues + 1;

	dev_info(ctrl->ctrl.dev,
		"creating %d I/O queues.\n", ctrl->queue_count - 1);

	memset(&ctrl->tag_set, 0, sizeof(ctrl->tag_set));
	ctrl->tag_set.ops = &nvme_loop_mq_ops;
	ctrl->tag_set.queue_depth = ctrl->ctrl.sqsize;
	ctrl->tag_set.reserved_tags = 1; /* fabric connect */
	ctrl->tag_set.numa_node = NUMA_NO_NODE;
	ctrl->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	ctrl->tag_set.cmd_size = sizeof(struct nvme_loop_iod) +
		SG_CHUNK_SIZE * sizeof(struct scatterlist);
	ctrl->tag_set.driver_data = ctrl;
	ctrl->tag_set.nr_hw_queues = ctrl->queue_count - 1;
	ctrl->tag_set.timeout = NVME_IO_TIMEOUT;
	ctrl->ctrl.tagset = &ctrl->tag_set;

	ret = blk_mq_alloc_tag_set(&ctrl->tag_set);
	if (ret)
		goto out_free_tag_set;

	ctrl->ctrl.connect_q = blk_mq_init_queue(&ctrl->tag_set);
	if (IS_ERR(ctrl->ctrl.connect_q)) {
		ret = PTR_ERR(ctrl->ctrl.connect_q);
		goto out_free_tag_set;
	}

	for (i = 1; i < ctrl->queue_count; i++) {
		ret = nvmf_connect_io_queue(&ctrl->ctrl,
				ctrl->ctrl.opts->subsysnqn,
				ctrl->ctrl.cntlid, i);
		if (ret)
			goto out_cleanup_connect_q;
	}

	nvme_loop_init_iod(ctrl, &ctrl->async_event_iod, 0);
	INIT_WORK(&ctrl->async_event_work, nvme_loop_async_event_work);

	pr_info("new ctrl: \"%s\"\n", ctrl->ctrl.opts->subsysnqn);

	mutex_lock(&nvme_loop_ctrl_mutex);
	list_add_tail(&ctrl->list, &nvme_loop_ctrl_list);
	mutex_unlock(&nvme_loop_ctrl_mutex);

	schedule_work(&ctrl->scan_work);
	schedule_work(&ctrl->async_event_work);
	return 0;

out_cleanup_connect_q:
	blk_cleanup_queue(ctrl->ctrl.connect_q);
out_free_tag_set:
	blk_mq_free_tag_set(&ctrl->tag_set);
out_remove_admin_queue:
	nvme_loop_destroy_admin_queue(ctrl);
out_free_queues:
	for (i = 1; i < ctrl->queue_count; i++)
		nvmet_sq_destroy(&ctrl->queues[i].nvme_sq);
	kfree(ctrl->queues);
out_uninit_ctrl:
	nvme_uninit_ctrl(&ctrl->ctrl);
out_put_ctrl:
	nvme_put_ctrl(&ctrl->ctrl);
	return ret;
}

static struct nvmf_transport_ops nvme_loop_transport = {
	.name		= "loop",
	.allowed_opts	= NVMF_OPT_QUEUE_SIZE | NVMF_OPT_NR_IO_QUEUES,
	.create_ctrl	= nvme_loop_create_ctrl,
};

static int __init nvme_loop_init_module(void)
{
	nvmf_register_transport(&nvme_loop_transport);
	return 0;
}

static void __exit nvme_loop_cleanup_module(void)
{
	struct nvme_loop_ctrl *ctrl, *next;

	nvmf_unregister_transport(&nvme_loop_transport);

	mutex_lock(&nvme_loop_ctrl_mutex);
	list_for_each_entry_safe(ctrl, next, &nvme_loop_ctrl_list, list)
		__nvme_loop_del_ctrl(ctrl);
	mutex_unlock(&nvme_loop_ctrl_mutex);

	flush_scheduled_work();
}

module_init(nvme_loop_init_module);
module_exit(nvme_loop_cleanup_module);

MODULE_LICENSE("GPL v2");
