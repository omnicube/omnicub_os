/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "nvme_internal.h"

/**
 * \file
 *
 */

static inline bool nvme_qpair_is_admin_queue(struct nvme_qpair *qpair)
{
	return qpair->id == 0;
}

static inline bool nvme_qpair_is_io_queue(struct nvme_qpair *qpair)
{
	return qpair->id != 0;
}

struct nvme_string {
	uint16_t	value;
	const char 	*str;
};

static const struct nvme_string admin_opcode[] = {
	{ NVME_OPC_DELETE_IO_SQ, "DELETE IO SQ" },
	{ NVME_OPC_CREATE_IO_SQ, "CREATE IO SQ" },
	{ NVME_OPC_GET_LOG_PAGE, "GET LOG PAGE" },
	{ NVME_OPC_DELETE_IO_CQ, "DELETE IO CQ" },
	{ NVME_OPC_CREATE_IO_CQ, "CREATE IO CQ" },
	{ NVME_OPC_IDENTIFY, "IDENTIFY" },
	{ NVME_OPC_ABORT, "ABORT" },
	{ NVME_OPC_SET_FEATURES, "SET FEATURES" },
	{ NVME_OPC_GET_FEATURES, "GET FEATURES" },
	{ NVME_OPC_ASYNC_EVENT_REQUEST, "ASYNC EVENT REQUEST" },
	{ NVME_OPC_NAMESPACE_MANAGEMENT, "NAMESPACE MANAGEMENT" },
	{ NVME_OPC_FIRMWARE_COMMIT, "FIRMWARE COMMIT" },
	{ NVME_OPC_FIRMWARE_IMAGE_DOWNLOAD, "FIRMWARE IMAGE DOWNLOAD" },
	{ NVME_OPC_NAMESPACE_ATTACHMENT, "NAMESPACE ATTACHMENT" },
	{ NVME_OPC_FORMAT_NVM, "FORMAT NVM" },
	{ NVME_OPC_SECURITY_SEND, "SECURITY SEND" },
	{ NVME_OPC_SECURITY_RECEIVE, "SECURITY RECEIVE" },
	{ 0xFFFF, "ADMIN COMMAND" }
};

static const struct nvme_string io_opcode[] = {
	{ NVME_OPC_FLUSH, "FLUSH" },
	{ NVME_OPC_WRITE, "WRITE" },
	{ NVME_OPC_READ, "READ" },
	{ NVME_OPC_WRITE_UNCORRECTABLE, "WRITE UNCORRECTABLE" },
	{ NVME_OPC_COMPARE, "COMPARE" },
	{ NVME_OPC_WRITE_ZEROES, "WRITE ZEROES" },
	{ NVME_OPC_DATASET_MANAGEMENT, "DATASET MANAGEMENT" },
	{ NVME_OPC_RESERVATION_REGISTER, "RESERVATION REGISTER" },
	{ NVME_OPC_RESERVATION_REPORT, "RESERVATION REPORT" },
	{ NVME_OPC_RESERVATION_ACQUIRE, "RESERVATION ACQUIRE" },
	{ NVME_OPC_RESERVATION_RELEASE, "RESERVATION RELEASE" },
	{ 0xFFFF, "IO COMMAND" }
};

static const char *
nvme_get_string(const struct nvme_string *strings, uint16_t value)
{
	const struct nvme_string *entry;

	entry = strings;

	while (entry->value != 0xFFFF) {
		if (entry->value == value) {
			return entry->str;
		}
		entry++;
	}
	return entry->str;
}

static void
nvme_admin_qpair_print_command(struct nvme_qpair *qpair,
			       struct nvme_command *cmd)
{

	nvme_printf(qpair->ctrlr, "%s (%02x) sqid:%d cid:%d nsid:%x "
		    "cdw10:%08x cdw11:%08x\n",
		    nvme_get_string(admin_opcode, cmd->opc), cmd->opc, qpair->id, cmd->cid,
		    cmd->nsid, cmd->cdw10, cmd->cdw11);
}

static void
nvme_io_qpair_print_command(struct nvme_qpair *qpair,
			    struct nvme_command *cmd)
{

	switch ((int)cmd->opc) {
	case NVME_OPC_WRITE:
	case NVME_OPC_READ:
	case NVME_OPC_WRITE_UNCORRECTABLE:
	case NVME_OPC_COMPARE:
		nvme_printf(qpair->ctrlr, "%s sqid:%d cid:%d nsid:%d "
			    "lba:%llu len:%d\n",
			    nvme_get_string(io_opcode, cmd->opc), qpair->id, cmd->cid,
			    cmd->nsid,
			    ((unsigned long long)cmd->cdw11 << 32) + cmd->cdw10,
			    (cmd->cdw12 & 0xFFFF) + 1);
		break;
	case NVME_OPC_FLUSH:
	case NVME_OPC_DATASET_MANAGEMENT:
		nvme_printf(qpair->ctrlr, "%s sqid:%d cid:%d nsid:%d\n",
			    nvme_get_string(io_opcode, cmd->opc), qpair->id, cmd->cid,
			    cmd->nsid);
		break;
	default:
		nvme_printf(qpair->ctrlr, "%s (%02x) sqid:%d cid:%d nsid:%d\n",
			    nvme_get_string(io_opcode, cmd->opc), cmd->opc, qpair->id,
			    cmd->cid, cmd->nsid);
		break;
	}
}

static void
nvme_qpair_print_command(struct nvme_qpair *qpair, struct nvme_command *cmd)
{
	nvme_assert(qpair != NULL, ("qpair can not be NULL"));
	nvme_assert(cmd != NULL, ("cmd can not be NULL"));

	if (nvme_qpair_is_admin_queue(qpair)) {
		nvme_admin_qpair_print_command(qpair, cmd);
	} else {
		nvme_io_qpair_print_command(qpair, cmd);
	}
}

static const struct nvme_string generic_status[] = {
	{ NVME_SC_SUCCESS, "SUCCESS" },
	{ NVME_SC_INVALID_OPCODE, "INVALID OPCODE" },
	{ NVME_SC_INVALID_FIELD, "INVALID_FIELD" },
	{ NVME_SC_COMMAND_ID_CONFLICT, "COMMAND ID CONFLICT" },
	{ NVME_SC_DATA_TRANSFER_ERROR, "DATA TRANSFER ERROR" },
	{ NVME_SC_ABORTED_POWER_LOSS, "ABORTED - POWER LOSS" },
	{ NVME_SC_INTERNAL_DEVICE_ERROR, "INTERNAL DEVICE ERROR" },
	{ NVME_SC_ABORTED_BY_REQUEST, "ABORTED - BY REQUEST" },
	{ NVME_SC_ABORTED_SQ_DELETION, "ABORTED - SQ DELETION" },
	{ NVME_SC_ABORTED_FAILED_FUSED, "ABORTED - FAILED FUSED" },
	{ NVME_SC_ABORTED_MISSING_FUSED, "ABORTED - MISSING FUSED" },
	{ NVME_SC_INVALID_NAMESPACE_OR_FORMAT, "INVALID NAMESPACE OR FORMAT" },
	{ NVME_SC_COMMAND_SEQUENCE_ERROR, "COMMAND SEQUENCE ERROR" },
	{ NVME_SC_LBA_OUT_OF_RANGE, "LBA OUT OF RANGE" },
	{ NVME_SC_CAPACITY_EXCEEDED, "CAPACITY EXCEEDED" },
	{ NVME_SC_NAMESPACE_NOT_READY, "NAMESPACE NOT READY" },
	{ 0xFFFF, "GENERIC" }
};

static const struct nvme_string command_specific_status[] = {
	{ NVME_SC_COMPLETION_QUEUE_INVALID, "INVALID COMPLETION QUEUE" },
	{ NVME_SC_INVALID_QUEUE_IDENTIFIER, "INVALID QUEUE IDENTIFIER" },
	{ NVME_SC_MAXIMUM_QUEUE_SIZE_EXCEEDED, "MAX QUEUE SIZE EXCEEDED" },
	{ NVME_SC_ABORT_COMMAND_LIMIT_EXCEEDED, "ABORT CMD LIMIT EXCEEDED" },
	{ NVME_SC_ASYNC_EVENT_REQUEST_LIMIT_EXCEEDED, "ASYNC LIMIT EXCEEDED" },
	{ NVME_SC_INVALID_FIRMWARE_SLOT, "INVALID FIRMWARE SLOT" },
	{ NVME_SC_INVALID_FIRMWARE_IMAGE, "INVALID FIRMWARE IMAGE" },
	{ NVME_SC_INVALID_INTERRUPT_VECTOR, "INVALID INTERRUPT VECTOR" },
	{ NVME_SC_INVALID_LOG_PAGE, "INVALID LOG PAGE" },
	{ NVME_SC_INVALID_FORMAT, "INVALID FORMAT" },
	{ NVME_SC_FIRMWARE_REQUIRES_RESET, "FIRMWARE REQUIRES RESET" },
	{ NVME_SC_CONFLICTING_ATTRIBUTES, "CONFLICTING ATTRIBUTES" },
	{ NVME_SC_INVALID_PROTECTION_INFO, "INVALID PROTECTION INFO" },
	{ NVME_SC_ATTEMPTED_WRITE_TO_RO_PAGE, "WRITE TO RO PAGE" },
	{ 0xFFFF, "COMMAND SPECIFIC" }
};

static const struct nvme_string media_error_status[] = {
	{ NVME_SC_WRITE_FAULTS, "WRITE FAULTS" },
	{ NVME_SC_UNRECOVERED_READ_ERROR, "UNRECOVERED READ ERROR" },
	{ NVME_SC_GUARD_CHECK_ERROR, "GUARD CHECK ERROR" },
	{ NVME_SC_APPLICATION_TAG_CHECK_ERROR, "APPLICATION TAG CHECK ERROR" },
	{ NVME_SC_REFERENCE_TAG_CHECK_ERROR, "REFERENCE TAG CHECK ERROR" },
	{ NVME_SC_COMPARE_FAILURE, "COMPARE FAILURE" },
	{ NVME_SC_ACCESS_DENIED, "ACCESS DENIED" },
	{ 0xFFFF, "MEDIA ERROR" }
};

static const char *
get_status_string(uint16_t sct, uint16_t sc)
{
	const struct nvme_string *entry;

	switch (sct) {
	case NVME_SCT_GENERIC:
		entry = generic_status;
		break;
	case NVME_SCT_COMMAND_SPECIFIC:
		entry = command_specific_status;
		break;
	case NVME_SCT_MEDIA_ERROR:
		entry = media_error_status;
		break;
	case NVME_SCT_VENDOR_SPECIFIC:
		return "VENDOR SPECIFIC";
	default:
		return "RESERVED";
	}

	return nvme_get_string(entry, sc);
}

static void
nvme_qpair_print_completion(struct nvme_qpair *qpair,
			    struct nvme_completion *cpl)
{
	nvme_printf(qpair->ctrlr, "%s (%02x/%02x) sqid:%d cid:%d cdw0:%x sqhd:%04x p:%x m:%x dnr:%x\n",
		    get_status_string(cpl->status.sct, cpl->status.sc),
		    cpl->status.sct, cpl->status.sc, cpl->sqid, cpl->cid, cpl->cdw0,
		    cpl->sqhd, cpl->status.p, cpl->status.m, cpl->status.dnr);
}

static bool
nvme_completion_is_retry(const struct nvme_completion *cpl)
{
	/*
	 * TODO: spec is not clear how commands that are aborted due
	 *  to TLER will be marked.  So for now, it seems
	 *  NAMESPACE_NOT_READY is the only case where we should
	 *  look at the DNR bit.
	 */
	switch ((int)cpl->status.sct) {
	case NVME_SCT_GENERIC:
		switch ((int)cpl->status.sc) {
		case NVME_SC_ABORTED_BY_REQUEST:
		case NVME_SC_NAMESPACE_NOT_READY:
			if (cpl->status.dnr) {
				return false;
			} else {
				return true;
			}
		case NVME_SC_INVALID_OPCODE:
		case NVME_SC_INVALID_FIELD:
		case NVME_SC_COMMAND_ID_CONFLICT:
		case NVME_SC_DATA_TRANSFER_ERROR:
		case NVME_SC_ABORTED_POWER_LOSS:
		case NVME_SC_INTERNAL_DEVICE_ERROR:
		case NVME_SC_ABORTED_SQ_DELETION:
		case NVME_SC_ABORTED_FAILED_FUSED:
		case NVME_SC_ABORTED_MISSING_FUSED:
		case NVME_SC_INVALID_NAMESPACE_OR_FORMAT:
		case NVME_SC_COMMAND_SEQUENCE_ERROR:
		case NVME_SC_LBA_OUT_OF_RANGE:
		case NVME_SC_CAPACITY_EXCEEDED:
		default:
			return false;
		}
	case NVME_SCT_COMMAND_SPECIFIC:
	case NVME_SCT_MEDIA_ERROR:
	case NVME_SCT_VENDOR_SPECIFIC:
	default:
		return false;
	}
}

static void
nvme_qpair_construct_tracker(struct nvme_tracker *tr, uint16_t cid, uint64_t phys_addr)
{
	tr->prp_bus_addr = phys_addr + offsetof(struct nvme_tracker, prp);
	tr->cid = cid;
}

static void
nvme_qpair_complete_tracker(struct nvme_qpair *qpair, struct nvme_tracker *tr,
			    struct nvme_completion *cpl, bool print_on_error)
{
	struct nvme_request	*req;
	bool			retry, error;

	req = tr->req;

	nvme_assert(req != NULL, ("tr has NULL req\n"));

	error = nvme_completion_is_error(cpl);
	retry = error && nvme_completion_is_retry(cpl) &&
		req->retries < nvme_retry_count;

	if (error && print_on_error) {
		nvme_qpair_print_command(qpair, &req->cmd);
		nvme_qpair_print_completion(qpair, cpl);
	}

	qpair->act_tr[cpl->cid] = NULL;

	nvme_assert(cpl->cid == req->cmd.cid, ("cpl cid does not match cmd cid\n"));

	if (retry) {
		req->retries++;
		nvme_qpair_submit_tracker(qpair, tr);
	} else {
		if (req->cb_fn) {
			req->cb_fn(req->cb_arg, cpl);
		}

		nvme_free_request(req);
		tr->req = NULL;

		LIST_REMOVE(tr, list);
		LIST_INSERT_HEAD(&qpair->free_tr, tr, list);

		/*
		 * If the controller is in the middle of resetting, don't
		 *  try to submit queued requests here - let the reset logic
		 *  handle that instead.
		 */
		if (!STAILQ_EMPTY(&qpair->queued_req) &&
		    !qpair->ctrlr->is_resetting) {
			req = STAILQ_FIRST(&qpair->queued_req);
			STAILQ_REMOVE_HEAD(&qpair->queued_req, stailq);
			nvme_qpair_submit_request(qpair, req);
		}
	}
}

static void
nvme_qpair_manual_complete_tracker(struct nvme_qpair *qpair,
				   struct nvme_tracker *tr, uint32_t sct, uint32_t sc, uint32_t dnr,
				   bool print_on_error)
{
	struct nvme_completion	cpl;

	memset(&cpl, 0, sizeof(cpl));
	cpl.sqid = qpair->id;
	cpl.cid = tr->cid;
	cpl.status.sct = sct;
	cpl.status.sc = sc;
	cpl.status.dnr = dnr;
	nvme_qpair_complete_tracker(qpair, tr, &cpl, print_on_error);
}

void
nvme_qpair_manual_complete_request(struct nvme_qpair *qpair,
				   struct nvme_request *req, uint32_t sct, uint32_t sc,
				   bool print_on_error)
{
	struct nvme_completion	cpl;
	bool			error;

	memset(&cpl, 0, sizeof(cpl));
	cpl.sqid = qpair->id;
	cpl.status.sct = sct;
	cpl.status.sc = sc;

	error = nvme_completion_is_error(&cpl);

	if (error && print_on_error) {
		nvme_qpair_print_command(qpair, &req->cmd);
		nvme_qpair_print_completion(qpair, &cpl);
	}

	if (req->cb_fn) {
		req->cb_fn(req->cb_arg, &cpl);
	}

	nvme_free_request(req);
}

static inline bool
nvme_qpair_check_enabled(struct nvme_qpair *qpair)
{
	if (!qpair->is_enabled &&
	    !qpair->ctrlr->is_resetting) {
		nvme_qpair_enable(qpair);
	}
	return qpair->is_enabled;
}

/**
 * \page nvme_async_completion NVMe Asynchronous Completion
 *
 * The userspace NVMe driver follows an asynchronous polled model for
 * I/O completion.
 *
 * \section async_io I/O commands
 *
 * The application may submit I/O from one or more threads
 * and must call nvme_ctrlr_process_io_completions()
 * from each thread that submitted I/O.
 *
 * When the application calls nvme_ctrlr_process_io_completions(),
 * if the NVMe driver detects completed I/Os that were submitted on that thread,
 * it will invoke the registered callback function
 * for each I/O within the context of nvme_ctrlr_process_io_completions().
 *
 * \section async_admin Admin commands
 *
 * The application may submit admin commands from one or more threads
 * and must call nvme_ctrlr_process_admin_completions()
 * from at least one thread to receive admin command completions.
 * The thread that processes admin completions need not be the same thread that submitted the
 * admin commands.
 *
 * When the application calls nvme_ctrlr_process_admin_completions(),
 * if the NVMe driver detects completed admin commands submitted from any thread,
 * it will invote the registered callback function
 * for each command within the context of nvme_ctrlr_process_admin_completions().
 *
 * It is the application's responsibility to manage the order of submitted admin commands.
 * If certain admin commands must be submitted while no other commands are outstanding,
 * it is the application's responsibility to enforce this rule
 * using its own synchronization method.
 */

/**
 * \brief Checks for and processes completions on the specified qpair.
 *
 * For each completed command, the request's callback function will
 *  be called if specified as non-NULL when the request was submitted.
 *
 * \sa nvme_cb_fn_t
 */
void
nvme_qpair_process_completions(struct nvme_qpair *qpair, uint32_t max_completions)
{
	struct nvme_tracker	*tr;
	struct nvme_completion	*cpl;

	if (!nvme_qpair_check_enabled(qpair)) {
		/*
		 * qpair is not enabled, likely because a controller reset is
		 *  is in progress.  Ignore the interrupt - any I/O that was
		 *  associated with this interrupt will get retried when the
		 *  reset is complete.
		 */
		return;
	}

	while (1) {
		cpl = &qpair->cpl[qpair->cq_head];

		if (cpl->status.p != qpair->phase)
			break;

		tr = qpair->act_tr[cpl->cid];

		if (tr != NULL) {
			nvme_qpair_complete_tracker(qpair, tr, cpl, true);
		} else {
			nvme_printf(qpair->ctrlr,
				    "cpl does not map to outstanding cmd\n");
			nvme_qpair_print_completion(qpair, cpl);
			nvme_assert(0, ("received completion for unknown cmd\n"));
		}

		if (++qpair->cq_head == qpair->num_entries) {
			qpair->cq_head = 0;
			qpair->phase = !qpair->phase;
		}

		_nvme_mmio_write_4(qpair->cq_hdbl, qpair->cq_head);

		if (max_completions > 0 && --max_completions == 0) {
			break;
		}
	}
}

int
nvme_qpair_construct(struct nvme_qpair *qpair, uint16_t id,
		     uint16_t num_entries, uint16_t num_trackers,
		     struct nvme_controller *ctrlr)
{
	struct nvme_tracker	*tr;
	uint16_t		i;
	volatile uint32_t	*doorbell_base;
	uint64_t		phys_addr = 0;

	nvme_assert(num_entries != 0, ("invalid num_entries\n"));
	nvme_assert(num_trackers != 0, ("invalid num_trackers\n"));

	qpair->id = id;
	qpair->num_entries = num_entries;

	qpair->ctrlr = ctrlr;

	/* cmd and cpl rings must be aligned on 4KB boundaries. */
	qpair->cmd = nvme_malloc("qpair_cmd",
				 qpair->num_entries * sizeof(struct nvme_command),
				 0x1000,
				 &qpair->cmd_bus_addr);
	if (qpair->cmd == NULL) {
		nvme_printf(ctrlr, "alloc qpair_cmd failed\n");
		goto fail;
	}
	qpair->cpl = nvme_malloc("qpair_cpl",
				 qpair->num_entries * sizeof(struct nvme_completion),
				 0x1000,
				 &qpair->cpl_bus_addr);
	if (qpair->cpl == NULL) {
		nvme_printf(ctrlr, "alloc qpair_cpl failed\n");
		goto fail;
	}

	doorbell_base = &ctrlr->regs->doorbell[0].sq_tdbl;
	qpair->sq_tdbl = doorbell_base + (2 * id + 0) * ctrlr->doorbell_stride_u32;
	qpair->cq_hdbl = doorbell_base + (2 * id + 1) * ctrlr->doorbell_stride_u32;

	LIST_INIT(&qpair->free_tr);
	LIST_INIT(&qpair->outstanding_tr);
	STAILQ_INIT(&qpair->queued_req);

	for (i = 0; i < num_trackers; i++) {
		/*
		 * Round alignment up to next power of 2.  This ensures the PRP
		 *  list embedded in the nvme_tracker object will not span a
		 *  4KB boundary.
		 */
		tr = nvme_malloc("nvme_tr", sizeof(*tr), nvme_align32pow2(sizeof(*tr)), &phys_addr);
		if (tr == NULL) {
			nvme_printf(ctrlr, "nvme_tr failed\n");
			goto fail;
		}
		nvme_qpair_construct_tracker(tr, i, phys_addr);
		LIST_INSERT_HEAD(&qpair->free_tr, tr, list);
	}

	qpair->act_tr = calloc(num_trackers, sizeof(struct nvme_tracker *));
	if (qpair->act_tr == NULL) {
		nvme_printf(ctrlr, "alloc nvme_act_tr failed\n");
		goto fail;
	}
	nvme_qpair_reset(qpair);
	return 0;
fail:
	nvme_qpair_destroy(qpair);
	return -1;
}

static void
nvme_admin_qpair_abort_aers(struct nvme_qpair *qpair)
{
	struct nvme_tracker	*tr;

	tr = LIST_FIRST(&qpair->outstanding_tr);
	while (tr != NULL) {
		if (tr->req->cmd.opc == NVME_OPC_ASYNC_EVENT_REQUEST) {
			nvme_qpair_manual_complete_tracker(qpair, tr,
							   NVME_SCT_GENERIC, NVME_SC_ABORTED_SQ_DELETION, 0,
							   false);
			tr = LIST_FIRST(&qpair->outstanding_tr);
		} else {
			tr = LIST_NEXT(tr, list);
		}
	}
}

static void
_nvme_admin_qpair_destroy(struct nvme_qpair *qpair)
{
	nvme_admin_qpair_abort_aers(qpair);
}


void
nvme_qpair_destroy(struct nvme_qpair *qpair)
{
	struct nvme_tracker	*tr;

	if (nvme_qpair_is_admin_queue(qpair)) {
		_nvme_admin_qpair_destroy(qpair);
	}
	if (qpair->cmd)
		nvme_free(qpair->cmd);
	if (qpair->cpl)
		nvme_free(qpair->cpl);
	if (qpair->act_tr)
		free(qpair->act_tr);

	while (!LIST_EMPTY(&qpair->free_tr)) {
		tr = LIST_FIRST(&qpair->free_tr);
		LIST_REMOVE(tr, list);
		nvme_free(tr);
	}
}

/**
 * \page nvme_io_submission NVMe I/O Submission
 *
 * I/O is submitted to an NVMe namespace using nvme_ns_cmd_xxx functions
 * defined in nvme_ns_cmd.c.  The NVMe driver submits the I/O request
 * as an NVMe submission queue entry on the nvme_qpair associated with
 * the logical core that submits the I/O.
 *
 * \sa nvme_ns_cmd_read, nvme_ns_cmd_write, nvme_ns_cmd_deallocate,
 *     nvme_ns_cmd_flush, nvme_get_ioq_idx
 */


void
nvme_qpair_submit_tracker(struct nvme_qpair *qpair, struct nvme_tracker *tr)
{
	struct nvme_request	*req;

	req = tr->req;
	qpair->act_tr[tr->cid] = tr;

	/* Copy the command from the tracker to the submission queue. */
	nvme_copy_command(&qpair->cmd[qpair->sq_tail], &req->cmd);

	if (++qpair->sq_tail == qpair->num_entries) {
		qpair->sq_tail = 0;
	}

	wmb();
	_nvme_mmio_write_4(qpair->sq_tdbl, qpair->sq_tail);
}

static void
_nvme_fail_request_bad_vtophys(struct nvme_qpair *qpair, struct nvme_tracker *tr)
{
	/*
	 * Bad vtophys translation, so abort this request and return
	 *  immediately.
	 */
	nvme_qpair_manual_complete_tracker(qpair, tr, NVME_SCT_GENERIC,
					   NVME_SC_INVALID_FIELD,
					   1 /* do not retry */, true);
}

static void
_nvme_fail_request_ctrlr_failed(struct nvme_qpair *qpair, struct nvme_request *req)
{
	nvme_qpair_manual_complete_request(qpair, req, NVME_SCT_GENERIC,
					   NVME_SC_ABORTED_BY_REQUEST, true);
}

void
nvme_qpair_submit_request(struct nvme_qpair *qpair, struct nvme_request *req)
{
	struct nvme_tracker	*tr;
	struct nvme_request	*child_req;
	uint64_t phys_addr;
	void *seg_addr;
	uint32_t nseg, cur_nseg, modulo, unaligned;

	nvme_qpair_check_enabled(qpair);

	if (req->num_children) {
		/*
		 * This is a split (parent) request. Submit all of the children but not the parent
		 * request itself, since the parent is the original unsplit request.
		 */
		TAILQ_FOREACH(child_req, &req->children, child_tailq) {
			nvme_qpair_submit_request(qpair, child_req);
		}
		return;
	}

	tr = LIST_FIRST(&qpair->free_tr);

	if (tr == NULL || !qpair->is_enabled) {
		/*
		 * No tracker is available, or the qpair is disabled due to
		 *  an in-progress controller-level reset or controller
		 *  failure.
		 */

		if (qpair->ctrlr->is_failed) {
			_nvme_fail_request_ctrlr_failed(qpair, req);
		} else {
			/*
			 * Put the request on the qpair's request queue to be
			 *  processed when a tracker frees up via a command
			 *  completion or when the controller reset is
			 *  completed.
			 */
			STAILQ_INSERT_TAIL(&qpair->queued_req, req, stailq);
		}
		return;
	}

	LIST_REMOVE(tr, list); /* remove tr from free_tr */
	LIST_INSERT_HEAD(&qpair->outstanding_tr, tr, list);
	tr->req = req;
	req->cmd.cid = tr->cid;

	if (req->payload_size) {
		/*
		 * Build PRP list describing payload buffer.
		 */

		phys_addr = nvme_vtophys(req->u.payload);
		if (phys_addr == NVME_VTOPHYS_ERROR) {
			_nvme_fail_request_bad_vtophys(qpair, tr);
			return;
		}
		nseg = req->payload_size >> nvme_u32log2(PAGE_SIZE);
		modulo = req->payload_size & (PAGE_SIZE - 1);
		unaligned = phys_addr & (PAGE_SIZE - 1);
		if (modulo || unaligned) {
			nseg += 1 + ((modulo + unaligned - 1) >> nvme_u32log2(PAGE_SIZE));
		}

		tr->req->cmd.psdt = NVME_PSDT_PRP;
		tr->req->cmd.dptr.prp.prp1 = phys_addr;
		if (nseg == 2) {
			seg_addr = req->u.payload + PAGE_SIZE - unaligned;
			tr->req->cmd.dptr.prp.prp2 = nvme_vtophys(seg_addr);
		} else if (nseg > 2) {
			cur_nseg = 1;
			tr->req->cmd.dptr.prp.prp2 = (uint64_t)tr->prp_bus_addr;
			while (cur_nseg < nseg) {
				seg_addr = req->u.payload + cur_nseg * PAGE_SIZE - unaligned;
				phys_addr = nvme_vtophys(seg_addr);
				if (phys_addr == NVME_VTOPHYS_ERROR) {
					_nvme_fail_request_bad_vtophys(qpair, tr);
					return;
				}
				tr->prp[cur_nseg - 1] = phys_addr;
				cur_nseg++;
			}
		}
	}

	nvme_qpair_submit_tracker(qpair, tr);
}

void
nvme_qpair_reset(struct nvme_qpair *qpair)
{
	qpair->sq_tail = qpair->cq_head = 0;

	/*
	 * First time through the completion queue, HW will set phase
	 *  bit on completions to 1.  So set this to 1 here, indicating
	 *  we're looking for a 1 to know which entries have completed.
	 *  we'll toggle the bit each time when the completion queue
	 *  rolls over.
	 */
	qpair->phase = 1;

	memset(qpair->cmd, 0,
	       qpair->num_entries * sizeof(struct nvme_command));
	memset(qpair->cpl, 0,
	       qpair->num_entries * sizeof(struct nvme_completion));
}

static void
_nvme_admin_qpair_enable(struct nvme_qpair *qpair)
{
	struct nvme_tracker		*tr;
	struct nvme_tracker		*tr_temp;

	/*
	 * Manually abort each outstanding admin command.  Do not retry
	 *  admin commands found here, since they will be left over from
	 *  a controller reset and its likely the context in which the
	 *  command was issued no longer applies.
	 */
	LIST_FOREACH_SAFE(tr, &qpair->outstanding_tr, list, tr_temp) {
		nvme_printf(qpair->ctrlr,
			    "aborting outstanding admin command\n");
		nvme_qpair_manual_complete_tracker(qpair, tr, NVME_SCT_GENERIC,
						   NVME_SC_ABORTED_BY_REQUEST, 1 /* do not retry */, true);
	}

	qpair->is_enabled = true;
}

static void
_nvme_io_qpair_enable(struct nvme_qpair *qpair)
{
	STAILQ_HEAD(, nvme_request)	temp;
	struct nvme_tracker		*tr;
	struct nvme_tracker		*tr_temp;
	struct nvme_request		*req;

	/*
	 * Manually abort each outstanding I/O.  This normally results in a
	 *  retry, unless the retry count on the associated request has
	 *  reached its limit.
	 */
	LIST_FOREACH_SAFE(tr, &qpair->outstanding_tr, list, tr_temp) {
		nvme_printf(qpair->ctrlr, "aborting outstanding i/o\n");
		nvme_qpair_manual_complete_tracker(qpair, tr, NVME_SCT_GENERIC,
						   NVME_SC_ABORTED_BY_REQUEST, 0, true);
	}

	qpair->is_enabled = true;

	STAILQ_INIT(&temp);
	STAILQ_SWAP(&qpair->queued_req, &temp, nvme_request);

	while (!STAILQ_EMPTY(&temp)) {
		req = STAILQ_FIRST(&temp);
		STAILQ_REMOVE_HEAD(&temp, stailq);

		nvme_printf(qpair->ctrlr, "resubmitting queued i/o\n");
		nvme_qpair_print_command(qpair, &req->cmd);
		nvme_qpair_submit_request(qpair, req);
	}
}

void
nvme_qpair_enable(struct nvme_qpair *qpair)
{
	if (nvme_qpair_is_io_queue(qpair)) {
		_nvme_io_qpair_enable(qpair);
	} else {
		_nvme_admin_qpair_enable(qpair);
	}
}

static void
_nvme_admin_qpair_disable(struct nvme_qpair *qpair)
{
	qpair->is_enabled = false;
	nvme_admin_qpair_abort_aers(qpair);
}

static void
_nvme_io_qpair_disable(struct nvme_qpair *qpair)
{
	qpair->is_enabled = false;
}

void
nvme_qpair_disable(struct nvme_qpair *qpair)
{
	if (nvme_qpair_is_io_queue(qpair)) {
		_nvme_io_qpair_disable(qpair);
	} else {
		_nvme_admin_qpair_disable(qpair);
	}
}

void
nvme_qpair_fail(struct nvme_qpair *qpair)
{
	struct nvme_tracker		*tr;
	struct nvme_request		*req;

	while (!STAILQ_EMPTY(&qpair->queued_req)) {
		req = STAILQ_FIRST(&qpair->queued_req);
		STAILQ_REMOVE_HEAD(&qpair->queued_req, stailq);
		nvme_printf(qpair->ctrlr, "failing queued i/o\n");
		nvme_qpair_manual_complete_request(qpair, req, NVME_SCT_GENERIC,
						   NVME_SC_ABORTED_BY_REQUEST, true);
	}

	/* Manually abort each outstanding I/O. */
	while (!LIST_EMPTY(&qpair->outstanding_tr)) {
		tr = LIST_FIRST(&qpair->outstanding_tr);
		/*
		 * Do not remove the tracker.  The abort_tracker path will
		 *  do that for us.
		 */
		nvme_printf(qpair->ctrlr, "failing outstanding i/o\n");
		nvme_qpair_manual_complete_tracker(qpair, tr, NVME_SCT_GENERIC,
						   NVME_SC_ABORTED_BY_REQUEST, 1 /* do not retry */, true);
	}
}

