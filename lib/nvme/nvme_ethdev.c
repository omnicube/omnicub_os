/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
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

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>

#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_dev.h>
#include <rte_nvme.h>
#include <rte_spinlock.h>

#include "nvme.h"
#include "nvme_logs.h"
#include "nvme_ethdev.h"

/*
 * The set of PCI devices this driver supports
 */
static struct rte_pci_id pci_id_nvme_map[] = {

#define RTE_PCI_DEV_ID_DECL_NVME(vend, dev) {RTE_PCI_DEVICE(vend, dev)},
#include "rte_pci_dev_ids.h"

{ .vendor_id=0x144d,.device_id=0xa820, .subsystem_vendor_id= PCI_ANY_ID, .subsystem_device_id = PCI_ANY_ID},
{ .vendor_id=0x144d,.device_id=0xa821, .subsystem_vendor_id= PCI_ANY_ID, .subsystem_device_id = PCI_ANY_ID},
{ .vendor_id=0x144d,.device_id=0xa802, .subsystem_vendor_id= PCI_ANY_ID, .subsystem_device_id = PCI_ANY_ID},
};

/*
 * This function is based on code in ixgbe_attach() in ixgbe/ixgbe.c.
 * It returns 0 on success.
 */
static int eth_nvme_dev_init(__attribute__((unused)) struct eth_driver *eth_drv,
		     struct rte_eth_dev *eth_dev)
{
	int i = 0;
	//struct rte_pci_device *pci_dev = eth_dev->pci_dev;
	struct nvme_dev *nvme_dev =
			NVME_DEV_PRIVATE_TO_HW(eth_dev->data->dev_private);
	nvme_dev->bar = (struct nvme_bar *)eth_dev->pci_dev->mem_resource[i].addr;
	printf("nvme_bar is %p\n", nvme_dev->bar);
	printf("nvme_bar capability is %lx\n", readq(&nvme_dev->bar->cap));
	printf("nvme_bar version is %lx\n", readq(&nvme_dev->bar->vs));
	nvme_dev->eth_dev = eth_dev;

    eth_dev->pci_dev->intr_handle.type = RTE_INTR_HANDLE_VFIO_MSIX;

    rte_intr_enable(&(eth_dev->pci_dev->intr_handle));
	
	nvme_probe(nvme_dev,NULL);

	return 0;
}

static struct eth_driver rte_nvme_pmd = {
	{
		.name = "rte_nvme_pmd",
		.id_table = pci_id_nvme_map,
		.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	},
	.eth_dev_init = eth_nvme_dev_init,
	.dev_private_size = sizeof(struct nvme_dev),
};

/*
 * Driver initialization routine.
 * Invoked once at EAL init time.
 * Register itself as the [Poll Mode] Driver of PCI NVMe devices.
 */
int rte_pmd_nvme_init(const char *name __rte_unused, const char *params __rte_unused)
{
	PMD_INIT_FUNC_TRACE();
	rte_eth_driver_register(&rte_nvme_pmd);
	return 0;
}

static struct rte_driver rte_nvme_driver = {
    .type = PMD_PDEV,
    .init = rte_pmd_nvme_init,
};

PMD_REGISTER_DRIVER(rte_nvme_driver);

void nvme_init(void)
{
}
