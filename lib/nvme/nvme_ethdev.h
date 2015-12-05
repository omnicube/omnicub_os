#ifndef _NVME_ETHDEV_H
#define _NVME_ETHDEV_H

#include <rte_pci.h>
#include "nvme.h"

int nvme_probe(struct nvme_dev *pci_dev, const struct pci_device_id *);

typedef struct eth_driver nvme_driver;

#define NVME_DEV_PRIVATE_TO_HW(adapter)\
		(struct nvme_dev *)adapter

typedef struct nvmmem_hdl {
	void *addr;
	phys_addr_t phys_addr;
} nvmmem_hdl_t;

#endif
