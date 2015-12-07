#ifndef SPDK_PCI_H
#define SPDK_PCI_H

#define PCI_CFG_SIZE		256
#define PCI_EXT_CAP_ID_SN	0x03
#define PCI_UIO_DRIVER		"uio_pci_generic"

int pci_device_get_serial_number(struct pci_device *dev, char *sn, int len);
int pci_device_has_uio_driver(struct pci_device *dev);
int pci_device_has_non_null_driver(struct pci_device *dev);
int pci_device_unbind_kernel_driver(struct pci_device *dev);
int pci_device_bind_uio_driver(struct pci_device *dev, char *driver_name);
int pci_device_switch_to_uio_driver(struct pci_device *pci_dev);
int pci_device_claim(struct pci_device *dev);

#endif
