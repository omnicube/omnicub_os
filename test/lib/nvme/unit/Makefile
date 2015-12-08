
OMNIOS_ROOT_DIR := $(CURDIR)/../../../..
include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

DIRS-y = nvme_c nvme_ns_cmd_c nvme_qpair_c nvme_ctrlr_c nvme_ctrlr_cmd_c

.PHONY: all clean $(DIRS-y)

all: $(DIRS-y)
clean: $(DIRS-y)

include $(OMNIOS_ROOT_DIR)/mk/omnios.subdirs.mk
