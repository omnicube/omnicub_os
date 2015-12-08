
OMNIOS_ROOT_DIR := $(CURDIR)/..
include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

DIRS-y += memory util nvme

.PHONY: all clean $(DIRS-y)

all: $(DIRS-y)
clean: $(DIRS-y)

include $(OMNIOS_ROOT_DIR)/mk/omnios.subdirs.mk
