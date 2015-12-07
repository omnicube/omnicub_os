OMNIOS_ROOT_DIR := $(CURDIR)/../..
include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

CFLAGS += $(DPDK_INC) -include $(CONFIG_NVME_IMPL)

C_SRCS = nvme_ethdev.c nvme_bits.c nvme-core.c nvme_interface.c nvme-scsi.c 

LIB = libomnios_nvme.a

all : $(LIB)

clean :
	$(Q)rm -f $(LIB) $(OBJS) *.d

$(LIB) : $(OBJS)
	$(LIB_C)

include $(OMNIOS_ROOT_DIR)/mk/omnios.deps.mk
