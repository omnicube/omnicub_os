OMNIOS_ROOT_DIR := $(CURDIR)/../..
include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

CFLAGS += $(DPDK_INC) -include $(CONFIG_NVME_IMPL)

C_SRCS = nvme_ctrlr_cmd.c nvme_ctrlr.c nvme_ns_cmd.c nvme_ns.c nvme_qpair.c nvme.c

LIB = libomnios_nvme.a

all : $(LIB)

clean :
	$(Q)rm -f $(LIB) $(OBJS) *.d

$(LIB) : $(OBJS)
	$(LIB_C)

include $(OMNIOS_ROOT_DIR)/mk/omnios.deps.mk
