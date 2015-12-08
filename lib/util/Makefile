
OMNIOS_ROOT_DIR := $(CURDIR)/../..
include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

CFLAGS += $(DPDK_INC)

C_SRCS = file.c string.c pci.c

LIB = libomnios_util.a

all : $(LIB)

clean :
	$(Q)rm -f $(LIB) $(OBJS) *.d

$(LIB) : $(OBJS)
	$(LIB_C)

include $(OMNIOS_ROOT_DIR)/mk/omnios.deps.mk
