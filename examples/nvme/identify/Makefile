
OMNIOS_ROOT_DIR := $(CURDIR)/../../..
include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

APP = identify

C_SRCS := identify.c

CFLAGS += -I. $(DPDK_INC)

OMNIOS_LIBS += $(OMNIOS_ROOT_DIR)/lib/nvme/libomnios_nvme.a \
	     $(OMNIOS_ROOT_DIR)/lib/util/libomnios_util.a \
	     $(OMNIOS_ROOT_DIR)/lib/memory/libomnios_memory.a

LIBS += $(OMNIOS_LIBS) -lpciaccess -lpthread $(DPDK_LIB) -lrt

all : $(APP)

$(APP) : $(OBJS) $(OMNIOS_LIBS)
	$(LINK_C)

clean :
	$(Q)rm -f $(OBJS) *.d $(APP)

include $(OMNIOS_ROOT_DIR)/mk/omnios.deps.mk
