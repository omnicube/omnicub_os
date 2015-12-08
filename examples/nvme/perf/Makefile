
OMNIOS_ROOT_DIR := $(CURDIR)/../../..
include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

APP = perf

C_SRCS := perf.c

CFLAGS += -I. $(DPDK_INC)

OMNIOS_LIBS += $(OMNIOS_ROOT_DIR)/lib/nvme/libomnios_nvme.a \
	     $(OMNIOS_ROOT_DIR)/lib/util/libomnios_util.a \
	     $(OMNIOS_ROOT_DIR)/lib/memory/libomnios_memory.a

LIBS += $(OMNIOS_LIBS) -lpciaccess -lpthread $(DPDK_LIB) -lrt

ifeq ($(OS),Linux)
LIBS += -laio
CFLAGS += -DHAVE_LIBAIO
endif

all : $(APP)

$(APP) : $(OBJS) $(OMNIOS_LIBS)
	$(LINK_C)

clean :
	$(Q)rm -f $(OBJS) *.d $(APP)

include $(OMNIOS_ROOT_DIR)/mk/omnios.deps.mk
