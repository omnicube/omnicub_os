
OMNIOS_ROOT_DIR := $(CURDIR)/../../..
include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

APP = vtophys

C_SRCS = vtophys.c

CFLAGS += $(DPDK_INC)

OMNIOS_LIBS += $(OMNIOS_ROOT_DIR)/lib/memory/libomnios_memory.a

LIBS += $(OMNIOS_LIBS) -lpthread $(DPDK_LIB) -lrt

all: $(APP)

$(APP): $(OBJS) $(OMNIOS_LIBS)
	$(LINK_C)

clean:
	$(Q)rm -f $(OBJS) *.d $(APP)

include $(OMNIOS_ROOT_DIR)/mk/omnios.deps.mk
