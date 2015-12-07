OMNIOS_ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/..
NVME_DIR := $(OMNIOS_ROOT_DIR)/lib/nvme

include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

C_SRCS = $(TEST_FILE) $(OTHER_FILES)

CFLAGS += -I$(OMNIOS_ROOT_DIR)/lib -include $(OMNIOS_ROOT_DIR)/test/lib/nvme/unit/nvme_impl.h

LIBS += -lcunit -lpthread

APP = $(TEST_FILE:.c=)

all: $(APP)

$(APP) : $(OBJS)
	$(LINK_C)

clean:
	$(Q)rm -f $(APP) $(OBJS) *.d

%.o: $(NVME_DIR)/%.c %.d $(MAKEFILE_LIST)
	$(COMPILE_C)

include $(OMNIOS_ROOT_DIR)/mk/omnios.deps.mk
