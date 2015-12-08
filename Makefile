
OMNIOS_ROOT_DIR := $(CURDIR)
include $(OMNIOS_ROOT_DIR)/mk/omnios.common.mk

DIRS-y += lib test examples

.PHONY: all clean $(DIRS-y)

all: $(DIRS-y)
clean: $(DIRS-y)

test: lib
examples: lib

include $(OMNIOS_ROOT_DIR)/mk/omnios.subdirs.mk
