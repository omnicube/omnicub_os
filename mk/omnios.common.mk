include $(OMNIOS_ROOT_DIR)/CONFIG

C_OPT ?= -fno-omit-frame-pointer
Q ?= @
S ?= $(notdir $(CURDIR))

ifeq ($(MAKECMDGOALS),)
MAKECMDGOALS=$(.DEFAULT_GOAL)
endif

OS := $(shell uname)

COMMON_CFLAGS = -g $(C_OPT) -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-declarations -Wstrict-prototypes -Werror -fno-strict-aliasing -march=native -m64 -I$(SPDK_ROOT_DIR)/include

COMMON_CFLAGS += -Wformat -Wformat-security -Wformat-nonliteral

COMMON_CFLAGS += -D_GNU_SOURCE

# Always build PIC code so that objects can be used in shared libs and position-independent executables
COMMON_CFLAGS += -fPIC

# Enable stack buffer overflow checking
COMMON_CFLAGS += -fstack-protector

# Enable full RELRO - no lazy relocation (resolve everything at load time).
# This allows the GOT to be made read-only early in the loading process.
LDFLAGS += -Wl,-z,relro,-z,now

# Make the stack non-executable.
# This is the default in most environments, but it doesn't hurt to set it explicitly.
LDFLAGS += -Wl,-z,noexecstack

ifeq ($(OS),FreeBSD)
LIBS += -L/usr/local/lib
COMMON_CFLAGS += -I/usr/local/include
endif

ifeq ($(CONFIG_DEBUG), y)
COMMON_CFLAGS += -DDEBUG -O0
else
COMMON_CFLAGS += -DNDEBUG -O2
# Enable _FORTIFY_SOURCE checks - these only work when optimizations are enabled.
COMMON_CFLAGS += -D_FORTIFY_SOURCE=2
endif

ifeq ($(CONFIG_COVERAGE), y)
COMMON_CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-arcs -ftest-coverage
ifeq ($(OS),FreeBSD)
LDFLAGS += --coverage
endif
endif

CFLAGS   += $(COMMON_CFLAGS) -Wno-pointer-sign -std=gnu99

MAKEFLAGS += --no-print-directory

OBJS = $(C_SRCS:.c=.o)

DEPFLAGS = -MMD -MP -MF $*.d.tmp

# Compile first input $< (.c) into $@ (.o)
COMPILE_C=\
	$(Q)echo "  CC $@"; \
	$(CC) -o $@ $(DEPFLAGS) $(CFLAGS) -c $< && \
	mv -f $*.d.tmp $*.d

# Link $(OBJS) and $(LIBS) into $@ (app)
LINK_C=\
	$(Q)echo "  LINK $@"; \
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $(OBJS) $(LIBS)

# Archive $(OBJS) into $@ (.a)
LIB_C=\
	$(Q)echo "  LIB $@"; \
	ar crDs $@ $(OBJS)

%.o: %.c %.d $(MAKEFILE_LIST)
	$(COMPILE_C)

%.d: ;

DPDK_DIR ?= $(CONFIG_DPDK_DIR)
DPDK_INC_DIR ?= $(DPDK_DIR)/include
DPDK_LIB_DIR ?= $(DPDK_DIR)/lib

DPDK_INC = -I$(DPDK_INC_DIR)
DPDK_LIB = -L$(DPDK_LIB_DIR) -lrte_eal -lrte_mempool -lrte_ring -Wl,-rpath=$(DPDK_LIB_DIR)
# librte_malloc was removed after DPDK 2.1.  Link this library conditionally based on its
#  existence to maintain backward compatibility.
ifneq ($(wildcard $(DPDK_DIR)/lib/librte_malloc.*),)
DPDK_LIB += -lrte_malloc
endif

# DPDK requires dl library for dlopen/dlclose on Linux.
ifeq ($(OS),Linux)
DPDK_LIB += -ldl
endif
ifeq ($(OS),FreeBSD)
DPDK_LIB += -lexecinfo
endif
