# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT ?= $(notdir $(BASEDIR))
PROJECT := $(strip $(PROJECT))

ERTS_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)]).")
ERL_INTERFACE_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, include)]).")
ERL_INTERFACE_LIB_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, lib)]).")

C_SRC_DIR = $(CURDIR)
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT)

# System type and C compiler/flags.

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Darwin)
	CC ?= cc
        LDFLAGS ?= -Wno-missing-braces
        CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong -Wformat -Werror=format-security -fno-strict-aliasing
else ifeq ($(UNAME_SYS), FreeBSD)
	CC ?= cc
	LDFLAGS ?= -Wl,-Bsymbolic-functions -Wl,-z,relro,-z,now
	CFLAGS ?= -DHAVE_SETPROCTITLE -DHAVE_STRTONUM -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong -Wformat -Werror=format-security -fno-strict-aliasing
	EPCAP_SANDBOX ?= capsicum
else ifeq ($(UNAME_SYS), OpenBSD)
	CC ?= cc
	LDFLAGS ?= -Wl,-z,relro,-z,now
	CFLAGS ?= -DHAVE_SETPROCTITLE -DHAVE_STRTONUM -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong -Wformat -Werror=format-security -fno-strict-aliasing
	EPCAP_SANDBOX ?= pledge
else ifeq ($(UNAME_SYS), Linux)
	CC ?= cc
	LDFLAGS ?= -Wl,-Bsymbolic-functions -Wl,-z,relro,-z,now
	CFLAGS ?= -DEPCAP_RLIMIT_NOFILES=1 -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong -Wformat -Werror=format-security -fno-strict-aliasing
	EPCAP_SANDBOX ?= seccomp
else ifeq ($(UNAME_SYS), SunOS)
	CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200112L -D__EXTENSIONS__=1 -DEPCAP_RLIMIT_NOFILES=1
endif

EPCAP_SANDBOX ?= rlimit

EPCAP_CFLAGS ?= -g -Wall -fwrapv
CFLAGS += $(EPCAP_CFLAGS) $(EPCAP_DEFINE) -I $(ERTS_INCLUDE_DIR) -I $(ERL_INTERFACE_INCLUDE_DIR) \
          -DEPCAP_SANDBOX=\"$(EPCAP_SANDBOX)\" -DEPCAP_SANDBOX_$(EPCAP_SANDBOX)

LDLIBS += -lpcap -L $(ERL_INTERFACE_LIB_DIR) -lerl_interface -lei
LDFLAGS += $(EPCAP_LDFLAGS)

# Verbosity.

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.c" -o -name "*.C" -o -name "*.cc" -o -name "*.cpp" \))
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS)

$(C_SRC_OUTPUT):
	$(COMPILE_C) -o $(C_SRC_OUTPUT) $(SOURCES) $(LDFLAGS) $(LDLIBS)

clean:
	@rm -f $(C_SRC_OUTPUT) $(OBJECTS)
