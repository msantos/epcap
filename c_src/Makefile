# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT ?= $(notdir $(BASEDIR))
PROJECT := $(strip $(PROJECT))

ERTS_INCLUDE_DIR ?= $(shell erl -noshell -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)])." -s erlang halt)
ERL_INTERFACE_INCLUDE_DIR ?= $(shell erl -noshell -eval "io:format(\"~s\", [code:lib_dir(erl_interface, include)])." -s erlang halt)
ERL_INTERFACE_LIB_DIR ?= $(shell erl -noshell -eval "io:format(\"~s\", [code:lib_dir(erl_interface, lib)])." -s erlang halt)

C_SRC_DIR = $(CURDIR)
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT)

# System type and C compiler/flags.
CC ?= cc

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Darwin)
	LDFLAGS ?= -Wno-missing-braces
	CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
					 	-Wformat -Werror=format-security \
					 	-fno-strict-aliasing \
					 	-pie -fPIE
else ifeq ($(UNAME_SYS), FreeBSD)
	LDFLAGS ?= -Wl,-Bsymbolic-functions -Wl,-z,relro,-z,now -Wl,-z,noexecstack
	CFLAGS ?= -DHAVE_SETPROCTITLE -DHAVE_STRTONUM \
					 	-D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
					 	-Wformat -Werror=format-security \
					 	-fno-strict-aliasing \
					 	-pie -fPIE
	RESTRICT_PROCESS ?= capsicum
else ifeq ($(UNAME_SYS), OpenBSD)
	LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack
	CFLAGS ?= -DHAVE_SETPROCTITLE -DHAVE_STRTONUM \
					 	-D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
					 	-Wformat -Werror=format-security \
					 	-fno-strict-aliasing \
					 	-pie -fPIE
	RESTRICT_PROCESS ?= pledge
else ifeq ($(UNAME_SYS), Linux)
	LDFLAGS ?= -Wl,-Bsymbolic-functions -Wl,-z,relro,-z,now -Wl,-z,noexecstack
	CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
					 	-Wformat -Werror=format-security \
					 	-fno-strict-aliasing \
					 	-pie -fPIE
else ifeq ($(UNAME_SYS), SunOS)
	CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200112L -D__EXTENSIONS__=1
endif

RESTRICT_PROCESS ?= rlimit
EPCAP_RLIMIT_NOFILES ?= 1

EPCAP_CFLAGS ?= -g -Wall -fwrapv
CFLAGS += $(EPCAP_CFLAGS) $(EPCAP_DEFINE) -I $(ERTS_INCLUDE_DIR) -I $(ERL_INTERFACE_INCLUDE_DIR) \
          -DRESTRICT_PROCESS=\"$(RESTRICT_PROCESS)\" -DRESTRICT_PROCESS_$(RESTRICT_PROCESS) \
					-DEPCAP_RLIMIT_NOFILES=$(EPCAP_RLIMIT_NOFILES)

LDLIBS += -lpcap -L $(ERL_INTERFACE_LIB_DIR) -lei
LDFLAGS += $(EPCAP_LDFLAGS)

# Verbosity.

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.c" \))
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS)

$(C_SRC_OUTPUT):
	$(COMPILE_C) -o $(C_SRC_OUTPUT) $(SOURCES) $(LDFLAGS) $(LDLIBS)

clean:
	@rm -f $(C_SRC_OUTPUT) $(OBJECTS)
