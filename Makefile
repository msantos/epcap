
ERL=erl
APP=epcap

CC=gcc

ERL_LIB=/usr/local/lib/erlang/lib/erl_interface-3.6.4
ARCH=-m32
CFLAGS=-Wall -I$(ERL_LIB)/include
LDFLAGS=-L$(ERL_LIB)/lib -lpcap -lerl_interface -lei -lpthread


all: erl epcap

erl:
	@$(ERL) -noinput +B \
		-eval 'case make:all() of up_to_date -> halt(0); error -> halt(1) end.'

epcap:
	@$(CC) -g $(ARCH) $(CFLAGS) -o c_src/epcap_priv.o -c c_src/epcap_priv.c
	@$(CC) -g $(ARCH) $(CFLAGS) -o c_src/epcap.o -c c_src/epcap.c
	@$(CC) $(ARCH) $(LDFLAGS) -o priv/epcap c_src/*.o


clean:  
	@rm -fv ebin/*.beam c_src/*.o

