
ERL=erl
APP=epcap

CC=gcc

ERL_LIB=/usr/local/lib/erlang/lib/erl_interface-3.6.4
ARCH=-m32
CFLAGS=-g -Wall
CPPFLAGS=-I$(ERL_LIB)/include
LDFLAGS=-L$(ERL_LIB)/lib -lpcap -lerl_interface -lei -lpthread


all: dir erl epcap

dir:
	-@mkdir -p priv/tmp ebin

erl:
	@$(ERL) -noinput +B \
		-eval 'case make:all() of up_to_date -> halt(0); error -> halt(1) end.'

epcap: epcap.o epcap_priv.o
	@$(CC) $(CFLAGS) $(ARCH) c_src/epcap.o $(LDFLAGS) -o priv/$@ c_src/epcap_priv.o

%.o: c_src/%.c
	gcc $(ARCH) $(CFLAGS) $(CPPFLAGS) -o c_src/$@ -c $<

clean:  
	@rm -fv ebin/*.beam c_src/*.o

