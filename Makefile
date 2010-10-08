
REBAR=$(shell which rebar || echo ./rebar)

all: $(REBAR) compile

./rebar:
	erl -noshell -s inets start \
		-eval 'httpc:request(get, {"http://hg.basho.com/rebar/downloads/rebar", []}, [], [{stream, "./rebar"}])' \
		-s init stop
	chmod +x ./rebar

compile:
	@$(REBAR) compile

clean:  
	@$(REBAR) clean

