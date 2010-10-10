
REBAR=$(shell which rebar || echo ./rebar)

all: compile

./rebar:
	erl -noshell -s inets start \
		-eval 'httpc:request(get, {"http://hg.basho.com/rebar/downloads/rebar", []}, [], [{stream, "./rebar"}])' \
		-s init stop
	chmod +x ./rebar

compile: $(REBAR)
	@$(REBAR) compile

clean: $(REBAR)
	@$(REBAR) clean

