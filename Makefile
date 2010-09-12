
REBAR=$(shell which rebar || echo ./rebar)

all: compile

compile:
	@$(REBAR) compile

clean:  
	@$(REBAR) clean

