#!/bin/sh

erl $@ -boot start_sasl -pa $PWD/ebin $PWD/deps/*/ebin
