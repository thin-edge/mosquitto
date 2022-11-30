R=../..
include ${R}/config.mk

.PHONY: all check test ptest clean
.NOTPARALLEL:

all :

check : test
ptest : test
test : 01 02 03

01 :
	./01-db-dump-client-stats.py
	./01-db-dump-corrupt.py
	./01-db-dump-print-empty.py
	./01-db-dump-print-v6-all.py
	./01-db-dump-print-v6-mqtt-v5-props.py
	./01-db-dump-stats-current.py
	./01-db-dump-stats.py

02 :
	./02-ctrl-args.py
	./02-ctrl-broker.py
	./02-ctrl-dynsec.py

03 :
	./03-passwd-args.py
	./03-passwd-changes.py

clean:
