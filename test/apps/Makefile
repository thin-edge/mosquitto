R=../..
include ${R}/config.mk

.PHONY: all check test ptest clean

all :

check : test
ptest : test
test : 01

01 :
	./01-db-dump-client-stats.py
	./01-db-dump-print-empty.py
	./01-db-dump-print-v6-all.py
	./01-db-dump-stats.py
	./01-db-dump-stats-current.py

clean:
