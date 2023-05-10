R=../../..
.PHONY: all clean

FUZZERS:= \
	mosquitto_passwd_fuzz_load

CPPFLAGS+=
CXXFLAGS+=-g -Wall -Werror -pthread
LDFLAGS+=
LIBADD+=$(LIB_FUZZING_ENGINE) ${R}/apps/mosquitto_passwd/mosquitto_passwd.a -lssl -lcrypto

all: $(FUZZERS)

mosquitto_passwd_fuzz_load : mosquitto_passwd_fuzz_load.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/db_dump_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

clean:
	rm -f *.o $(FUZZERS)
