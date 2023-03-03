R=../..
.PHONY: all clean

FUZZERS:= \
	mosquitto_passwd_fuzz_load

LOCAL_CPPFLAGS:=$(CPPFLAGS)
LOCAL_CXXFLAGS:=$(CXXFLAGS) -g -Wall -Werror -pthread
LOCAL_LDFLAGS:=$(LDFLAGS)
LOCAL_LIBADD:=$(LIBADD) $(LIB_FUZZING_ENGINE) ${R}/apps/mosquitto_passwd/mosquittopasswd.a

all: $(FUZZERS)

mosquitto_passwd_fuzz_load : mosquitto_passwd_fuzz_load.cpp
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/db_dump_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

clean:
	rm -f *.o $(FUZZERS)
