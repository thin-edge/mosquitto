R=../..
.PHONY: all clean

FUZZERS:= \
	db_dump_fuzz_load

LOCAL_CPPFLAGS:=$(CPPFLAGS)
LOCAL_CXXFLAGS:=$(CXXFLAGS) -g -Wall -Werror -pthread
LOCAL_LDFLAGS:=$(LDFLAGS)
LOCAL_LIBADD:=$(LIBADD) $(LIB_FUZZING_ENGINE) ${R}/apps/db_dump/mosquitto_db_dump.a

all: $(FUZZERS)

db_dump_fuzz_load : db_dump_fuzz_load.cpp
	$(CXX) $(LOCAL_CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/db_dump_seed_corpus.zip ${OUT}/

clean:
	rm -f *.o $(FUZZERS)
