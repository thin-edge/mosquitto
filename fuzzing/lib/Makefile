R=../..
.PHONY: all clean

FUZZERS:= \
	lib_fuzz_pub_topic_check2 \
	lib_fuzz_sub_topic_check2 \
	lib_fuzz_utf8

CPPFLAGS+=-I${R}/include/
CXXFLAGS+=-g -Wall -Werror -pthread
LDFLAGS+=
LIBADD+=$(LIB_FUZZING_ENGINE) ${R}/lib/libmosquitto.a -lssl -lcrypto

all: $(FUZZERS)

lib_fuzz_pub_topic_check2 : lib_fuzz_pub_topic_check2.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBADD)
	install $@ ${OUT}/$@

lib_fuzz_sub_topic_check2 : lib_fuzz_sub_topic_check2.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBADD)
	install $@ ${OUT}/$@

lib_fuzz_utf8 : lib_fuzz_utf8.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBADD)
	install $@ ${OUT}/$@

clean:
	rm -f *.o $(FUZZERS)
