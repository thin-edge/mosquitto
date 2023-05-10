R=../../..
.PHONY: all clean

FUZZERS:= \
	dynsec_fuzz_load

CPPFLAGS+= \
	-I${R} -I${R}/common -I${R}/include -I${R}/lib -I${R}/src -I${R}/deps \
	-DWITH_BRIDGE -DWITH_BROKER -DWITH_CONTROL -DWITH_EC -DWITH_EPOLL \
	-DWITH_MEMORY_TRACKING -DWITH_PERSISTENCE -DWITH_SOCKS -DWITH_SYSTEMD \
	-DWITH_SYS_TREE -DWITH_TLS -DWITH_TLS_PSK -DWITH_UNIX_SOCKETS -DWITH_WEBSOCKETS=WS_IS_BUILTIN
CXXFLAGS+=-g -Wall -Werror -pthread
LDFLAGS+=
LIBADD+=$(LIB_FUZZING_ENGINE) ${R}/plugins/dynamic-security/mosquitto_dynamic_security.a ${R}/src/mosquitto_broker.a -lssl -lcrypto -lcjson

all: $(FUZZERS)

dynsec_fuzz_load : dynsec_fuzz_load.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBADD)
	install $@ ${OUT}/$@
	cp ${R}/fuzzing/corpora/dynsec_config_seed_corpus.zip ${OUT}/$@_seed_corpus.zip

clean:
	rm -f *.o $(FUZZERS) *.gcno *.gcda
