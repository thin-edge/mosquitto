R=../..
include ${R}/config.mk

CFLAGS_FINAL=${CFLAGS} ${BROKER_CFLAGS} ${BROKER_CPPFLAGS} -I${R}/include -I${R}/ -I${R}/lib -I${R}/src -I${R}/deps -I${R}/common

OBJS = \
	   db_dump.o \
	   print.o \
	   stubs.o

BROKER_OBJS = \
	   ${R}/src/memory_mosq.o \
	   ${R}/src/memory_public.o \
	   ${R}/src/packet_datatypes.o \
	   ${R}/src/persist_read.o \
	   ${R}/src/persist_read_v234.o \
	   ${R}/src/persist_read_v5.o \
	   ${R}/src/property_mosq.o \
	   ${R}/src/topic_tok.o \
	   ${R}/src/utf8_mosq.o

.PHONY: all clean reallyclean

all : mosquitto_db_dump

mosquitto_db_dump : ${OBJS} ${BROKER_OBJS}
	${CROSS_COMPILE}${CC} $^ -o $@ ${LDFLAGS} ${LIBS} ${APP_LDFLAGS}

db_dump.o : db_dump.c db_dump.h ${R}/src/persist.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

print.o : print.c db_dump.h ${R}/src/persist.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

${BROKER_OBJS} :
	$(MAKE) -C ${R}/src $(notdir $@)

stubs.o : stubs.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

reallyclean: clean

clean :
	-rm -f $(OBJS) $(BROKER_OBJS)  mosquitto_db_dump *.gcda *.gcno

install:

uninstall:
