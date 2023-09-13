R=../..
include ${R}/config.mk

.PHONY : all binary check clean reallyclean test install uninstall

PLUGIN_NAME=mosquitto_sparkplug_aware
CFLAGS+=-I${R}/include -I${R}/
LDFLAGS+=-fPIC -shared
LDADD+=

# Objects for this plugin only, built from source in this directory
OBJS = \
	on_message.o \
	plugin.o

# Objects from e.g. the common directory that are not in this directory
OBJS_EXTERNAL =

all : binary

binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${OBJS} ${OBJS_EXTERNAL}
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $^ -o $@ ${LDADD}

${OBJS} : %.o: %.c plugin_global.h
	${CROSS_COMPILE}${CC} $(CPPFLAGS) $(CFLAGS) -c $< -o $@


reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

check: test
test:

install: ${PLUGIN_NAME}.so
	$(INSTALL) -d "${DESTDIR}$(libdir)"
	$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"

coverage:
	lcov --capture --directory . --output-file coverage.info --no-external
	genhtml coverage.info --output-directory out
