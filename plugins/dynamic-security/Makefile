R=../..
include ${R}/config.mk

PLUGIN_NAME=mosquitto_dynamic_security

LOCAL_CFLAGS+=
LOCAL_CPPFLAGS+=-I${R}/lib/ -I${R}/src/ -I${R}/plugins/common
LOCAL_LIBADD+=-lcjson -lm
LOCAL_LDFLAGS+=

WITH_PW_CACHE:=yes
ifeq ($(WITH_PW_CACHE),yes)
        LOCAL_CPPFLAGS+=-DWITH_PW_CACHE
endif

OBJS = \
	acl.o \
	auth.o \
	clients.o \
	clientlist.o \
	config.o \
	config_init.o \
	control.o \
	default_acl.o \
	groups.o \
	grouplist.o \
	kicklist.o \
	plugin.o \
	roles.o \
	rolelist.o \
	tick.o

OBJS_EXTERNAL = \
	base64_mosq.o \
	json_help.o \
	misc_mosq.o \
	password_mosq.o \

EXTRA_DEPS:=dynamic_security.h

ifeq ($(WITH_TLS),yes)
ALL_DEPS:= binary
else
ALL_DEPS:=
endif

all : ${ALL_DEPS}

base64_mosq.o : ${R}/common/base64_mosq.c ${R}/common/base64_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

misc_mosq.o : ${R}/common/misc_mosq.c ${R}/common/misc_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

password_mosq.o : ${R}/common/password_mosq.c ${R}/common/password_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

include ${R}/plugins/plugin.mk
