ifeq ($(WITH_ADNS),yes)
	LDADD+=-lanl
	CPPFLAGS+=-DWITH_ADNS
endif

ifeq ($(WITH_BRIDGE),yes)
	CPPFLAGS+=-DWITH_BRIDGE
endif

ifeq ($(WITH_CONTROL),yes)
	CPPFLAGS+=-DWITH_CONTROL
endif

ifeq ($(WITH_EC),yes)
	CPPFLAGS+=-DWITH_EC
endif

ifeq ($(WITH_EPOLL),yes)
	ifeq ($(UNAME),Linux)
		CPPFLAGS+=-DWITH_EPOLL
	endif
endif

ifeq ($(WITH_MEMORY_TRACKING),yes)
	ifneq ($(UNAME),SunOS)
		CPPFLAGS+=-DWITH_MEMORY_TRACKING
	endif
endif

ifeq ($(WITH_OLD_KEEPALIVE),yes)
	CPPFLAGS+=-DWITH_OLD_KEEPALIVE
endif

ifeq ($(WITH_PERSISTENCE),yes)
	CPPFLAGS+=-DWITH_PERSISTENCE
endif

ifeq ($(WITH_SYS_TREE),yes)
	CPPFLAGS+=-DWITH_SYS_TREE
endif

ifeq ($(WITH_SYSTEMD),yes)
	CPPFLAGS+=-DWITH_SYSTEMD
	LDADD+=-lsystemd
endif

ifeq ($(WITH_THREADING),yes)
	CFLAGS+=-pthread
	LDFLAGS+=-pthread
endif

ifeq ($(WITH_TLS),yes)
	LDADD+=-lssl -lcrypto
endif

ifeq ($(WITH_WEBSOCKETS),lws)
	CPPFLAGS+=-DWITH_WEBSOCKETS=WS_IS_LWS
	LDADD+=-lwebsockets
endif

ifeq ($(WITH_WRAP),yes)
	LDADD+=-lwrap
	CPPFLAGS+=-DWITH_WRAP
endif

ifeq ($(WITH_XTREPORT),yes)
	CPPFLAGS+=-DWITH_XTREPORT
endif
