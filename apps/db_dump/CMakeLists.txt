add_executable(mosquitto_db_dump
	db_dump.c db_dump.h
	print.c
	stubs.c

	../../lib/memory_mosq.c
	../../lib/packet_datatypes.c
	../../lib/property_mosq.c
	../../lib/utf8_mosq.c

	../../src/memory_public.c
	../../src/persist_read.c
	../../src/persist_read_v234.c
	../../src/persist_read_v5.c
	../../src/topic_tok.c
)

target_compile_definitions(mosquitto_db_dump PRIVATE
	WITH_BROKER
	WITH_PERSISTENCE
)

target_include_directories(mosquitto_db_dump PRIVATE
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/common"
	"${mosquitto_SOURCE_DIR}/include"
	"${mosquitto_SOURCE_DIR}/lib"
	"${mosquitto_SOURCE_DIR}/src"
	"${OPENSSL_INCLUDE_DIR}"
)

if(WITH_TLS)
	target_link_libraries(mosquitto_db_dump PRIVATE config-header OpenSSL::SSL)
endif()

install(TARGETS mosquitto_db_dump
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
