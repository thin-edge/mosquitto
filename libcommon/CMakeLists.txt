set(C_SRC
	utf8_common.c
)

add_library(libmosquitto_common OBJECT
	${C_SRC}
)

target_include_directories(libmosquitto_common
	PUBLIC
		"${mosquitto_SOURCE_DIR}/"
		"${mosquitto_SOURCE_DIR}/include"
)

set_target_properties(libmosquitto_common PROPERTIES
	OUTPUT_NAME mosquitto_common
	VERSION ${VERSION}
	SOVERSION 1
	POSITION_INDEPENDENT_CODE 1
)
