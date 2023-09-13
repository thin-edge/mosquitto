set(PLUGIN_NAME mosquitto_sparkplug_aware)

add_library(${PLUGIN_NAME} MODULE
	on_message.c
	plugin.c
)

target_compile_definitions(${PLUGIN_NAME} PRIVATE WITH_CJSON)

target_include_directories(${PLUGIN_NAME} PRIVATE
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/common"
	"${mosquitto_SOURCE_DIR}/deps"
	"${mosquitto_SOURCE_DIR}/include"
)

if(WITH_BUNDLED_DEPS)
	target_include_directories(${PLUGIN_NAME} PRIVATE
		"${mosquitto_SOURCE_DIR}/deps"
	)
endif()

set_target_properties(${PLUGIN_NAME} PROPERTIES
	PREFIX ""
)

target_link_libraries(${PLUGIN_NAME} PRIVATE
	common-options
	mosquitto
)

if(WIN32)
	install(TARGETS ${PLUGIN_NAME}
		DESTINATION "${CMAKE_INSTALL_BINDIR}")
else()
	install(TARGETS ${PLUGIN_NAME}
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
		LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()
