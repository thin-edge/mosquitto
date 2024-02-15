function(plugin_helper_no_install PLUGIN_NAME SRCLIST INCLIST LINKLIST)
	add_library(${PLUGIN_NAME} MODULE ${SRCLIST})
	target_include_directories(${PLUGIN_NAME} PRIVATE
		${INCLIST}
		"${mosquitto_SOURCE_DIR}/"
		"${mosquitto_SOURCE_DIR}/common"
		"${mosquitto_SOURCE_DIR}/include"
	)
	if(WITH_BUNDLED_DEPS)
		target_include_directories(${PLUGIN_NAME} PRIVATE "${mosquitto_SOURCE_DIR}/deps")
	endif()

	set_target_properties(${PLUGIN_NAME} PROPERTIES
		PREFIX ""
		POSITION_INDEPENDENT_CODE 1
	)

	target_link_libraries(${PLUGIN_NAME} PRIVATE
		${LINKLIST}
		common-options
		mosquitto
	)
endfunction()

function(plugin_helper PLUGIN_NAME SRCLIST INCLIST LINKLIST)
	plugin_helper_no_install("${PLUGIN_NAME}" "${SRCLIST}" "${INCLIST}" "${LINKLIST}")

	if(WIN32)
		install(TARGETS ${PLUGIN_NAME}
			DESTINATION "${CMAKE_INSTALL_BINDIR}")
	else()
		install(TARGETS ${PLUGIN_NAME}
			RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
			LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
		)
	endif()
endfunction()

add_subdirectory(dynamic-security)
add_subdirectory(persist-sqlite)
add_subdirectory(examples)
add_subdirectory(sparkplug-aware)
