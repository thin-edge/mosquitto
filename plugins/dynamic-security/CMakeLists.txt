if(WITH_TLS)
	set(PLUGIN_NAME mosquitto_dynamic_security)

	set(SRCLIST
		acl.c
		auth.c
		../../common/base64_mosq.c ../../common/base64_mosq.h
		clients.c
		clientlist.c
		config.c
		config_init.c
		control.c
		default_acl.c
		dynamic_security.h
		groups.c
		grouplist.c
		../../common/json_help.c ../../common/json_help.h
		kicklist.c
		../../common/misc_mosq.c ../../common/misc_mosq.h
		../../common/password_mosq.c ../../common/password_mosq.h
		plugin.c
		roles.c
		rolelist.c
		tick.c
	)

	set(INCLIST
		"${CJSON_INCLUDE_DIRS}"
		"${mosquitto_SOURCE_DIR}/lib"
		"${mosquitto_SOURCE_DIR}/src"
	)

	set(LINKLIST
		cJSON
		OpenSSL::SSL
	)

	plugin_helper("${PLUGIN_NAME}" "${SRCLIST}" "${INCLIST}" "${LINKLIST}")
endif()
