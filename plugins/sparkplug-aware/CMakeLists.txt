set(PLUGIN_NAME mosquitto_sparkplug_aware)

set(SRCLIST
	on_message.c
	plugin.c
)

set(INCLIST )
set(LINKLIST )

plugin_helper("${PLUGIN_NAME}" "${SRCLIST}" "${INCLIST}" "${LINKLIST}")
