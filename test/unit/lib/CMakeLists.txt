add_executable(lib-test
	datatype_read.c
	datatype_write.c
	misc_trim_test.c
	property_add.c
	property_read.c
	property_user_read.c
	property_write.c
	property_value.c
	stubs.c
	util_topic_test.c
	# main test files
	test.c
	../../../lib/memory_mosq.c
	../../../common/misc_mosq.c
	../../../lib/packet_datatypes.c
	../../../lib/packet_mosq.c
	../../../lib/property_mosq.c
	../../../lib/util_mosq.c
	../../../lib/util_topic.c
)

target_link_libraries(lib-test PRIVATE common-unit-test-header OpenSSL::SSL libmosquitto_common)
add_test(NAME unit-lib-test COMMAND lib-test)
