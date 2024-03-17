add_executable(libcommon-test
	utf8.c
	test.c
)

target_link_libraries(libcommon-test
	PRIVATE
		common-unit-test-header
		OpenSSL::SSL
		libmosquitto_common
)
add_test(NAME unit-libcommon-test COMMAND libcommon-test)
