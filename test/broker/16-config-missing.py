#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

conf_file = os.path.basename(__file__).replace('.py', '.conf')

do_test_broker_failure(conf_file, [], cmd_args=['-c', conf_file], rc_expected=3, error_log_entry=f"Error: Unable to open config file '{conf_file}'.\n")

exit(0)
