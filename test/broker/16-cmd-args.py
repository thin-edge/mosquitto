#!/usr/bin/env python3

# Test whether command line args are handled

from mosq_test_helper import *

do_test_broker_failure("", [], cmd_args=["-h"], rc_expected=3)
do_test_broker_failure("", [], cmd_args=["-p", "0"], rc_expected=3) # Port invalid
do_test_broker_failure("", [], cmd_args=["-p", "65536"], rc_expected=3) # Port invalid
do_test_broker_failure("", [], cmd_args=["-p"], rc_expected=3) # Missing port
do_test_broker_failure("", [], cmd_args=["-c"], rc_expected=3) # Missing config
do_test_broker_failure("", [], cmd_args=["--tls-keylog"], rc_expected=3) # Missing filename
do_test_broker_failure("", [], cmd_args=["--unknown"], rc_expected=3) # Unknown option

exit(0)
