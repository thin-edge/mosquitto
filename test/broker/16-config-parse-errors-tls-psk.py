#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

conf_file = os.path.basename(__file__).replace('.py', '.conf')

do_test_broker_failure(conf_file, ["bridge_psk string"], 3, "Error: The 'bridge_psk' option requires a bridge to be defined first.")
do_test_broker_failure(conf_file, ["bridge_identity string"], 3, "Error: The 'bridge_identity' option requires a bridge to be defined first.")

exit(0)
