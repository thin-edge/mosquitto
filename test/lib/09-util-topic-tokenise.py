#!/usr/bin/env python3

from mosq_test_helper import *

rc = 1

client_args = sys.argv[1:]
client = mosq_test.start_client(filename=sys.argv[1].replace('/', '-'), cmd=client_args)

if mosq_test.wait_for_subprocess(client):
    print("test client not finished")
    rc=1
else:
    rc=client.returncode
exit(rc)
