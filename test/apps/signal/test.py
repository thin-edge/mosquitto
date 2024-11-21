#!/usr/bin/env python3

import mosq_test_helper
import pathlib
import ptest

tests = []

for test_file in pathlib.Path('.').glob('signal-*.py'):
    tests.append((1, test_file.resolve()))

test = ptest.PTest()
test.run_tests(tests)
