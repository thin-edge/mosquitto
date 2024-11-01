#!/usr/bin/env python3

import subprocess
import time
import sys

class PTest():
    def __init__(self, testdef):
        self.ports = testdef[0]
        self.cmd = str(testdef[1])
        self.attempts = 0
        try:
            if isinstance(testdef[2], (list,)):
                self.args = [self.cmd] + testdef[2]
            else:
                self.args = [self.cmd] + [testdef[2]]
        except IndexError:
            self.args = [self.cmd]
        self.start_time = 0
        self.proc = None
        self.mosq_port = None
        self.runtime = 0

    def start(self):
        self.run_args = self.args.copy()
        for p in self.mosq_port:
            self.run_args.append(str(p))

        self.proc = subprocess.Popen(self.run_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.start_time = time.time()

    def print_result(self, col):
        cmd = " ".join(self.run_args)
        print(f"{self.runtime:0.3f}s : \033[{col}m{cmd}\033[0m")


def next_test(tests, ports):
    if len(tests) == 0 or len(ports) == 0:
        return

    test = tests.pop()
    test.mosq_port = []

    if len(ports) < test.ports:
        tests.insert(0, test)
        return None
    else:

        for i in range(0, test.ports):
            proc_port = ports.pop()
            test.mosq_port.append(proc_port)

        test.start()
        return test


def run_tests(test_list, minport=1888, max_running=20):
    ports = list(range(minport, minport+max_running+1))
    start_time = time.time()
    passed = 0
    retried = 0
    failed = 0

    tests = []
    for t in test_list:
        tests.append(PTest(t))

    failed_tests = []
    running_tests = []
    retry_tests = []
    while len(tests) > 0 or len(running_tests) > 0 or len(retry_tests) > 0:
        if len(running_tests) <= max_running:
            t = next_test(tests, ports)
            if t is None:
                time.sleep(0.1)
            else:
                running_tests.append(t)

        if len(running_tests) == 0 and len(tests) == 0 and len(retry_tests) > 0:
            # Only retry tests after everything else has finished to reduce load
            tests = retry_tests
            retry_tests = []

        for t in running_tests:
            t.proc.poll()
            if t.proc.returncode is not None:
                t.runtime = time.time() - t.start_time
                running_tests.remove(t)

                for portret in t.mosq_port:
                    ports.append(portret)
                t.proc.terminate()
                t.proc.wait()

                if t.proc.returncode == 1 and t.attempts < 5:
                    t.print_result(33)
                    retried += 1
                    t.attempts += 1
                    t.proc = None
                    t.mosq_port = None
                    retry_tests.append(t)
                    continue

                if t.proc.returncode == 1:
                    t.print_result(31)
                    failed = failed + 1
                    failed_tests.append(t.cmd)
                    print(f"{t.cmd}:")
                    (stdo, stde) = t.proc.communicate()
                else:
                    passed = passed + 1
                    t.print_result(32)

    print("Passed: %d\nRetried: %d\nFailed: %d\nTotal: %d\nTotal time: %0.2f" % (passed, retried, failed, passed+failed, time.time()-start_time))
    if failed > 0:
        print("Failing tests:")
        failed_tests.sort()
        for f in failed_tests:
            print(f)
        sys.exit(1)
