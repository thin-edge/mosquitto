#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

def start_broker(filename):
    cmd = [mosq_test.get_build_root() + '/src/mosquitto', '-v', '-c', filename]

    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        logfile = os.path.basename(__file__)+'.vglog'
        if os.environ.get('MOSQ_USE_VALGRIND') == 'callgrind':
            cmd = ['valgrind', '-q', '--tool=callgrind', '--log-file='+logfile] + cmd
        elif os.environ.get('MOSQ_USE_VALGRIND') == 'massif':
            cmd = ['valgrind', '-q', '--tool=massif', '--log-file='+logfile] + cmd
        else:
            cmd = ['valgrind', '-q', '--trace-children=yes', '--leak-check=full', '--show-leak-kinds=all', '--log-file='+logfile] + cmd

    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


conf_file = os.path.basename(__file__).replace('.py', '.conf')

broker = start_broker(conf_file)
mosq_test.wait_for_subprocess(broker)


assert(broker.returncode == 3)
(_, stde) = broker.communicate()
error_message = stde.decode('utf-8')
if not error_message.endswith(f"Error: Unable to open config file {conf_file}.\n"):
    print(f"Got wrong error message: '{error_message}'")
    exit(1)
    
exit(0)
