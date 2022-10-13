#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

vg_index = 0

def start_broker(filename):
    global vg_index
    cmd = ['../../src/mosquitto', '-v', '-c', filename]

    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        logfile = os.path.basename(__file__)+'.'+str(vg_index)+'.vglog'
        if os.environ.get('MOSQ_USE_VALGRIND') == 'callgrind':
            cmd = ['valgrind', '-q', '--tool=callgrind', '--log-file='+logfile] + cmd
        elif os.environ.get('MOSQ_USE_VALGRIND') == 'massif':
            cmd = ['valgrind', '-q', '--tool=massif', '--log-file='+logfile] + cmd
        else:
            cmd = ['valgrind', '-q', '--trace-children=yes', '--leak-check=full', '--show-leak-kinds=all', '--log-file='+logfile] + cmd

    vg_index += 1
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def write_config(filename, port, config_str):
    with open(filename, 'w') as f:
        f.write(f"{config_str}")


def do_test(config_str, rc_expected):
    rc = 1
    port = mosq_test.get_port()

    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, config_str)

    try:
        broker = start_broker(conf_file)
        broker.wait(timeout=1)

        if broker.returncode == rc_expected:
            rc = 0
    except mosq_test.TestError:
        pass
    except subprocess.TimeoutExpired:
        broker.terminate()
    except Exception as e:
        print(e)
    finally:
        os.remove(conf_file)
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print(config_str)
            exit(rc)


do_test("bridge_psk string\n", 3) # Missing bridge config
do_test("bridge_identity string\n", 3) # Missing bridge config


exit(0)
