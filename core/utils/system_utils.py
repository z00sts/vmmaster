import subprocess
import sys


def run_command(command, silent=False):
    process = subprocess.Popen(
        command, stderr=subprocess.STDOUT, stdout=subprocess.PIPE
    )

    if not silent:
        output = ""
        while process.poll() is None:
            line = process.stdout.readline()
            sys.stdout.write(line)
            output += line

        sys.stdout.write('\n')
        # FIXME: do not print "qemu-img create -f qcow2 -b" result in STDOUT
    else:
        process.wait()

    return process.returncode, process.communicate()[0]
