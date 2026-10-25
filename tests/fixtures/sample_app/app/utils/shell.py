"""Shell helpers."""
import os
from subprocess import run


def run_command(cmd):
    def log(msg):
        os.system("logger " + msg)

    log(cmd)
    return run(cmd, shell=True, capture_output=True).stdout
