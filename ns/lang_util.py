#!/usr/bin/python

import subprocess
import sys

IS_PY2 = (sys.version_info[0] == 2)
if IS_PY2:
    def is_string(obj):
        return isinstance(obj, basestring)
else:
    def is_string(obj):
        return isinstance(obj, str)

def is_integral(obj):
    return isinstance(obj,int) or isinstance(obj,long)

def listize(obj):
    if isinstance(obj,tuple) or isinstance(obj,list):
        return list(obj)
    return [obj]

def dictize(obj):
    if not isinstance(obj, dict):
        obj=listize(obj)
        # convert lists into index-keyed dicts
        obj=dict(zip(xrange(len(obj)), obj))
    return obj

def boolize(obj):
    if is_string(obj):
        if obj.isdigit():
            return bool(int(obj))
        else:
            return obj in ['1', 'True', 'true']
    return bool(obj)

class Platform(object):  # basically an enum
    LINUX, WINDOWS, OSX = range(3)

def platform():
    """ Returns the current platform. """
    name=sys.platform
    if name.startswith('linux'):
        return Platform.LINUX
    elif name.startswith('win'):
        return Platform.WINDOWS
    elif name.startswith('darwin'):
        return Platform.OSX
    return None

class Capture(object):  # basically an enum
    OUTPUT, ERROR, BOTH, MERGED = range(4)

class ChildProcess(object):
    def __init__(self, cmd_arg_list, capture, env):
        cmd_arg_list = listize(cmd_arg_list)

        stdout = None
        if capture in [Capture.OUTPUT, Capture.BOTH, Capture.MERGED]:
            stdout = subprocess.PIPE
        stderr = None
        if capture in [Capture.ERROR, Capture.BOTH]:
            stderr = subprocess.PIPE
        elif capture == Capture.MERGED:
            stderr = subprocess.STDOUT

        close_fds = (platform() != Platform.WINDOWS)

        self._output = None
        if capture is None:
            self._output = (None, None)

        self.child = subprocess.Popen(cmd_arg_list, close_fds = close_fds,
                stdout = stdout, stderr = stderr, env = env)

    def wait(self):
        self.child.wait()
        return self  # allow chaining

    def poll(self):
        return self.child.poll()

    def output(self):
        """ Returns a tuple of the program's stdout and stderr output, if it
        was captured.  If output was captured as MERGED, all data will be in
        the stdout position. """
        if self._output is None:
            self._output = self.child.communicate()
        return self._output

    def return_code(self):
        return self.child.returncode

def run(arg_list, capture = None, env = None):
    """ Executes the provided command/argument list and returns an ChildProcess
    object to interact with that process.

    Keyword arguments:
        arg_list -- a list with the first element being the command name and
            the rest being arguments to that command
        capture -- what kind of output capturing is requested (default None)
        env -- the environment for the subprocess if different (default None)
    """
    return ChildProcess(arg_list, capture = capture, env = env)
