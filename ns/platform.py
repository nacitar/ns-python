#!/usr/bin/env python3
from enum import Enum
import platform as _platform
import sys as _sys

class OS(Enum):
    LINUX, WINDOWS, OSX = range(3)

def id():
    """ Returns the current platform. """
    name = _sys.platform
    if name.startswith('linux'):
        return Platform.OS.LINUX
    elif name.startswith('win'):
        return Platform.OS.WINDOWS
    elif name.startswith('darwin'):
        return Platform.OS.OSX
    return None

def bits():
    """ Determines the number of bits for this platform. """
    arch = _platform.machine()
    if arch in ['AMD64', 'x86_64', '64bit']:
        return 64
    if arch in ['x86', 'i386', '32bit']:
        return 32
    raise RuntimeError('Could not detect architecture bits.')
