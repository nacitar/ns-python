#!/usr/bin/env python3

def listize(obj):
    """ If obj is iterable and not a string, returns a new list with the same
    contents.  Otherwise, returns a new list with obj as its only element.
    """
    if not isinstance(obj, str):
        try:
            return list(obj)
        except:
            pass
    return [obj]

def dictize(obj):
    """ If obj can be directly converted into a dictionary, returns a new
    dictionary made from obj.  Otherwise, obj is listized and a new dictionary
    is returned with indexes as keys and the provided values as values.
    """
    try:
        return dict(obj)
    except:
        obj = listize(obj)
        # convert lists into index-keyed dicts
        return dict(zip(xrange(len(obj)), obj))

def boolize(obj):
    """ If obj is a str, returns True if obj is 'True', 'true', or a string
    representing a non-zero integer.  If obj is not a str, returns a direct
    conversion to bool.
    """
    if isinstance(obj, str):
        if obj.isdigit():
            obj = int(obj)
        else:
            return obj in ['True', 'true']
    return bool(obj)

# TODO: move this
class Range(object):
    """ A simple range class with the sole purpose of allowing str conversion
    to yield something iptables length-matching friendly.
    """
    def __init__(self, start, stop):
        self._value = range(start, stop)

    def __iter__(self):
        return self._value.__iter__()

    def __str__(self):
        return '%s:%s' % (self._value.start, self._value.stop)
