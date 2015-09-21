#!/usr/bin/env python3

def listize(obj):
    if isinstance(obj, tuple) or isinstance(obj, list):
        return list(obj)
    return [obj]

def dictize(obj):
    if not isinstance(obj, dict):
        obj=listize(obj)
        # convert lists into index-keyed dicts
        obj=dict(zip(xrange(len(obj)), obj))
    return obj

def boolize(obj):
    if isinstance(obj, str):
        if obj.isdigit():
            return bool(int(obj))
        else:
            return obj in ['1', 'True', 'true']
    return bool(obj)
