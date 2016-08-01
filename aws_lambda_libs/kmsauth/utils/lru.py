"LRU cache"
import collections


class LRUCache(object):
    """
    Cheap LRU cache implementation.
    """

    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = collections.OrderedDict()

    def __contains__(self, key):
        return key in self.cache

    def __getitem__(self, key):
        value = self.cache.pop(key)
        self.cache[key] = value
        return value

    def __setitem__(self, key, value):
        try:
            self.cache.pop(key)
        except KeyError:
            if len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)
        self.cache[key] = value
