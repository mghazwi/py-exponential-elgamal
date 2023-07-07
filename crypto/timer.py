import contextlib
import time


@contextlib.contextmanager
def time_measure(key, should_print=False, skip=False):
    start = time.time()
    yield
    end = time.time()
    elapsed = end - start

    print(f"{key} took {elapsed} s")


class Timer(object):

    def __init__(self, key):
        self.key = key

    def __call__(self, method):
        def timed(*args, **kw):
            with time_measure(self.key):
                result = method(*args, **kw)
                return result

        return timed
