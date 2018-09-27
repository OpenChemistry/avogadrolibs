
"""This module provides convenient function facilitating scripting.

These functions have been copied from scikit-build project.
See https://github.com/scikit-build/scikit-build
"""

import errno
import os

from contextlib import contextmanager
from functools import wraps


def mkdir_p(path):
    """Ensure directory ``path`` exists. If needed, parent directories
    are created.

    Adapted from http://stackoverflow.com/a/600612/1539918
    """
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:  # pragma: no cover
            raise


@contextmanager
def push_env(**kwargs):
    """This context manager allow to set/unset environment variables.
    """
    saved_env = dict(os.environ)
    for var, value in kwargs.items():
        if value is not None:
            os.environ[var] = value
        elif var in os.environ:
            del os.environ[var]
    yield
    os.environ.clear()
    for (saved_var, saved_value) in saved_env.items():
        os.environ[saved_var] = saved_value


class ContextDecorator(object):
    """A base class or mixin that enables context managers to work as
    decorators."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __enter__(self):
        # Note: Returning self means that in "with ... as x", x will be self
        return self

    def __exit__(self, typ, val, traceback):
        pass

    def __call__(self, func):
        @wraps(func)
        def inner(*args, **kwds):  # pylint:disable=missing-docstring
            with self:
                return func(*args, **kwds)
        return inner


class push_dir(ContextDecorator):
    """Context manager to change current directory.
    """
    def __init__(self, directory=None, make_directory=False):
        """
        :param directory:
          Path to set as current working directory. If ``None``
          is passed, ``os.getcwd()`` is used instead.

        :param make_directory:
          If True, ``directory`` is created.
        """
        self.directory = None
        self.make_directory = None
        self.old_cwd = None
        super(push_dir, self).__init__(
            directory=directory, make_directory=make_directory)

    def __enter__(self):
        self.old_cwd = os.getcwd()
        if self.directory:
            if self.make_directory:
                mkdir_p(self.directory)
            os.chdir(self.directory)
        return self

    def __exit__(self, typ, val, traceback):
        os.chdir(self.old_cwd)
