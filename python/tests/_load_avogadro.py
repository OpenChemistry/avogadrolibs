"""
Import avogadro.connect for tests, without requiring a fully built wheel.

``avogadro/__init__.py`` eagerly imports the compiled ``core`` and ``io``
extension modules, so a plain ``import avogadro`` fails in a source
checkout that has not been built (no C++ compiler run, no pybind11
extensions present). ``connect.py`` itself has no avogadro-internal
imports -- only the standard library -- so these tests do not need those
extensions at all.

load_connect_module() prefers a real, already-installed ``avogadro``
package (e.g. in CI, after ``pip install .`` builds the wheel) and only
falls back to loading ``connect.py`` through a minimal stand-in package
when the real one cannot be imported. Either way, callers get back the
same module object shape: ``.connect``, ``.RPCError``, ``.result_data``.
"""

import importlib
import sys
import types
from pathlib import Path

_AVOGADRO_DIR = Path(__file__).resolve().parent.parent / "avogadro"


def load_connect_module():
    if "avogadro" not in sys.modules:
        try:
            importlib.import_module("avogadro")
        except ImportError:
            stub = types.ModuleType("avogadro")
            stub.__path__ = [str(_AVOGADRO_DIR)]
            sys.modules["avogadro"] = stub
    return importlib.import_module("avogadro.connect")
