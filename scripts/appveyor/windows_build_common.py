__all__ = ['DEFAULT_PY_ENVS', 'venv_paths']

from subprocess import check_call
import os

DEFAULT_PY_ENVS = ['35-x64', '36-x64', '37-x64']

SCRIPT_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', '..'))

def venv_paths(python_version):

    # Create venv
    venv_executable = 'C:/Python%s/Scripts/virtualenv.exe' % (python_version)
    venv_dir = os.path.join(ROOT_DIR, 'venv-%s' % python_version)
    check_call([venv_executable, venv_dir])

    python_executable = os.path.join(venv_dir, 'Scripts', 'python.exe')
    python_include_dir = os.path.join(venv_dir, 'Include')

    # XXX It should be possible to query skbuild for the library dir associated
    #     with a given interpreter.
    xy_ver = python_version.split('-')[0]

    python_library = 'C:/Python%s/libs/python%s.lib' % (python_version, xy_ver)

    print('')
    print('PYTHON_EXECUTABLE: %s' % python_executable)
    print('PYTHON_INCLUDE_DIR: %s' % python_include_dir)
    print('PYTHON_LIBRARY: %s' % python_library)

    pip = os.path.join(venv_dir, 'Scripts', 'pip.exe')

    ninja_executable = os.path.join(
        ROOT_DIR, 'venv-35-x64', 'Scripts', 'ninja.exe')
    print('NINJA_EXECUTABLE:%s' % ninja_executable)

    # Update PATH
    path = os.path.join(venv_dir, 'Scripts')

    return python_executable, \
        python_include_dir, \
        python_library, \
        pip, \
        ninja_executable, \
        path
