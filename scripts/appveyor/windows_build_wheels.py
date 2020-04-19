from subprocess import check_call
import os
import sys
import shutil

SCRIPT_DIR = os.path.dirname(__file__)
REPO_DIR = os.path.abspath(os.getcwd())
ROOT_DIR = os.path.abspath(os.path.join(REPO_DIR, '..'))

print('ROOT_DIR: %s' % ROOT_DIR)
print('REPO_DIR: %s' % REPO_DIR)

from wheel_builder_utils import push_dir, push_env
from windows_build_common import DEFAULT_PY_ENVS, venv_paths

def build_wheels(py_envs=DEFAULT_PY_ENVS):

    # Install Eigen
    eigen_build_dir = os.path.join(ROOT_DIR, 'eigen-build')
    os.mkdir(eigen_build_dir)
    eigen_install_dir = os.path.join(ROOT_DIR, 'eigen')
    check_call([
        'cmake', '-DCMAKE_INSTALL_PREFIX:PATH=%s' % eigen_install_dir,
        '../eigen-eigen-b3f3d4950030/'], cwd=eigen_build_dir)
    check_call(['cmake',  '--build',  '.',  '--target', 'install'], cwd=eigen_build_dir)


    for py_env in py_envs:
        python_executable, \
                python_include_dir, \
                python_library, \
                pip, \
                ninja_executable, \
                path = venv_paths(py_env)

        with push_env(PATH='%s%s%s' % (path, os.pathsep, os.environ['PATH'])):

            # Install dependencies
            requirements_file = os.path.join(REPO_DIR, 'requirements-dev.txt')
            if os.path.exists(requirements_file):
                check_call([pip, 'install', '--upgrade', '-r', requirements_file])
            check_call([pip, 'install', 'cmake'])
            check_call([pip, 'install', 'scikit_build'])
            check_call([pip, 'install', 'ninja'])

            build_type = 'Release'

            # Install pybind
            source_dir = os.path.join(ROOT_DIR, 'pybind11-2.2.4')
            build_dir = os.path.join(ROOT_DIR, 'pybind11-build')
            shutil.rmtree(build_dir, ignore_errors=True)
            os.mkdir(build_dir)
            install_dir = os.path.join(ROOT_DIR, 'pybind11-install')
            shutil.rmtree(install_dir, ignore_errors=True)
            os.mkdir(install_dir)

            check_call(['cmake',
                        '-GVisual Studio 14 2015 Win64',
                       '-DPYTHON_EXECUTABLE:PATH=%s' % python_executable,
                       '-DPYBIND11_TEST:BOOL=FALSE',
                       '-DCMAKE_INSTALL_PREFIX:PATH=%s' % install_dir,
                       source_dir], cwd=build_dir)

            check_call(['cmake',  '--build', '.', '--target', 'install'], cwd=build_dir)

            # Generate wheel
            check_call([
                python_executable,
                'setup.py', 'bdist_wheel',
                '--build-type', build_type, '-G', 'Ninja',
                '--',
                '-DCMAKE_MAKE_PROGRAM:FILEPATH=%s' % ninja_executable,
                '-DBUILD_TESTING:BOOL=OFF',
                '-DPYTHON_EXECUTABLE:FILEPATH=%s' % python_executable,
                '-DPYTHON_INCLUDE_DIR:PATH=%s' % python_include_dir,
                '-DPYTHON_LIBRARY:FILEPATH=%s' % python_library,
                '-Dpybind11_DIR:PATH=%s' % os.path.join(install_dir, 'share', 'cmake', 'pybind11'),
                '-DEIGEN3_INCLUDE_DIR:PATH=%s' % os.path.join(eigen_install_dir, 'include','eigen3')
            ])
            # Cleanup
            check_call([python_executable, 'setup.py', 'clean'])

if __name__ == '__main__':
    build_wheels()
