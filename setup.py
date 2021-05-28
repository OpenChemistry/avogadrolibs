import os

from skbuild import setup


def extra_cmake_args():
    # FIXME: this doesn't seem to work if we supply more than one argument.
    # I really am not sure why.
    env = os.getenv('EXTRA_CMAKE_ARGS')
    return env.split(';') if env else []


def wheel_args():
    # Check if we are building wheels...
    env = os.getenv('GITHUB_WORKFLOW')
    args = [
      '-DPYTHON_WHEEL_BUILD:BOOL=TRUE',
    ]
    return args if env == 'Build Wheels' else []


cmake_args = [
    '-DUSE_SPGLIB:BOOL=FALSE',
    '-DUSE_OPENGL:BOOL=FALSE',
    '-DUSE_QT:BOOL=FALSE',
    '-DUSE_MMTF:BOOL=FALSE',
    '-DUSE_PYTHON:BOOL=TRUE',
    '-DUSE_HDF5:BOOL=FALSE',
    '-DUSE_LIBARCHIVE:BOOL=FALSE',
    '-DUSE_LIBMSYM:BOOL=FALSE',
] + extra_cmake_args() + wheel_args()

# Add pybind11 if it is installed
try:
    from pybind11 import get_cmake_dir
except ImportError:
    pass
else:
    cmake_args.append('-Dpybind11_DIR:PATH=' + get_cmake_dir())

setup(
    name='avogadro',
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    description='Avogadro provides analysis and data processing useful in computational chemistry, molecular modeling, bioinformatics, materials science, and related areas.',
    author='Kitware',
    license='BSD',
    url='https://github.com/OpenChemistry/avogadrolibs',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: C++',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: Science/Research',
        'Topic :: Scientific/Engineering',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Topic :: Software Development :: Libraries',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Unix',
        'Operating System :: MacOS'
        ],
    packages=['avogadro'],
    cmake_args=cmake_args,
)
