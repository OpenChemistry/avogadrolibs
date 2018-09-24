from skbuild import setup

setup(
    name="avogadrolibs",
    version="0.0.1",
    description="",
    author='Kitware',
    license="BSD",
    #package_dirs={
    #    'avogadro': 'python/avogadro'
    #},
    packages=['avogadro'],
    cmake_args=[
        '-DUSE_SPGLIB:BOOL=FALSE',
        '-DUSE_OPENGL:BOOL=FALSE',
        '-DUSE_QT:BOOL=FALSE',
        '-DUSE_MMTF:BOOL=FALSE',
        '-DUSE_PYTHON:BOOL=TRUE',
        '-DUSE_MOLEQUEUE:BOOL=FALSE',
        '-DUSE_HDF5:BOOL=FALSE',
        '-DUSE_LIBARCHIVE:BOOL=FALSE',
        '-DUSE_LIBMSYM:BOOL=FALSE',
        '-DBUILD_BINARY_WHEEL:BOOL=TRUE'
    ]
)

