from skbuild import setup

setup(
    name="avogadro",
    version="0.0.8",
    description="",
    author='Kitware',
    license="BSD",
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
        '-DUSE_LIBMSYM:BOOL=FALSE'
    ]
)

