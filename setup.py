from skbuild import setup

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

