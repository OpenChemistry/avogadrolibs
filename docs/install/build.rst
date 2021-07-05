.. _Build:

Building Source Code
=====================

The Open Chemistry project uses Git for version control, and CMake to
direct the build process. The `openchemistry
repository <https://github.com/OpenChemistry/openchemistry>`__ contains
git submodules with other actively developed projects such as
`Avogadro <Avogadro>`__, and
`MoleQueue <MoleQueue>`__. It will also automatically download source
tarballs and build them for third party dependencies, with variables
named USE_SYSTEM_LIBRARY to attempt to find and build against system
versions.

This page goes through the steps of building the Open Chemistry projects
using the openchemistry git repository. It is entirely possible to build
each project individually without using the "superbuild" approach, but
you will need to ensure all dependencies are built and can be found by
the project. 

Once successfully built you will be left with several build
directories which you can treat as normal build directories, developing
and compiling from inside them largely ignoring the outer build tree.

.. _cloning_repositories:

Cloning Repositories
^^^^^^^^^^^^^^^^^^^^^

You should clone the repositories from our source code hosting
infrastructure, or the Github/Gitorious mirror. You should also track
changes from here as the cloning/update process will be faster, and is
always in sync with Gerrit. To clone the Open Chemistry repository that
contains the other projects as submodules,

.. code-block:: shell

    git clone --recursive git://github.com/OpenChemistry/openchemistry.git

Updating
^^^^^^^^

In order to update the repository from the openchemistry module you can
run,

.. code-block:: shell

    git pull
    git submodule update --init

Prerequisites
^^^^^^^^^^^^^^

The Open Chemistry projects have a number of prerequisites, and these
vary by platform. On Windows Visual Studio 2017 is best supported. The
superbuild will attempt to build a number of dependencies, on Linux you
are likely best off installing these with your package manager, and on
macOS the homebrew package manager works well.

We should add a package listing for various Linux distributions, but as
a guide you will need:

- a C/C++ compiler that supports C++11
- OpenGL
- Qt 5.6+
- CMake 3.3+
- Python

Building
^^^^^^^^^

It is recommended that you create a build tree outside of the source
tree. Assuming you are in the directory where you cloned the repository
the following commands will create a build tree, configure it and build.

.. code-block:: shell

    mkdir openchemistry-build
    cd openchemistry-build
    cmake ../openchemistry
    cmake --build . --config Release

You may wish to run cmake-gui in the build directory once it has been
configured. You can build against system libraries to avoid building
them (examples include Boost, Eigen, etc), and turn testing on globally
(ENABLE_TESTS) if you would like to ensure all tests are configured and
built for sub-projects. The --config argument to cmake --build is only
used on the Windows platform with MSVC, and can be removed elsewhere.

.. _finding_qt_windows_generators:

Finding Qt, Windows Generators
------------------------------

We go to great care to use Qt5_DIR as the base for all Qt 5 modules, so
setting the correct Qt5_DIR should result in a valid tree, you can also
use CMAKE_PREFIX_PATH to point at the install prefix of Qt. When setting
Qt5_DIR for Windows, using Qt 5.10.1 as an example, you should set the
variable to 'C:/Qt/Qt5.10.1/5.10.1/msvc2017_64/lib/cmake/Qt5' (without
the quotes). As you upgrade, you can usually just replace the version
(that occurs twice), you must also be careful to match the CMake
generator to the compiler and architecture on Windows, I recommend
'Visual Studio 15 2017 Win64', we no longer build/test 32 bit binaries
on any platform.

.. _normal_development:

Normal Development
------------------

You can also open the top-level CMakeLists.txt in Qt Creator, choose the
build location, have that configure and build and then open the
top-level CMakeLists.txt for each of the sub-projects. When setting the
build location choose the openchemistry-build/avogadrolibs for Avogadro,
openchemistry-build/molequeue for MoleQueue, etc. Once you have compiled
the top-level, for normal day-to-day development you are free to ignore
it and perform the majority of work in the project being developed.

.. _build_tree_layout:

Build Tree Layout
^^^^^^^^^^^^^^^^^

The build tree mirrors the source tree for most active projects. So
avogadrolibs is in the same relative path in the source and build trees.
For things such as Boost which are built from a source tarball they can
be found only in the build tree, and are under thirdparty/boost-prefix,
these projects are dependencies but are not expected to be edited in
place.

There is a prefix directory in the base of the build tree. This acts as
an install prefix for all projects, with the normal include, bin, share
and lib directories. This can be used to inject an additional prefix in
CMAKE_PREFIX_PATH to ensure projects build by the superbuild are found.
It keeps the sub-projects relatively simple as they either find stuff in
the prefix, or normal system paths.

.. _running_executables:

Running Executables
-------------------

It is recommended that you run the binaries from within the prefix
directory in the build tree. The top-level targets (avogadroapp,
molequeue, monogochem) all install to the prefix, if running make from
within the individual build trees run make install to ensure you are
using the latest version. On Linux and Windows running Avogadro 2 looks
like,

.. code-block:: shell

    ./openchemistry-build/prefix/bin/avogadro2

On Mac, it might be:

.. code-block:: shell

    export DYLD_LIBRARY_PATH=/Users/your-user/openchemistry-build/prefix/lib
    open /Users/your-user/openchemistry-build/avogadroapp/bin/Avogadro2.app

We will look into improving this situation soon.

.. _building_packages:

Building Packages
-----------------

The molequeue and avogadroapps projects can build installers.
In order to do this you must cd into the appropriate subdirectory and
call make package. So to build the Avogadro 2 package,

.. code-block:: shell

    cd avogadroapp
    make package

You may need to run cmake-gui, toggle advanced variables and
enable/disable packages you are interested in. They are prefixed by
CPACK, and can be toggled before calling make package. A binary
installer will be created in the build directory.
