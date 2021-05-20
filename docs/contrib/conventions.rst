.. _Code Conventions:

Coding Conventions (C++)
========================

C++ Features
^^^^^^^^^^^^

-  Don't use exceptions or asserts - Avogadro is production code and should never crash
-  Prefer solutions from the Qt library over Boost/others in Qt
   dependent code

   -  In Avogadro use the C++11 features where necessary, they fall back
      to Boost on older compilers
   -  Avogadro offers AVO_OVERRIDE and AVO_FINAL (defines for new C++11
      override and final)

-  Minimize dependencies on third party libraries, think carefully
   before adding more
-  Use templates where they make sense
-  Submit proposed topics to Gerrit

   -  Monitor the CDash@Home builds and nightly builds once merged to
      ensure support in all supported compilers

.. _including_headers:

Including Headers
^^^^^^^^^^^^^^^^^^

-  In public headers, always use this form to include project headers:
   #include <avogadro/core/something.h>
-  Prefer declaration of types in public headers over including headers
   for the type

.. code:: cpp

   namespace Avogadro {
   class MyClass;
   }

-  In source files include specialized headers first, then dependency
   headers, then generic headers

.. code:: cpp

    #include "myapiheader.h" // Our header
    #include <avogadro/core/molecule.h> // Avogadro header from a different module
    #include <QtCore/QString> // Qt header
    #include <vector> // STL

.. _export_macro_headers:

Export Macro Headers
--------------------

-  If you need to include the export header for the module do it as the
   first include

.. code:: cpp

    #include "avogadrorenderingexport.h"

.. _private_headers:

Private Headers
---------------

-  Private headers are denoted by \_p.h endings, and should not be
   included in public headers

.. _qt_headers:

Qt Headers
----------

-  Use the Qt module and camel-cased header
-  Never include Qt module headers such as QtGui, instead include the
   header for the class being used

.. code:: cpp

    #include <QtGui> // WRONG (module header)!
    #include <QtGui/QDialog> // Correct

Namespaces
^^^^^^^^^^

-  Open Chemistry code is namespaced
-  Avogadro uses nested namespaces

   -  Everything is inside the Avogadro namespace
   -  Code in the core module is in the Avogadro::Core namespace

-  MoleQueue and MongoChem use a namespace to contain most code
-  Don't overspecify, i.e. code in the Avogadro namespace doesn't need
   to use Avogadro::

   -  Qt signals and slots are one exception where MOC often needs a little help

-  Never use using inside a public header

   -  Only pull in specific symbols in source files, i.e. using
      Avogadro::Core::Molecule;

Casting
^^^^^^^

-  Avoid C-style casts, prefer C++ (static_cast, dynamic_cast,
   const_cast, reinterpret_cast)
-  For Qt classes, and Qt derived classes prefer qobject_cast over
   dynamic_cast

Aesthetics
^^^^^^^^^^

-  Prefer enums to define constants over static const int or defines
-  Prefer verbose argument names in headers

   -  Most IDEs show the argument names in their autocompletion
   -  It looks better in the generated documentation
   -  Poor style making people guess what an argument is for

-  Avoid abbreviations, as they are often ambiguous and we can afford
   the extra bytes
