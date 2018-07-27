clang-format
------------

We use [clang-format][clang-format] to keep formatting in the code base
consistent. Please run clang-format on your patches before submitting.

clang-format ships with a Python script ```clang/tools/clang-format-diff.py```
that can be used to reformat patches. For example the following command will
reformat all the lines in the latest commit

```shell
git diff -U0 HEAD^ | clang-format-diff.py -i -p1

```

clang-format also provides [git-clang-format][git-clang-format], a script that
more closely integrates with git. If you add this script to your path you can
using the following command to reformat all the lines in the latest commit.

```shell
git clang-format HEAD~1

```

### clang-format-diff locations by platform

The exact location of the Python script varies by platform/distro. The table
below provides the location on some common platform/distro's

| Platform/Distro.  | Location                             |
| ---------------- |:-------------------------------------:|
| Arch Linux       | /usr/share/clang/clang-format-diff.py |
| Ubuntu           | /usr/bin/clang-format-diff-3.8        |

The script can also be downloaded [here][clang-format-diff].

Code style
----------

This project is developed primarily in C++ and Python. Please follow these code
style guidelines when contributing code to our project.

* Alphabetize includes

* Use #include "xxx" for local includes, #include \<xxx\> for external includes.

* Do not add comment separators before function definitions.

* Split long lines, when reasonable, to avoid going over 80 characters per line.

* Add a space after the commas in parameter lists, e.g.,
  function(a, b, c), not function(a,b,c)

* Add spaces between operators, e.g. 5 - 2, not 5-2.

* For class names, use CamelCase, starting their names with an upper-case
  letter.

* For local variables and function names, use camelCase, starting names with a
  lower-case letter.

* For member variables, prefix them with m\_, i.e. m\_camelCase, starting the
  name with a lower-case letter.

* For comments, add a space between // and the beginning of the comment, e.g.,

    * // A comment
    * \# Python comment

* Use 2 spaces when indenting C++ code, 4 spaces for Python code.

* Do not indent inside namespaces, e.g.,

        namespace Avogadro {
        namespace Core {
        void foo();
        }
        }

* Curly braces marking the start and end of a code block should be on
  separate lines and aligned vertically with the statement preceding
  the block, e.g.,

        if (condition) {
          statement;
        }

        for (int i = 0; i < n; ++i) {
          statement;
        }

* Assume that C++11 features are available, and prefer them over legacy macros,
  defines, etc. A few examples follow, but are not exhaustive.

    * Use override to specify member overrides in derived classes.
    * Set default values of member variables directly in definitions.
    * Use nullptr instead of NULL.

### C++ Features

* Don't use exceptions
* Prefer solutions from the Qt library over others in Qt dependent code
* Minimize dependencies on third party libraries, think carefully before adding
  more
* Use templates where they make sense

### Including Headers

* In public headers, always use this form to include project headers:
  #include <avogadro/core/something.h>
* Prefer declaration of types in public headers over including headers for the
  type

        namespace Avogadro {
        class MyClass;
        }

* In source files include specialized headers first, then dependency headers,
  then generic headers

        #include "myapiheader.h" // Our header
        #include <avogadro/core/molecule.h> // Avogadro header from a different module
        #include <QtCore/QString> // Qt header
        #include <vector> // STL

* If you need to include the export header for the module do it as the first include

        #include "avogadrorenderingexport.h"

* Private headers are denoted by _p.h endings, and should not be included in
  public headers
* Use the Qt module and camel-cased header
* Never include Qt module headers such as QtGui, instead include the header for
  the class being used

        #include <QtGui> // WRONG (module header)!
        #include <QtGui/QDialog> // Correct

### Namespaces

* Avogadro uses nested namespaces
  * Everything is inside the Avogadro namespace
  * Code in the core module is in the Avogadro::Core namespace
* Don't overspecify, i.e. code in the Avogadro namespace doesn't need to use
  Avogadro::
  * Qt signals and slots are one exception where MOC often needs a little help
* Never use using inside a public header
  * Only pull in specific symbols in source files, i.e. using
    Avogadro::Core::Molecule;

### Casting

* Avoid C-style casts, prefer C++ (static_cast, dynamic_cast, const_cast,
  reinterpret_cast)
* For Qt classes, and Qt derived classes prefer qobject_cast over dynamic_cast

### Aesthetics

* Prefer enums to define constants over static const int or defines
* Prefer verbose argument names in headers
  * Most IDEs show the argument names in their autocompletion
  * It looks better in the generated documentation
  * Poor style making people guess what an argument is for
* Avoid abbreviations, as they are often ambiguous and we can afford the extra
  bytes

[clang-format]: http://llvm.org/releases/3.8.0/tools/clang/docs/ClangFormatStyleOptions.html
[git-clang-format]: https://llvm.org/svn/llvm-project/cfe/trunk/tools/clang-format/git-clang-format
[flake8]: https://pypi.python.org/pypi/flake8
[clang-format-diff]: https://llvm.org/svn/llvm-project/cfe/trunk/tools/clang-format/clang-format-diff.py
