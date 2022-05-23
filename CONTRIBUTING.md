Contributing
------------

Avogadro welcomes new development and ideas! We are an open community, made better by all of us.

If you're an Avogadro user who wants to give back, a great
place to start is supporting your fellow users on the [Avogadro
Forum](https://discuss.avogadro.cc/). Questions of all levels are posted, 
and you may find that there are some for which your experience is very valuable!

If you find a bug or have a feature suggestion, please take a moment
to submit a description to the [GitHub Tracker](https://github.com/openchemistry/avogadrolibs/issues/), 
which helps as an open
database of issues and suggestions as the code is developed. While there are
several different GitHub repositories for the project, we will move
issues around if they better fit a particular component.

For development of Avogadro itself, the [Avogadro
Forum](https://discuss.avogadro.cc/) has sections for discussing
ideas, planned directions, work in progress, etc. This includes both the C++ libraries
and Python scripts and utilities.

## Contributing Code

Our project uses the standard GitHub pull request process for code review
and integration. Please check our [development][Development] guide for more
details on developing and contributing to the project. The GitHub issue
tracker can be used to report bugs, make feature requests, etc.

The best way to coordinate development, get support, and offer feedback is
through the [Avogadro Discussion forum](https://discuss.avogadro.cc/)

## Coding Conventions

### C++ Features

-  Don't use exceptions or asserts - Avogadro is production code and should never crash
-  Prefer solutions from the Qt library over Boost/others in Qt
   dependent code

   -  In Avogadro use the C++11 or C++17 features where necessary, they fall back
      to Boost on older compilers
   -  Be careful about using newer language features, since Avogadro runs on many
      different compilers and platforms. Visual C++ and Clang may not support every
      feature in GCC.

-  Minimize dependencies on third party libraries, think carefully
   before adding more. If in doubt, please ask.
-  Use templates where they make sense

### Casting

-  Avoid C-style casts, prefer C++ (static_cast, dynamic_cast,
   const_cast, reinterpret_cast)
-  For Qt classes, and Qt derived classes prefer qobject_cast over
   dynamic_cast

### Aesthetics

-  Prefer enums to define constants over static const int or defines
-  Prefer verbose argument names in headers

   -  Most IDEs show the argument names in their autocompletion
   -  It looks better in the generated documentation
   -  Poor style making people guess what an argument is for

-  Avoid abbreviations, as they are often ambiguous and we can afford
   the extra bytes
-  Please use comments and docstrings frequently. You will appreciate it
   yourself when looking back over code. It may make sense now, but in 
   a few weeks or months, you may not remember why you wrote that particular
   implementation. (Let alone reading other people's code in a large project.)

For more on [Coding Style](http://two.avogadro.cc/contrib/style.html) see the
[style guide](http://two.avogadro.cc/contrib/style.html) which is enforced through
`clang-format` which runs as part of our continuous integration.

## A Quick Note About Plugins

For the most part, Avogadro plugins should be published to your own repository.

Examples:
- Input Generators: https://github.com/OpenChemistry/avogenerators
- Example Commands: https://github.com/OpenChemistry/avogadro-commands
- cclib Import: https://github.com/OpenChemistry/avogadro-cclib
- Nanocar Builder: https://github.com/kbsezginel/nanocar-avogadro
- ASE: https://github.com/ghutchis/avogadro-build-ase
- RDKit: https://github.com/ghutchis/avogadro-rdkit
- GenIce: https://github.com/ghutchis/avogadro-genice
- SciKitNano: https://github.com/ghutchis/avogadro-scikit-nano

  [Development]: http://two.avogadro.cc/contrib/code.html "Development guide"
  [Wiki]: http://wiki.openchemistry.org/ "Open Chemistry wiki"
  [Doxygen]: http://two.avogadro.cc/api/index.html "API documentation"
