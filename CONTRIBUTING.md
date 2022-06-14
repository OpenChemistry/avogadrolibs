# Contributing

Avogadro welcomes new development and ideas! We are an open community, made better by all of us.

If you're an Avogadro user who wants to give back, a great
place to start is supporting your fellow users on the [Avogadro
Forum](https://discuss.avogadro.cc/). Questions of all levels are posted,
and you may find that there are some for which your experience is very valuable!

If you find a bug or have a feature suggestion, please take a moment
to submit a description to the
[GitHub Tracker](https://github.com/openchemistry/avogadrolibs/issues/),
which helps as an open
database of issues and suggestions as the code is developed. While there are
several different GitHub repositories for the project, we will move
issues around if they better fit a particular component.

For development of Avogadro itself, the [Avogadro
Forum](https://discuss.avogadro.cc/) has sections for discussing
ideas, planned directions, work in progress, etc. This includes both
the C++ libraries and Python scripts and utilities.

## Contributing Code

Our project uses the standard GitHub pull request process for code review
and integration. Please check our [development][Development] guide for more
details on developing and contributing to the project. The [GitHub issue
tracker](https://github.com/openchemistry/avogadrolibs/issues) can be 
used to report bugs, make feature requests, etc.

The best way to coordinate development, get support, and offer feedback is
through the [Avogadro Discussion forum](https://discuss.avogadro.cc/)

If you are new to Git, the Software Carpentry's [Version Control with
Git](https://swcarpentry.github.io/git-novice/) tutorial is a good place to
start.  More learning resources are listed in the [GitHub Learning Resources]
(https://help.github.com/en/github/getting-started-with-github/git-and-github-learning-resources)

1. Make sure you have a free [GitHub](https://github.com/) account. To increase
   the security of your account, we strongly recommend that you configure
   [two-factor authentication](https://docs.github.com/en/github/authenticating-to-github/securing-your-account-with-two-factor-authentication-2fa).
   Additionally, you may want to [sign your commits](https://docs.github.com/en/github/authenticating-to-github/managing-commit-signature-verification). We will not accept
   commits without your full name in the signature for proper attribution and citation.
   Please do not submit (semi-)anonymous contributions.

2. Fork the [OpenChemistry repository](https://github.com/openchemistry/openchemistry) on
   GitHub to make your changes.  To keep your copy up to date with respect to
   the main repository, you need to frequently [sync your
   fork](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/syncing-a-fork):

   In general, most changes occur in the `avogadrolibs` repository, with some fewer changes
   in the `avogadroapp` repository too.

   ```
   git remote add upstream https://github.com/openchemistry/avogadrolibs
   git fetch upstream
   git checkout dev
   git merge upstream/dev
   ```

3. Build OpenChemistry and `avogadrolibs`. You will find full instructions on [building from source code](http://two.avogadro.cc/install/build.html) on the Avogadro2 website.

4. Avogadro contains dozens of tests of different types and complexity and
   running each is difficult and probably not reasonable on your workstation.
   Most will be run as part of our Continuous Integration as part of a
   pull request.

   If possible, also try to add new tests for the features added or bugs fixed
   by your pull request.

   Developers reviewing your pull request will be happy to help you add or run
   the relevant tests as part of the pull request review process.

5. Write a useful and properly formatted commit message.
   Follow [these guidelines and template](https://git-scm.com/book/en/v2/Distributed-Git-Contributing-to-a-Project#_commit_guidelines),
   in particular start your message with a short imperative sentence on a single
   line, possibly followed by a blank line and a more detailed explanation.

   In the detailed explanation it's good to include relevant external references
   (e.g. GitHub issue fixed) using full URLs, and errors or tracebacks the
   commit is supposed to fix.
   You can use the Markdown syntax for lists and code highlighting, wrapping the
   explanation text at 72 characters when possible.

6. Commit and push your changes to your
   [fork](https://help.github.com/en/github/using-git/pushing-commits-to-a-remote-repository).

7. Open a [pull
   request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request)
   with these changes. Your pull request message ideally should include:

   * Why you made the changes (e.g. references to GitHub issues being fixed).

   * A description of the implementation of the changes.

   * How to test the changes, if you haven't included specific tests already.

8. The pull request should pass all the continuous integration tests which are
   automatically started by GitHub.

9. Your pull request will be handled by code review and the
   continuous integration tests.

## Coding Conventions

### C++ Features

* Don't use exceptions or asserts - Avogadro is production code and 
  should never crash
* Prefer solutions from the Qt library over Boost/others in Qt
  dependent code

  * In Avogadro use the C++11 or C++17 features where necessary, they fall back
    to Boost on older compilers
  * Be careful about using newer language features, since Avogadro runs on many
      different compilers and platforms. Visual C++ and Clang may not 
      support every feature in GCC.

* Minimize dependencies on third party libraries, think carefully
   before adding more. If in doubt, please ask.
* Use templates where they make sense

### Casting

* Avoid C-style casts, prefer C++ (static_cast, dynamic_cast,
   const_cast, reinterpret_cast)
* For Qt classes, and Qt derived classes prefer qobject_cast over
   dynamic_cast

### Aesthetics

* Prefer enums to define constants over static const int or defines
* Prefer verbose argument names in headers

  * Most IDEs show the argument names in their autocompletion
  * It looks better in the generated documentation
  * Poor style making people guess what an argument is for

* Avoid abbreviations, as they are often ambiguous and we can afford
   the extra bytes
* Please use comments and docstrings frequently. You will appreciate it
   yourself when looking back over code. It may make sense now, but in
   a few weeks or months, you may not remember why you wrote that particular
   implementation. (Let alone reading other people's code in a large project.)

For more on [Coding Style](http://two.avogadro.cc/contrib/style.html) see the
[style guide](http://two.avogadro.cc/contrib/style.html) which is enforced through
`clang-format` which runs as part of our continuous integration.

## A Quick Note About Plugins

For the most part, Avogadro plugins should be published to your own repository.

Examples:

* Input Generators: <https://github.com/OpenChemistry/avogenerators>
* Example Commands: <https://github.com/OpenChemistry/avogadro-commands>
* cclib Import: <https://github.com/OpenChemistry/avogadro-cclib>
* Nanocar Builder: <https://github.com/kbsezginel/nanocar-avogadro>
* ASE: <https://github.com/ghutchis/avogadro-build-ase>
* RDKit: <https://github.com/ghutchis/avogadro-rdkit>
* GenIce: <https://github.com/ghutchis/avogadro-genice>
* SciKitNano: <https://github.com/ghutchis/avogadro-scikit-nano>

  [Development]: http://two.avogadro.cc/contrib/code.html "Development guide"
  [Wiki]: http://wiki.openchemistry.org/ "Open Chemistry wiki"
  [Doxygen]: http://two.avogadro.cc/api/index.html "API documentation"
