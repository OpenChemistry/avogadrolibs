# ![Avogadro 2][Avogadro2Logo] Avogadro 2

[![Latest Release](https://img.shields.io/github/v/release/openchemistry/avogadrolibs)](https://github.com/OpenChemistry/avogadrolibs/releases) [![BSD License](https://img.shields.io/github/license/openchemistry/avogadrolibs)](https://github.com/OpenChemistry/avogadrolibs/blob/master/LICENSE) [![Build Status](https://img.shields.io/github/workflow/status/openchemistry/avogadrolibs/CMake%20Build%20Matrix)](https://github.com/OpenChemistry/avogadrolibs/actions) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) [![GitHub contributors](https://img.shields.io/github/contributors/openchemistry/avogadrolibs.svg?style=flat)](https://github.com/OpenChemistry/avogadrolibs/graphs/contributors)  [![OpenCollective Backers](https://img.shields.io/opencollective/all/open-chemistry)](https://opencollective.com/open-chemistry)

## Introduction

Avogadro is an advanced molecular editor designed for cross-platform use in
computational chemistry, molecular modeling, bioinformatics, materials science,
and related areas. It offers flexible rendering and a powerful plugin
architecture.

Core features and goals of the Avogadro project include:

* Open source distributed under the liberal 3-clause BSD license
* Cross platform with builds on Linux, Mac OS X and Windows
* Intuitive interface designed to be useful to whole community
* Fast and efficient embracing the latest technologies
* Extensible, making extensive use of a plugin architecture
* Flexible supporting a range of chemical data formats and packages

The code in this repository is a rewrite of Avogadro with source
code split across a
[libraries repository](https://github.com/openchemistry/avogadrolibs)
and an [application repository](https://github.com/openchemistry/avogadroapp).
The new code architecture provides a high-performance rendering engine, modern
code development, and significantly improved speed and stability.

Avogadro 2 is being developed as part of the [Open Chemistry][OpenChemistry]
project by an open community, and was started at [Kitware][Kitware] as
an open source community project. The Avogadro 1.x series currently has more
features, and can be found [here][Avogadro1]. We are actively porting more
features to the Avogadro 2 code base, and making regular releases to get
feedback from the community.

We are actively working to finish Avogadro 2.0 in 2022.

## Installing

We provide nightly binaries built by GitHub actions for:

* [Linux AppImage](https://nightly.link/OpenChemistry/avogadrolibs/workflows/build_cmake/master/Avogadro2.AppImage.zip)
* [MacOS](https://nightly.link/OpenChemistry/avogadrolibs/workflows/build_cmake/master/macOS.dmg.zip)
* [Windows 64-bit](https://nightly.link/OpenChemistry/avogadrolibs/workflows/build_cmake/master/Win64.exe.zip)

If you would like to build from source we recommend that you
follow our [building Open Chemistry][Build] guide that will take care of
building most dependencies.

## Contributing

We welcome *all* kinds of contributions as a community project, from bug
reports, feature suggestions, language translations, Python plugins,
and C++ code development.

Our project uses the standard GitHub pull request process for code review
and integration. Please check our [contribution][Contribution] guide for more
details on developing and contributing to the project. The [GitHub issue
tracker](https://github.com/openchemistry/avogadrolibs/issues/)
can be used to report bugs, make feature requests, etc. Our API is
[documented online][API] with updated documentation generated nightly.

To introduce yourself, ask for help, or general discussion, we welcome everyone
to our [forum](https://discuss.avogadro.cc/)

Contributors Hall of Fame:
<a href="https://github.com/openchemistry/avogadrolibs/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=openchemistry/avogadrolibs" />
</a>

  [Avogadro2Logo]: https://raw.githubusercontent.com/OpenChemistry/avogadrolibs/master/docs/avogadro2_64.png "Avogadro2"
  [OpenChemistry]: http://openchemistry.org/ "Open Chemistry Project"
  [OpenChemistryLogo]: https://raw.githubusercontent.com/OpenChemistry/avogadrolibs/master/docs/OpenChemistry128.png "Open Chemistry"
  [Kitware]: http://kitware.com/ "Kitware, Inc."
  [Avogadro1]: http://avogadro.cc/ "Avogadro 1"
  [Build]: https://two.avogadro.cc/install/build.html "Building Avogadro"
  [Contribution]: https://two.avogadro.cc/contrib/ "Contribution guide"
  [API]: https://two.avogadro.cc/api/ "API documentation"
