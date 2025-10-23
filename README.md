# ![Avogadro 2][Avogadro2Logo] Avogadro 2

[![Latest Release](https://img.shields.io/github/v/release/openchemistry/avogadrolibs)](https://github.com/OpenChemistry/avogadrolibs/releases) [![BSD License](https://img.shields.io/github/license/openchemistry/avogadrolibs)](https://github.com/OpenChemistry/avogadrolibs/blob/master/LICENSE) [![Build Status](https://img.shields.io/github/actions/workflow/status/openchemistry/avogadrolibs/build_cmake.yml?branch=master)](https://github.com/OpenChemistry/avogadrolibs/actions) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/44bb12662c564ed8a27ee8a7fd89ed50)](https://app.codacy.com/gh/OpenChemistry/avogadrolibs/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Download Count](https://avogadro.cc/downloads.svg?readme)](https://github.com/OpenChemistry/avogadrolibs/releases) [![Citation Count](https://avogadro.cc/citations.svg?readme)](http://doi.org/10.1186/1758-2946-4-17)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat)](http://makeapullrequest.com) [![GitHub contributors](https://img.shields.io/github/contributors/openchemistry/avogadrolibs.svg?style=flat&color=0bf)](https://github.com/OpenChemistry/avogadrolibs/graphs/contributors)  [![OpenCollective Backers](https://img.shields.io/opencollective/all/open-chemistry)](https://opencollective.com/open-chemistry)

## Introduction

Avogadro is an advanced molecular editor designed for cross-platform use in
computational chemistry, molecular modeling, education, bioinformatics,
materials science, and related areas.
It offers flexible rendering and a powerful plugin architecture.

Core features and goals of the Avogadro project include:

* Open-source, distributed under the liberal 3-clause BSD license
* Cross-platform, with builds on Linux, Mac OS X and Windows
* An intuitive interface designed to be useful to the whole community
* Fast and efficient, embracing the latest technologies
* Extensible, making extensive use of a plugin architecture
* Flexible, supporting a range of chemical data formats and packages

Avogadro 2 began as a rewrite of the original [Avogadro 1.x][Avogadro1], which
is now unsupported.
The successor is faster, better, much more stable, and more featureful.
A final couple of features yet to be ported will be implemented by the time of
the 2.0 release, but in the meantime Avogadro 2 already has
[much new functionality of its own](https://two.avogadro.cc/docs/whats-new-in-avogadro-2/).

Avogadro's codebase is split across a
[libraries repository](https://github.com/openchemistry/avogadrolibs)
and an [application repository](https://github.com/openchemistry/avogadroapp).
The new code architecture provides a high-performance rendering engine, modern
code development, and significantly improved speed and stability.

Avogadro is being developed as part of the [Open Chemistry][OpenChemistry]
project by an open community, which was started at [Kitware][Kitware] as
an open-source community project.

## Installing

For the most up-to-date experience use the nightly builds prepared by GitHub
actions for:

* [Linux (AppImage)](https://nightly.link/OpenChemistry/avogadrolibs/workflows/build_linux/master/Avogadro2-x86_64.AppImage.zip)
* [macOS (Apple Silicon)](https://nightly.link/OpenChemistry/avogadrolibs/workflows/build_mac/master/macOS-arm64.zip)
* [macOS (Intel)](https://nightly.link/OpenChemistry/avogadrolibs/workflows/build_mac/master/macOS-intel.zip)
* [Windows](https://nightly.link/OpenChemistry/avogadrolibs/workflows/build_windows/master/Win64.exe.zip)

We also maintain a
[`beta` Flatpak](https://two.avogadro.cc/install/flatpak.html#install-flatpak-beta)
for Linux that is updated with the lastest changes every week or two.

For full releases and an overview of all available ways to obtain Avogadro see
the [overview](Install) on the Avogadro website.

Binaries and the source code for each release can be found on the
[GitHub releases page](https://github.com/OpenChemistry/avogadrolibs/releases).

If you would like to build from source we recommend that you follow our
[build guide][Build].

## User guide

Our [user documentation](https://two.avogadro.cc/docs/) can be found on the
Avogadro website, as well as a brief guide to
[getting started](https://two.avogadro.cc/docs/getting-started/).

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
  [OpenChemistry]: https://openchemistry.org/ "Open Chemistry Project"
  [OpenChemistryLogo]: https://raw.githubusercontent.com/OpenChemistry/avogadrolibs/master/docs/OpenChemistry128.png "Open Chemistry"
  [Kitware]: https://kitware.com/ "Kitware, Inc."
  [Avogadro1]: https://avogadro.cc/ "Avogadro 1"
  [Build]: https://two.avogadro.cc/develop/build/ "Building Avogadro"
  [Install]: https://two.avogadro.cc/install/ "Installing Avogadro"
  [Contribution]: https://two.avogadro.cc/contrib/ "Contribution guide"
  [API]: https://two.avogadro.cc/develop/classlist/ "API documentation"
