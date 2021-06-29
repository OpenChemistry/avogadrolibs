:notoc:

.. _about:

Avogadro
========

Avogadro is an advanced molecule editor and visualizer designed for cross-platform use in computational chemistry, molecular modeling, bioinformatics, materials science, and related areas. It offers flexible high quality rendering and a powerful plugin architecture.

This documentation site is for Avogadro 2, currently in development.

- Free, Open Source: Easy to install and all source code and documentation is available to modify or extend.
- International: Translations into Chinese, French, German, Italian, Russian, Spanish, and others, with more languages to come.
- Intuitive: Built to work easily for students and advanced researchers both.
- Fast: Supports multi-threaded rendering and computation.
- Extensible: Plugin architecture for developers, including rendering, interactive tools, commands, and Python scripts.


Install
-----------------------------------------

.. panels::
  :container: container-fluid pb-3
  :column: col-lg-4 col-md-4 col-sm-12 col-xs-12 p-2
  :header: text-center

  :fa:`apple,fa-2x,style=fab` **MacOS**
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  .. link-button:: https://github.com/OpenChemistry/avogadrolibs/releases/download/1.94.0/Avogadro2-1.94.0-Darwin.dmg
      :text: Download DMG
      :classes: btn-outline-primary btn-block
  ++++++++++++++
  .. link-button:: https://nightly.link/OpenChemistry/avogadrolibs/workflows/build_cmake/master/macOS.dmg.zip
      :text: Download Nightly Build
      :classes: btn-outline-primary btn-block

  ---
  :fa:`windows,fa-2x,style=fab` **Windows**  
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  .. link-button:: https://github.com/OpenChemistry/avogadrolibs/releases/download/1.94.0/Avogadro2-1.94.0-win64.exe
      :text: Download Installer
      :classes: btn-outline-primary btn-block
  ++++++++++++++
  .. link-button:: https://nightly.link/OpenChemistry/avogadrolibs/workflows/build_cmake/master/Win64.exe.zip
      :text: Download Nightly Build
      :classes: btn-outline-primary btn-block
    
  ---
  :fa:`linux,fa-2x,style=fab` **Linux** 
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  .. link-button:: https://dl.flathub.org/repo/appstream/org.openchemistry.Avogadro2.flatpakref
      :text: Download Flatpak
      :classes: btn-outline-primary btn-block
  +++++++++++++++++++++++++++++++++++++++
  .. link-button:: build.html
        :text: Build from source
        :classes: btn-outline-primary btn-block
    
Graphics
-----------------------------------  
  
.. panels::
  :container: container-fluid pb-3  
  :column: col-lg-4 col-md-4 col-sm-12 col-xs-12 p-2
  :header: text-center

  .. image:: /_images/400px/benzene-mo.png
    :alt: Thumbnail for benzene molecular orbital
  ---
  .. image:: /_images/400px/zeolite.png
    :alt: Thumbnail for zeolite rendering
  ---
  .. image:: /_images/400px/phenol-qtaim.png
    :alt: Thumbnail for QTAim analysis
  ---
  .. image:: /_images/400px/bondcentric.png
    :alt: Thumbnail for bond-centric editing
  ---
  .. image:: /_images/400px/C180.png
    :alt: Thumbnail for symmetry analysis of C180
  ---
  .. image:: /_images/400px/covid-spike.png
    :alt: Thumbnail for COVID spike protein

Resources
---------

.. panels::
  :container: container-fluid pb-3
  :column: col-lg-4 col-md-4 col-sm-12 col-xs-12 p-2
  :header: text-center
  
  :fa:`book,fa-2x,style=fas` **User Guide**
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  Coming Soon for Avogadro2:

  * Getting Started
  * Tutorials
  * Manual

  ---
  :fa:`laptop-code,fa-2x,style=fas` **API Documentation**
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  Develop scripts and C++ code with Avogadro:

  * :ref:`Script Plugins<Scripts>`
  * Jupyter Notebooks
  * :ref:`C++ API<API>`

  ---
  :fa:`users,fa-2x,style=fas` **Contribute**
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  We want your help to make Avogadro better for everyone:

  * Roadmap
  * :ref:`Translation / Localization<Translate>`
  * Bugs / Issues
  * Feature Requests


Connecting with the Avogadro community
--------------------------------------

There are various ways to get in touch with the Avogadro community:

* `Avogadro Discussion`_ is the best place to ask usage questions and is a
  great way to get feedback from other users on how to approach a problem.
* If you think you've found a bug, or would like to request a feature, please
  report an issue at the `AvogadroLibs GitHub repository`_.

You can also find more information about Avogadro on `Twitter`_.



.. toctree::
    :maxdepth: 2
    :hidden:

    install/index
    scripts/index
    api/index
    contrib/index

.. _Avogadro Discussion: https://discuss.avogadro.cc/
.. _`AvogadroLibs GitHub repository`: https://github.com/openchemistry/avogadrolibs
.. _Twitter: https://twitter.com/AvogadroChem
.. _Issues: https://github.com/OpenChemistry/avogadrolibs/issues
.. _Features: https://github.com/OpenChemistry/avogadrolibs/issues
