.. _generators--command-scripts:

Command Scripts
============================

Command scripts work similarly to generators - passing JSON to
Avogadro to render a form interface and then perform work. In principal,
the scripts can be written in any programming language, although most
are currently written in Python.

This guide will cover the UI aspects of scripts, with separate
discussion of generators and command operation elsewhere.

Script Entry Points
-------------------

The script *must* handle the following command-line arguments:

-  ``--debug`` Enable extra debugging output. Used with other commands.
   It is not required that the script support extra debugging, but it
   should not crash when this option is passed.
-  ``--lang XX`` Display the user interface with a specific language or
   localization. It is not required that scripts support localization,
   but it should not crash when this option is passed.
-  ``--print-options`` Print the available UI options supported by the
   script, e.g. simulation parameters, etc. See below for more details.
-  ``--display-name`` Print a user-friendly name for the script. This is
   used in the GUI for menu entries, window titles, etc.
-  ``--menu-path`` Print the expected menu path for the script,
   separated by "|" characters (e.g., "Extensions|Quantum" or
   "Build|Insert"). The final part of the menu path will include the
   display-name.

Specifying UI options with --print-options
------------------------------------------

The format of the ``--print-options`` output must be a JSON object of
the following form:

::

   {
     "userOptions": {
       ...
     },
     "highlightStyles": [
       {
         "style": "Descriptive name",
         "rules": [
           {
             "patterns": [ ... ],
             "format": { ... }
           },
           ...
         ],
       },
       ...
     ],
     "inputMoleculeFormat": "cjson"
   }

The ``userOptions`` block contains a JSON object keyed with option names
(e.g. "First option name"), which are used in the GUI to label
simulation parameter settings. Various parameter types are supported.
