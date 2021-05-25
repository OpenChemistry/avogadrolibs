.. _Script Interfaces:

Script Interfaces
=================

Fixed String Lists (Pop-up menus)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Parameters that have a fixed number of mutually-exclusive string values
will be presented using a pop-up menu (combo box). Such a parameter can
be specified in the ``userOptions`` block as:

::

   {
     "userOptions": {
       "Parameter Name": {
         "type": "stringList",
         "values": ["Option 1", "Option 2", "Option 3"],
         "default": 0
       }
     }
   }

Here, "Parameter Name" is the default label that will be displayed in
the GUI as a label next to the combo box. If you wish to have the label
differ from the JSON key, you can add a "label" key pair:

::

   "userOptions": {
     "element": {
       "type": "stringList",
       "label": "Metal",
       "values": ["Gold", "Silver", "Platinum"],
       "default": 0
     }
   }

Use of the "label" is optional, but encouraged, since it greatly
facilitates translation and localization (e.g., "color" vs. "colour").

The array of strings in values will be used as the available entries in
the combo box in the order they are written. The default parameter is a
zero-based index  into the values array and indicates which value should
be initially selected.

Short Free-Form Text Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A short text string can be requested (e.g. for the "title" of an
optimization) via:

::

   {
     "userOptions": {
       "Parameter Name": {
         "type": "string",
         "default": "blah blah blah"
       }
     }
   }

This will add a blank text box to the GUI, initialized with the text
specified by default.

Existing files
~~~~~~~~~~~~~~

A script can ask for the absolute path to an existing file using the
following option block:

::

   {
     "userOptions": {
       "Parameter Name": {
         "type": "filePath",
         "default": "/path/to/some/file"
       }
     }
   }

This will add an option to select a file to the GUI, initialized to the
file pointed to by default.

Integer Values
~~~~~~~~~~~~~~

Scripts may request integer values from a specified range by adding a
user-option of the following form:

::

   {
     "userOptions": {
       "Parameter Name": {
         "type": "integer",
         "minimum": -5,
         "maximum": 5,
         "default": 0,
         "prefix": "some text ",
         "suffix": " units"
       }
     }
   }

This block will result in a QSpinBox, configured as follows:

-  minimum and maximum indicate the valid range of integers for the
   parameter.
-  default is the integer value that will be shown initially.
-  (optional) prefix and suffix are used to insert text before or after
   the integer value in the spin box. This is handy for specifying
   units. Note that any prefix or suffix will be stripped out of the
   corresponding entry in the call to scripts, and just the raw integer
   value will be sent.

Floating-point values
~~~~~~~~~~~~~~~~~~~~~

Scripts may request floating-point values from a specififed range by
adding:

::

  {
    "userOptions": {
      "Parameter Name": {
        "type": "integer",
        "minimum": -5,
        "maximum": 5,
        "default": 0,
        "prefix": "some text ",
        "suffix": " units"
            }
        }
    }

Boolean Parameters
~~~~~~~~~~~~~~~~~~

If a simple on/off value is needed, a boolean type option can be
requested:

::

   {
     "userOptions": {
       "Parameter Name": {
         "type": "boolean",
         "default": true,
       }
     }
   }

This will result in a check box in the dynamically generated GUI, with
the initial check state shown in default.
