Script Interfaces
=================

Fixed Mutually-Exclusive Parameter Lists
----------------------------------------

Parameters that have a fixed number of mutually-exclusive string values will
be presented using a QComboBox. Such a parameter can be specified in the
`userOptions` block as:
~~~{.js}
{
  "userOptions": {
    "Parameter Name": {
      "type": "stringList",
      "values": ["Option 1", "Option 2", "Option 3"],
      "default": 0
    }
  }
}
~~~
Here, `Parameter Name` is the label that will be displayed in the GUI as a
label next to the combo box.
The array of strings in `values` will be used as the available entries in
the combo box in the order they are written.
`default` is a zero-based index into the `values` array and indicates
which value should be initially selected by default.

Short Free-Form Text Parameters
-------------------------------

A short text string can be requested (e.g. for the "title" of an
optimization) via:
~~~{.js}
{
  "userOptions": {
    "Parameter Name": {
      "type": "string",
      "default": "blah blah blah"
    }
  }
}
~~~
This will add a QLineEdit to the GUI, initialized with the text specified by
`default`.

Existing files
--------------

An input generator can ask for the absolute path to an existing file using
the following option block:
~~~{.js}
{
  "userOptions": {
    "Parameter Name": {
      "type": "filePath",
      "default": "/path/to/some/file"
    }
  }
}
~~~
This will add an Avogadro::QtGui::FileBrowseWidget to the GUI, initialized to
the file pointed to by default.

Clamped Integer Values
----------------------

Scripts may request integer values from a specified range by adding a
user-option of the following form:
~~~{.js}
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
~~~
This block will result in a QSpinBox, configured as follows:
- `minimum` and `maximum` indicate the valid range of integers for the
  parameter.
- `default` is the integer value that will be shown initially.
- (optional) `prefix` and `suffix` are used to insert text before or
  after the integer value in the spin box.
  This is handy for specifying units.
  Note that any prefix or suffix will be stripped out of the corresponding
  entry in the call to `--generate-input`, and just the raw integer value
  will be sent.

Boolean Parameters
------------------

If a simple on/off value is needed, a boolean type option can be requested:
~~~{.js}
{
  "userOptions": {
    "Parameter Name": {
      "type": "boolean",
      "default": true,
    }
  }
}
~~~
This will result in a QCheckBox in the dynamically generated GUI, with
the inital check state shown in `default`.