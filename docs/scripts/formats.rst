.. _Script Formats:

Script File Formats
===================

Avogadro allows scripts to translate between formats which Avogadro already
handles and new formats (e.g., to use packages like cclib).

The script must handle the following command line arguments:

* ``--metadata`` Print metadata describing the format and the script's
  abilities and exit.
* ``--read`` Read data from standard input and produce a standard
  representation on standard output.
* ``--write`` Read a standard representation from standard input and write
  the formatted result to standard output.

Format scripts do not need to handle both ``--read`` and ``--write`` options.
For example a format could be intended to only read in a new format by converting
to `cjson`.

Identify the Format with ``--metadata``
----------------------------------------

Running the script with the ``--metadata`` option should print a JSON object
of the following form:

::

  {
    "inputFormat": "cml",
    "outputFormat": "cml",
    "operations": ["read", "write"],
    "identifier": "Unique Name",
    "name": "User-friendly Name",
    "description": "Description of format.",
    "specificationUrl": "http://url.specifying.format/if/any/exist",
    "fileExtensions": ["ext"],
    "mimeTypes": ["chemical/x-ext"]
    }

Details:

* `inputFormat` indicates the format that the script can convert to the
  implemented format by the ``--write`` command. Allowed values are `"cml"`,
  `"cjson"`, or `"xyz"`. See the ``--write`` documentation for more detail.
* `outputFormat` indicates the format that the script can convert to from the
  implemented format by the ``--read`` command. Allowed values are `"cml"`,
  `"cjson"`, or `"xyz"`. See the ``--read`` documentation for more detail.
* `operations` specifies the scripts capabilies. The array should contain
  `"read"` if the script implements the ``--read`` option, and/or `"write"` if
  ``--write`` is available.
* `identifier` is a unique identifier. The value must only be unique amongst
  script formats, as it will be prefixed with "User Script: " internally by
  Avogadro.
* `name` is a user-friendly name for the format.
* `description` is a description of the format, along with any relevant help
  text for users.
* `specificationUrl` is the URL of the format specification if available
  (or relevant web page/wiki otherwise).
* `fileExtensions` is an array specifying the file extensions that this
  format supports.
* `mimeTypes` is an array specifying the mime types that this format
  supports.

Required members are:
  - `operations`
  - `inputFormat` (if `"write"` is specified in `operations`)
  - `outputFormat` (if `"read"` is specified in `operations`)
  - `identifier`
  - `name`

Optional members are:
  - `description`
  - `specificationUrl`
  - `fileExtensions`
  - `mimeTypes`

Reading a format with ``--read``
--------------------------------

If `"read"` is specified in the `operations` ``--metadata`` output along with
a valid `outputFormat`, Avogadro will call the script with ``--read`` and
write the implemented format to the script's standard input. The script shall
convert the input to `outputFormat` and print it to standard output.

Writing a format with ``--write``
---------------------------------

If `"write"` is specified in the `operations` ``--metadata`` output along with
a valid ``inputFormat``, Avogadro will call the script with ``--write`` and
write the ``inputFormat`` to the script's standard input. The script shall
convert the input to the implemented format and print it to standard output.
