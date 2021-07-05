.. _Input Generators:

Input Generators
================

Input generators offer several unique capabilities for formatting text
input for programs, including syntax highlighting rules and capabilities
for creating multiple files as part of one input (e.g., separate files
for geometry and keywords).

Avogadro will call input generator scripts using several command-line arguments
to generate JSON both for the user interface form and for the input to send
to the external programs.

Script Entry Points
-------------------

The script must handle the following command-line arguments:

- ``--debug`` Enable extra debugging output. Used with other commands.
  It is not required that the script support extra debugging, but it should
  not crash when this option is passed.
- ``--print-options`` Print the available options supported by the
  script, e.g. simulation parameters, etc. See below for more details.
- ``--generate-input`` Read an option block from stdin and print
  input files to stdout. See below for more details.
- ``--display-name`` Print a user-friendly name for the input generator.
  This is used in the GUI for menu entries, window titles, etc.

Specifying parameters with ``--print-options``
----------------------------------------------

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

The `userOptions` block contains a JSON object keyed with option names
(e.g. "First option name"), which are used in the GUI to label simulation
parameter settings. Various parameter types are supported.

Special Parameters
------------------

Some parameters are common to most calculation codes.
If the following parameter names are found, they will be handled specially
while creating the GUI (e.g., the charge and spin will be placed on one line)

It is recommended to use the names below for these options to provide a
consistent interface and ensure that MoleQueue job staging uses correct
values where appropriate.

====================   ===========  ====================================================================
 Option Name            Type         Description  
====================   ===========  ====================================================================
 "Title"                string      Input file title comment, MoleQueue job description.         
 "Filename Base"        string      Input file base name, e.g. "job" in "job.inp".                      
 "Processor Cores"      integer     Number of cores to use. Will be passed to MoleQueue.                
 "Calculation Type"     stringList  Type of calculation, e.g. "Single Point" or "Equilibrium Geometry".
 "Theory"               stringList  Levels of QM theory, e.g. "RHF", "B3LYP", "MP2", "CCSD", etc.
 "Basis"                stringList  Available basis sets, e.g. "STO-3G", "6-31G**", etc.              
 "Charge"               integer     Charge on the system.
 "Multiplicity"         integer     Spin multiplicity of the system. 
====================   ===========  ====================================================================

Syntax Highlighting
-------------------

Rules for syntax highlighting can be specified as a collection of
regular expressions or wildcard patterns and text format specifications
in the "highlightRules" array. The highlightRules format is:

::

   "highlightStyles": [
     {
       "style": "Style 1",
       "rules": [ (list of highlight rules, see below) ],
     },
     {
       "style": "Style 2",
       "rules": [ (list of highlight rules, see below) ],
     },
     ...
   ],

The style name is unique to the style object, and used to associate a
set of highlighting rules with particular output files. See the
--generate-input documentation for more details.

The general form of a highlight rule is:

::

   {
     "patterns": [
       { "regexp": "^Some regexp?$" },
       { "wildcard": "A * wildcard expression" },
       { "string": "An exact string to match.",
         "caseSensitive": false
       },
       ...
     ],
     "format": {
       "preset": "<preset name>"
     }
   }

or,

::

   {
     "patterns": [
       ...
     ],
     "format": {
       "foreground": [ 255, 128,  64 ],
       "background": [   0, 128, 128 ],
       "attributes": ["bold", "italic", "underline"],
       "family": "serif"
     }
   }

The patterns array contains a collection of fixed strings, wildcard
expressions, and regular expressions (using the QRegExp syntax flavor,
see the QRegExp documentation) that are used to identify strings that
should be formatted. There must be one of the following members present
in each pattern object:

-  regexp A QRegExp-style regular expression. If no capture groups
   ("(...)") are defined, the entire match is formatted. If one or more
   capture groups, only the captured texts will be marked.
-  wildcard A wildcard expression
-  string An exact string to match. Any pattern object may also set a
   boolean caseSensitive member to indicate whether the match should
   consider character case. If omitted, a case-sensitive match is
   assumed.

The preferred form of the format member is simply a specification of a
preset format. This allows for consistent color schemes across input
generators. The recognized presets are:

*  "title": A human readable title string.
*  "keyword": directives defined by the target input format
   specification to have special meaning, such as tags indicating where
   coordinates are to be found.
*  "property": A property of the simulation, such as level of theory,
   basis set, minimization method, etc.
*  "literal": A numeric literal (i.e. a raw number, such as a
   coordinate).
*  "comment": Sections of the input that are ignored by the simulation
   code.

If advanced formatting is desired, the second form of the format member
allows fine-tuning of the font properties:

*  foreground color as an RGB tuple, ranged 0-255
*  background color as an RGB tuple, ranged 0-255
*  attributes array of font attributes, valid strings are "bold", "italic", or "underline"
*  family of font. Valid values are "serif", "sans", or "mono" Any of the font property members may be omitted and default QTextCharFormat settings will be substituted.

The input generator extension will apply the entries in the highlightRules object to the text in the order they appear. Thus, later rules will override the formatting of earlier rules should a conflict arise.

::

  {
    "patterns": [
      ...
    ],
    "format": {
      "foreground": [ 255, 128,  64 ],
      "background": [   0, 128, 128 ],
      "attributes": ["bold", "italic", "underline"],
      "family": "serif"
    }
  }

The `patterns` array contains a collection of fixed strings, wildcard
expressions, and regular expressions (using the QRegExp syntax flavor, see
the QRegExp documentation) that are used to identify strings that should be
formatted.

There must be one of the following members present in each pattern object:

* `regexp` A QRegExp-style regular expression. If no capture groups ("(...)")
  are defined, the entire match is formatted. If one or more capture groups,
  only the captured texts will be marked.
* `wildcard` A wildcard expression
* `string` An exact string to match.

Any pattern object may also set a boolean `caseSensitive` member to indicate
whether the match should consider character case. If omitted, a
case-sensitive match is assumed.

The preferred form of the `format` member is simply a specification of a
preset format. This allows for consistent color schemes across input generators.
The recognized presets are:

* `"title"`: A human readable title string.
* `"keyword"`: directives defined by the target input format specification
  to have special meaning, such as tags indicating where coordinates are
  to be found.
* `"property"`: A property of the simulation, such as level of theory, basis
  set, minimization method, etc.
* `"literal"`: A numeric literal (i.e. a raw number, such as a coordinate).
* `"comment"`: Sections of the input that are ignored by the simulation code.

If advanced formatting is desired, the second form of the `format` member
allows fine-tuning of the font properties:

* `foreground` color as an RGB tuple, ranged 0-255
* `background` color as an RGB tuple, ranged 0-255
* `attributes` array of font attributes, valid strings are `"bold"`,
  `"italic"`, or `"underline"`
* `family` of font. Valid values are `"serif"`, `"sans"`, or `"mono"`

Any of the font property members may be omitted and default QTextCharFormat
settings will be substituted.

The input generator extension will apply the entries in the `highlightRules`
object to the text in the order they appear. Thus, later rules will
override the formatting of earlier rules should a conflict arise.

Requesting Full Structure of Current Molecule
---------------------------------------------

The `inputMoleculeFormat` is optional, and can be used to request a
representation of the current molecule's geometry when
`--generate-input` is called. The corresponding value
indicates the format of the molecule that the script expects. If this value
is omitted, no representation of the structure will be provided.

note Currently valid options for inputMoleculeFormat are "cjson" for
Chemical JSON or "cml" for Chemical Markup Language.

Handling User Selections: ``--generate-input``
-----------------------------------------------

When ``--generate-input`` is passed, the information needed to generate
the input file will be written to the script's standard input
channel as JSON string of the following form:

::

  {
    "cjson": {...},
    "options": {
     "First option name": "Value 2",
      "Second option name": "Value 1",
      ...
    }
  }

The ``cjson`` entry will contain a Chemical JSON representation
of the molecule if `inputMoleculeFormat` is set to "cjson" in the
``--print-options`` output.
Similarly, a ``cml`` entry and CML string will exist if a Chemical Markup
Language representation was requested.
It will be omitted entirely if `inputMoleculeFormat` is not set.

The ``options`` block contains key/value
pairs for each of the options specified in the `userOptions` block of the
``--print-options`` output.

If the script is called with ``--generate-input``, it must write a JSON
string to standard output with the following format:

::

  {
    "files": [
      {
        "filename": "file1.ext",
        "contents": "...",
        "highlightStyles": [ ... ]
      },
      {
        "filename": "file2.ext",
        "filePath": "/path/to/file/on/local/filesystem"
      },
      ...
    ],
    "warnings": ["First warning.", "Second warning.", ... ],
    "mainFile": "file2.ext"
  }

The `files` block is an array of objects, which define the actual input
files. The `filename` member provides the name of the file, and
either `contents` or `filePath` provide the text that goes into the file.
The `contents` string will be used as the file contents, and `filePath`
should contain an absolute path to a file on the filesystem to read and use
as the input file contents.

The optional `highlightStyles` member is an array of strings describing any
highlight styles to apply to the file (see ``--print-options`` documentation).
Each string in this array must match a `style` description in a highlighting
rule in the ``--print-options`` output.
Zero or more highlighting styles may be applied to any file.

The order of the files in the
GUI will match the order of the files in the array, and the first file will
be displayed first.

The `warnings` member provides an array of strings that describe non-fatal
warnings to be shown to the users. This is useful for describing
the resolution of conflicting options, e.g. "Ignoring basis set for
semi-empirical calculation.". This member is optional and should be omitted
if no warnings are present.

The `mainFile` member points to the primary input file for a calculation.
This is the file that will be used as a command line argument when executing
the simulation code (if applicable), and used by MoleQueue to set the
`$$inputFileName$$` and `$$inputFileBaseName$$` input template keywords.
This is optional; if present, the filename must exist in the `files` array.
If absent and only one file is specified in `files`, the single input file
will be used. Otherwise, the main file will be left unspecified.

Automatic Generation of Geometry
--------------------------------

The generation of molecular geometry descriptions may be skipped in the
script and deferred to the InputGenerator class by use of a special keyword.
The "contents" string may contain a keyword of the form

::

$$coords:[coordSpec]$$


where `[coordSpec]` is a sequence of characters.
The characters in `[coordSpec]` indicate the information needed about each
atom in the coordinate block.
 
Other keywords that can be used in the input files are:
- `$$atomCount$$`: Number of atoms in the molecule.
- `$$bondCount$$`: Number of bonds in the molecule.

Coordinate Blocks
~~~~~~~~~~~~~~~~~

The characters in the specification string indicate the information
needed about each atom in the coordinate block.

-  ``#``: Atom index (one-based index)
-  ``Z``: Atomic number (e.g. "6" for carbon)
-  ``G``: GAMESS-styled Atomic number (e.g. "6.0" for carbon)
-  ``S``: Element symbol (e.g. "C" for carbon)
-  ``N``: Element name (e.g. "Carbon")
-  ``x``: X cartesian coordinate
-  ``y``: Y cartesian coordinate
-  ``z``: Z cartesian coordinate
-  ``a``: 'a' lattice coordinate (unit cell required)
-  ``b``: 'b' lattice coordinate (unit cell required)
-  ``c``: 'c' lattice coordinate (unit cell required)
-  ``0``: A literal "0". Useful for optimization flags.
-  ``1``: A literal "1". Useful for optimization flags.
-  ``_``: A space character. Useful for alignment.

For example, the specification string

::

   __SZxyz110

will be replaced by a molecule-specific block of text similar to the
following:

::

     C  6    1.126214  0.765886  0.000000 1 1 0
     C  6    0.819345 -0.564955  0.000000 1 1 0
     C  6   -0.598383 -0.795127  0.000000 1 1 0
     C  6   -1.310706  0.370165  0.000000 1 1 0
     S  16  -0.285330  1.757144  0.000000 1 1 0
     H  1    2.130424  1.185837  0.000000 1 1 0
     H  1    1.548377 -1.375303  0.000000 1 1 0
     H  1   -1.033768 -1.794407  0.000000 1 1 0
     H  1   -2.396173  0.450760  0.000000 1 1 0

Error Handling
--------------

In general, these scripts should be written robustly so that they will not
fail under normal circumstances. However, if for some reason an error
occurs that must be reported to the user, simply write the error message to
standard output as plain text (i.e. not JSON), and it will be shown to the
user.

Debugging
---------

Debugging may be enabled by defining AVO_QM_INPUT_DEBUG in the process's
environment. This will cause the ``--debug`` option to be passed in
all calls to generator scripts, and will print extra information to the
qDebug() stream from within avogadro. The script is free to handle the
debug flag as the author wishes.
