/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_INPUTGENERATOR_H
#define AVOGADRO_QTPLUGINS_INPUTGENERATOR_H

#include <qjsonobject.h>

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QStringList>

class QJsonDocument;
class QProcess;
class QRegExp;
class QTextCharFormat;
class QTextStream;

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {
class GenericHighlighter;

/**
 * @brief The InputGenerator class provides an interface to input generator
 * scripts.
 * @author David C. Lonie
 *
 * The QuantumInput extension provides a scriptable method for users to add
 * custom input generators to Avogadro. By writing an executable that implements
 * the interface defined below, new input generators can be created faster and
 * easier than writing full Avogadro extensions.
 *
 * Script Entry Points
 * ===================
 *
 * The script must handle the following command-line arguments:
 * - `--debug` Enable extra debugging output. Used with other commands.
 *   It is not required that the script support extra debugging, but it should
 *   not crash when this option is passed.
 * - `--print-options` Print the available options supported by the
 *   script, e.g. simulation parameters, etc. See below for more details.
 * - `--generate-input` Read an option block from stdin and print
 *   input files to stdout. See below for more details.
 * - `--display-name` Print a user-friendly name for the input generator.
 *   This is used in the GUI for menu entries, window titles, etc.
 *
 * Specifying parameters with `--print-options`
 * ============================================
 *
 * The format of the `--print-options` output must be a JSON object of
 * the following form:
~~~{.js}
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
  "inputMoleculeFormat": "cjson",
  "allowCustomBaseName" : true
}
~~~
 * The `userOptions` block contains a JSON object keyed with option names
 * (e.g. "First option name"), which are used in the GUI to label simulation
 * parameter settings. Various parameter types are supported:
 *
 * Fixed Mutually-Exclusive Parameter Lists
 * ----------------------------------------
 *
 * Parameters that have a fixed number of mutually-exclusive string values will
 * be presented using a QComboBox. Such a parameter can be specified in the
 * `userOptions` block as:
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
 * Here, `Parameter Name` is the label that will be displayed in the GUI as a
 * label next to the combo box.
 * The array of strings in `values` will be used as the available entries in
 * the combo box in the order they are written.
 * `default` is a zero-based index into the `values` array and indicates
 * which value should be initially selected by default.
 *
 * Short Free-Form Text Parameters
 * -------------------------------
 *
 * A short text string can be requested (e.g. for the "title" of an
 * optimization) via:
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
 * This will add a QLineEdit to the GUI, initialized with the text specified by
 * `default`.
 *
 * Clamped Integer Values
 * ----------------------
 *
 * Scripts may request integer values from a specified range by adding a
 * user-option of the following form:
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
 * This block will result in a QSpinBox, configured as follows:
 * - `minimum` and `maximum` indicate the valid range of integers for the
 *   parameter.
 * - `default` is the integer value that will be shown initially.
 * - (optional) `prefix` and `suffix` are used to insert text before or
 *   after the integer value in the spin box.
 *   This is handy for specifying units.
 *   Note that any prefix or suffix will be stripped out of the corresponding
 *   entry in the call to `--generate-input`, and just the raw integer value
 *   will be sent.
 *
 * Boolean Parameters
 * ------------------
 *
 * If a simple on/off value is needed, a boolean type option can be requested:
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
 * This will result in a QCheckBox in the dynamically generated GUI, with
 * the inital check state shown in `default`.
 *
 * Special Parameters
 * ------------------
 *
 * Some parameters are common to most calculation codes.
 * If the following parameter names are found, they will be handled specially
 * while creating the GUI.
 *
 * @todo Document expected option names/value that are handled specially.
 *
 * Syntax Highlighting
 * -------------------
 *
 * Rules for syntax highlighting can be specified as a collection of regular
 * expressions or wildcard patterns and text format specifications in the
 * "highlightRules" array. The `highlightRules` format is:
~~~{.js}
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
~~~
 * The `style` name is unique to the style object, and used to associate a
 * set of highlighting rules with particular output files. See the
 * `--generate-input` documentation for more details.
 *
 * The general form of a highlight rule is:
~~~{.js}
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
    "foreground": [ 255, 128,  64 ],
    "background": [   0, 128, 128 ],
    "attributes": ["bold", "italic", "underline"],
    "family": "serif"
  }
}
~~~
 *
 * The `patterns` array contains a collection of fixed strings, wildcard
 * expressions, and regular expressions (using the QRegExp syntax flavor, see
 * the QRegExp documentation) that are used to identify strings that should be
 * formatted.
 * There must be one of the following members present in each pattern object:
 * - `regexp` A QRegExp-style regular expression
 * - `wildcard` A wildcard expression
 * - `string` An exact string to match.
 *
 * Any pattern object may also set a boolean `caseSensitive` member to indicate
 * whether the match should consider character case. If omitted, a
 * case-sensitive match is assumed.
 *
 * The `format` member specifies
 * the font properties to apply:
 * - `foreground` color as an RGB tuple, ranged 0-255
 * - `background` color as an RGB tuple, ranged 0-255
 * - `attributes` array of font attributes, valid strings are `"bold"`,
 *   `"italic"`, or `"underline"`
 * - `family` of font. Valid values are `"serif"`, `"sans"`, or `"mono"`
 *
 * Any of the font property members may be omitted and default QTextCharFormat
 * settings will be substituted.
 *
 * The input generator extension will apply the entries in the `highlightRules`
 * object to the text in the order they appear. Thus, later rules will
 * override the formatting of earlier rules should a conflict arise.
 *
 * Requesting Full Structure of Current Molecule
 * ---------------------------------------------
 *
 * The `inputMoleculeFormat` is optional, and can be used to request a
 * representation of the current molecule's geometry when
 * `--generate-input` is called. The corresponding value
 * indicates the format of the molecule that the script expects. If this value
 * is omitted, no representation of the structure will be provided.
 *
 * @note Currently valid options for inputMoleculeFormat are "cjson" for
 * Chemical JSON or "cml" for Chemical Markup Language.
 *
 * Specifying Filenames
 * --------------------
 *
 * The `allowCustomBaseName` option toggles whether the user may specify a
 * custom base name for input files. If the simulation code expects specific
 * filenames, set this to false and hardcode the filenames the code expects.
 * If the simulation allows input files to have custom names, set this to true
 * and use the base name provided to generate the input filenames (See the
 * `--generate-input` `baseName` documentation below). If this option is not
 * specified, it is assumed to be false.
 *
 * Handling User Selections: `--generate-input`
 * ============================================
 *
 * When `--generate-input` is passed, the information needed to generate
 * the input file will be written to the script's standard input
 * channel as JSON string of the following form:
~~~{.js}
{
  "cjson": {...},
  "options": {
    "First option name": "Value 2",
    "Second option name": "Value 1",
    ...
  },
  "settings": {
    "baseName": "job",
    "numberOfCores": 4
  }
}
~~~
 * The `cjson` entry will contain a Chemical JSON representation
 * of the molecule if `inputMoleculeFormat` is set to "cjson" in the
 * `--print-options` output.
 * Similarly, a `cml` entry and CML string will exist if a Chemical Markup
 * Language representation was requested.
 * It will be omitted entirely if `inputMoleculeFormat` is not set.
 * The `options` block contains key/value
 * pairs for each of the options specified in the `userOptions` block of the
 * `--print-options` output.
 * The `settings` block contains a fixed set of parameters that are always
 * available provided:
 * - `baseName`: The basename for input files (See the `allowCustomBaseName`
 *   documentation above). This defaults to "job" if `allowCustomBaseName` is
 *   `false`.
 * - `numberOfCores`: The number of processor cores requested.
 *
 * If the script is called with `--generate-input`, it must write a JSON
 * string to standard output with the following format:
~~~{.js}
{
  "files": [
    {
      "filename": "file1.ext",
      "contents": "...",
      "highlightStyles": [ ... ]
    },
    {
      "filename": "file2.ext",
      "contents": "..."
    },
    ...
  ],
  "warnings": ["First warning.", "Second warning.", ... ],
  "mainFile": "file2.ext"
}
~~~
 * The `files` block is an array of objects, which define the actual input
 * files. The `filename` member provides the name of the file, and
 * `contents` provides the text that goes into the file.
 * The optional `highlightStyles` member is an array of strings describing any
 * highlight styles to apply to the file (see `--print-options` documentation).
 * Each string in this array must match a `style` description in a highlighting
 * rule in the `--print-options` output.
 * Zero or more highlighting styles may be applied to any file.
 * The order of the files in the
 * GUI will match the order of the files in the array, and the first file will
 * be displayed first.
 *
 * The `warnings` member provides an array of strings that describe non-fatal
 * warnings to be shown to the users. This is useful for describing
 * the resolution of conflicting options, e.g. "Ignoring basis set for
 * semi-empirical calculation.". This member is optional and should be omitted
 * if no warnings are present.
 *
 * The `mainFile` member points to the primary input file for a calculation.
 * This is the file that will be used as a command line argument when executing
 * the simulation code (if applicable), and used by MoleQueue to set the
 * `$$inputFileName$$` and `$$inputFileBaseName$$` input template keywords.
 * This is optional; if present, the filename must exist in the `files` array.
 * If absent and only one file is specified in `files`, the single input file
 * will be used. Otherwise, the main file will be left unspecified.
 *
 * Automatic Generation of Geometry
 * ================================
 *
 * The generation of molecular geometry descriptions may be skipped in the
 * script and deferred to the InputGenerator class by use of a special keyword.
 * The "contents" string may contain a keyword of the form
~~~
$$coords:[coordSpec]$$
~~~
 * where `[coordSpec]` is a sequence
 * of characters. The characters in `[coordSpec]` indicate the
 * information needed about each atom in the coordinate block:
 * - @c Z: Atomic number
 * - @c S: Element symbol
 * - @c N: Element name
 * - @c x: X cartesian coordinate in Angstrom
 * - @c y: Y cartesian coordinate in Angstrom
 * - @c z: Z cartesian coordinate in Angstrom
 * - @c 0: A literal "0". Useful for optimization flags.
 * - @c 1: A literal "1". Useful for optimization flags.
 * - @c _: A space character. Useful for alignment.
 *
 * For example, the string
~~~
$$coords:__SZxyz110$$
~~~
 * will be
 * replaced by a molecule-specific block of text similar to the following:
~~~
  C  6    1.126214  0.765886  0.000000 1 1 0
  C  6    0.819345 -0.564955  0.000000 1 1 0
  C  6   -0.598383 -0.795127  0.000000 1 1 0
  C  6   -1.310706  0.370165  0.000000 1 1 0
  S  16  -0.285330  1.757144  0.000000 1 1 0
  H  1    2.130424  1.185837  0.000000 1 1 0
  H  1    1.548377 -1.375303  0.000000 1 1 0
  H  1   -1.033768 -1.794407  0.000000 1 1 0
  H  1   -2.396173  0.450760  0.000000 1 1 0
~~~
 *
 * Other keywords that can be used in the input files are:
 * - `$$atomCount$$`: Number of atoms in the molecule.
 * - `$$bondCount$$`: Number of bonds in the molecule.
 *
 * Error Handling
 * ==============
 *
 * In general, these scripts should be written robustly so that they will not
 * fail under normal circumstances. However, if for some reason an error
 * occurs that must be reported to the user, simply write the error message to
 * standard output as plain text (i.e. not JSON), and it will be shown to the
 * user.
 *
 * Debugging
 * =========
 *
 * Debugging may be enabled by defining AVO_QM_INPUT_DEBUG in the process's
 * environment. This will cause the <tt>--debug</tt> option to be passed in
 * all calls to generator scripts, and will print extra information to the
 * qDebug() stream from within avogadro. The script is free to handle the
 * debug flag as the author wishes.
 */
class InputGenerator : public QObject
{
  Q_OBJECT
public:
  /**
   * Constructor
   * @param scriptFilePath_ Absolute path to generator script.
   */
  explicit InputGenerator(const QString &scriptFilePath_);
  ~InputGenerator();

  /**
   * @return True if debugging is enabled.
   */
  bool debug() const { return m_debug; }

  /**
   * Query the script for the available options (<tt>--generate-options</tt>)
   * and return the output as a JSON object.
   * @note The results will be cached the first time this function is called
   * and reused in subsequent calls.
   * @note If an error occurs, the error string will be set. Call hasErrors()
   * to check for success, and errorString() or errorList() to get a
   * user-friendly description of the error.
   */
  QJsonObject options() const;

  /**
   * Query the script for a user-friendly name (<tt>--display-name</tt>).
   * @note The results will be cached the first time this function is called
   * and reused in subsequent calls.
   * @note If an error occurs, the error string will be set. Call hasErrors()
   * to check for success, and errorString() or errorList() to get a
   * user-friendly description of the error.
   */
  QString displayName() const;

  /**
   * @return The path to the generator file.
   */
  QString scriptFilePath() const { return m_scriptFilePath; }

  /**
   * Request input files from the script using the supplied options object and
   * molecule. See the class documentation for details on the @p options_
   * object format.
   *
   * If the files are generated successfully, use the functions
   * numberOfInputFiles(), fileNames(), and fileContents() to retrieve them.
   *
   * @return true on success and false on failure.
   * @note If an error occurs, the error string will be set. Call hasErrors()
   * to check for success, and errorString() or errorList() to get a
   * user-friendly description of the error.
   */
  bool generateInput(const QJsonObject &options_, const Core::Molecule &mol);

  /**
   * @return The number of input files stored by generateInput().
   * @note This function is only valid after a successful call to
   * generateInput().
   */
  int numberOfInputFiles() const;

  /**
   * @return A list of filenames created by generateInput().
   * @note This function is only valid after a successful call to
   * generateInput().
   */
  QStringList fileNames() const;

  /**
   * @return The "main" input file of the collection. This is the input file
   * used by MoleQueue to determine the $$inputFileName$$ and
   * $$inputFileBaseName$$ keywords.
   * @note This function is only valid after a successful call to
   * generateInput().
   */
  QString mainFileName() const;

  /**
   * @return A file contents corresponding to @p fileName. Must call
   * generateInput() first.
   * @sa fileNames
   */
  QString fileContents(const QString &fileName) const;

  /**
   * @return A syntax highlighter for the file @a fileName. Must call
   * generateInput() first. The caller takes ownership of the returned object.
   * @sa fileNames
   */
  GenericHighlighter *fileHighlighter(const QString &fileName) const;

  /**
   * @return True if an error is set.
   */
  bool hasErrors() const { return !m_errors.isEmpty(); }

  /**
   * Reset the error counter.
   */
  void clearErrors() { m_errors.clear(); }

  /**
   * @return A QStringList containing all errors that occurred in the last call
   * to the input generator script.
   */
  QStringList errorList() const { return m_errors; }

  /**
   * @return A QStringList containing all warnings returned by the input
   * generator script in the last call to generateInput. These are
   * script-specific warnings.
   */
  QStringList warningList() const { return m_warnings; }

public slots:
  /**
   * Enable/disable debugging.
   */
  void setDebug(bool d) { m_debug = d; }

private:

  QByteArray execute(const QStringList &args,
                     const QByteArray &scriptStdin = QByteArray()) const;
  bool parseJson(const QByteArray &json, QJsonDocument &doc) const;
  QString processErrorString(const QProcess &proc) const;
  bool insertMolecule(QJsonObject &json, const Core::Molecule &mol) const;
  QString generateCoordinateBlock(const QString &spec,
                                  const Core::Molecule &mol) const;
  void replaceKeywords(QString &str, const Core::Molecule &mol) const;
  bool parseHighlightStyles(const QJsonArray &json) const;
  bool parseRules(const QJsonArray &json, GenericHighlighter &highligher) const;
  bool parseFormat(const QJsonObject &json, QTextCharFormat &format) const;
  bool parsePattern(const QJsonValue &json, QRegExp &pattern) const;

  bool m_debug;
  // File extension of requested molecule format
  mutable QString m_moleculeExtension;
  mutable QString m_scriptFilePath;
  mutable QString m_displayName;
  mutable QJsonObject m_options;
  mutable QStringList m_warnings;
  mutable QStringList m_errors;

  QStringList m_filenames;
  QString m_mainFileName;
  QMap<QString, QString> m_files;
  QMap<QString, GenericHighlighter*> m_fileHighlighters;

  mutable QMap<QString, GenericHighlighter*> m_highlightStyles;

  QString m_pythonInterpreter;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_INPUTGENERATOR_H
