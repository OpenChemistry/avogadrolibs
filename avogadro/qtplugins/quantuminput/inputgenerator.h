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
class QTextStream;

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {

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
 * The script must handle the following command-line arguments:
 * - <tt>--debug</tt> Enable extra debugging output. Used with other commands.
 *   It is not required that the script support extra debugging, but it should
 *   not crash when this option is passed.
 * - <tt>--print-options</tt> Print the available options supported by the
 *   script, e.g. simulation parameters, etc. See below for more details.
 * - <tt>--generate-input</tt> Read an option block from stdin and print
 *   input files to stdout. See below for more details.
 * - <tt>--display-name</tt> Print a user-friendly name for the input generator.
 *   This is used in the GUI for menu entries, window titles, etc.
 *
 * The format of the <tt>--print-options</tt> output must be a JSON object of
 * the following form:
\code {.js}
{
  "userOptions": {
    "First option name": {
      "values": [
        "Value 1",
        "Value 2",
        "Value 3",
        ...
      ],
      "default": 0
    },
    "Second option name": {
      "values": [
        "Value 1",
        "Value 2",
        "Value 3",
        ...
      ],
      "default": 2,
    },
    ...
  },
  "inputMoleculeFormat": "cjson"
}
\endcode
 * The "userOptions" block contains a JSON object keyed with option names
 * (e.g. "First option name"), which are used in the GUI to label simulation
 * parameter settings. The "values" member of the option object provides an
 * array of strings containing the possible values of the parameter. "default"
 * indicates which value is the default by providing a zero-based index into the
 * "values" array.
 *
 * @note Currently, only parameters that have a discrete set of values can be
 * used, and the values will be placed in a combo box in the GUI. This will
 * eventually be expanded to provide ways of requesting other types of
 * parameters, such as integers, floating point numbers, booleans, etc.
 *
 * @todo Document expected option names/value that are handled specially.
 *
 * The "inputMoleculeFormat" is optional, and can be used to request a
 * representation of the current molecule's geometry when
 * <tt>--generate-input</tt> is called. The corresponding value
 * indicates the format of the molecule that the script expects. If this value
 * is omitted, no representation of the structure will be provided.
 *
 * @note Currently valid options for inputMoleculeFormat are "cjson" for
 * Chemical JSON or "cml" for Chemical Markup Language.
 *
 * When <tt>--generate-input</tt> is used, the information needed to generate
 * the input file will be passed to the script's standard input
 * channel as JSON string of the following form:
\code {.js}
{
  "cjson": "[...]",
  "options": {
    "First option name": "Value 2",
    "Second option name": "Value 1",
    ...
  }
}
\endcode
 * The "cjson" entry will contain a string with a Chemical JSON representation
 * of the molecule if "inputMoleculeFormat" is set to "cjson" in the
 * <tt>--print-options</tt> output.
 * Similarly, it will be "cml" if a Chemical Markup Language representation was
 * requested.
 * It will be omitted entirely if "inputMoleculeFormat" is not set.
 * The "options" block contains key/value
 * pairs for each of the options specified in the "userOptions" block of the
 * <tt>--print-options</tt> output.
 *
 * If the script is called with <tt>--generate-input</tt>, it must write a JSON
 * string to standard output of the following format:
\code {.js}
{
  "files": [
    {
      "filename": "file1.ext",
      "contents": "..."
    },
    {
      "filename": "file2.ext",
      "contents": "..."
    },
    ...
  ]
}
\endcode
 * The "files" block is an array of objects, which define the actual input
 * files. The "filename" member provides the name of the file, and "contents"
 * provides the text that goes into the file. The order of the files in the
 * GUI will match the order of the files in the array, and the first file will
 * be displayed first.
 *
 * The generation of molecular geometry descriptions may be skipped in the
 * script and deferred to the InputGenerator class by use of a special keyword.
 * The "contents" string may contain a keyword of the form
 * \verbatim $$coords:[coordSpec]$$ \endverbatim where <tt>[coordSpec]</tt>
 * is a sequence
 * of characters. The characters in <tt>[coordSpec]</tt> indicate the
 * information needed about each atom in the coordinate block:
 * - \c Z: Atomic number
 * - \c S: Element symbol
 * - \c N: Element name
 * - \c x: X cartesian coordinate in Angstrom
 * - \c y: Y cartesian coordinate in Angstrom
 * - \c z: Z cartesian coordinate in Angstrom
 *
 * For example, the string \verbatim $$coords:SZxyz$$ \endverbatim will be
 * replaced by a molecule-specific block of text similar to the following:
\verbatim
C     6        1.126214              0.765886              0.000000
C     6        0.819345             -0.564955              0.000000
C     6       -0.598383             -0.795127              0.000000
C     6       -1.310706              0.370165              0.000000
S     16      -0.285330              1.757144              0.000000
H     1        2.130424              1.185837              0.000000
H     1        1.548377             -1.375303              0.000000
H     1       -1.033768             -1.794407              0.000000
H     1       -2.396173              0.450760              0.000000
\endverbatim
 *
 * In general, these scripts should be written robustly so that they will not
 * fail under normal circumstances. However, if for some reason an error
 * occurs that must be reported to the user, simply write the error message to
 * standard output as plain text (i.e. not JSON), and it will be shown to the
 * user.
 *
 * Debugging may be enabled by defining AVO_QM_INPUT_DEBUG in the process's
 * environment. This will cause the <tt>--debug</tt> option to be passed in
 * all calls to generator scripts, and will print extra information to the
 * qDebug() stream from within avogadro.
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
   */
  int numberOfInputFiles() const;

  /**
   * @return A list of filenames created by generateInput().
   */
  QStringList fileNames() const;

  /**
   * @return A file contents corresponding to @p fileName. Must call
   * generateInput() first.
   * @sa fileNames
   */
  QString fileContents(const QString &fileName) const;

  /**
   * @return True if an error is set.
   */
  bool hasErrors() const { return !m_errors.isEmpty(); }

  /**
   * Reset the error counter.
   */
  void clearErrors() { m_errors.clear(); }

  /**
   * @return A QStringList containing all errors.
   */
  QStringList errorList() const { return m_errors; }

  /**
   * @return A double-spaced list of all errors that occurred.
   */
  QString errorString() const { return m_errors.join("\n\n"); }

public slots:
  /**
   * Enable/disable debugging.
   */
  void setDebug(bool d) { m_debug = d; }

private:
  /// Molecular representation formats that generator scripts can request.
  /// @todo xyz
  enum InputMoleculeFormat {
    Unknown = -1,
    NoInputFormat = 0,
    CJSON,
    CML
  };

  QByteArray execute(const QStringList &args,
                     const QByteArray &stdin = QByteArray()) const;
  bool parseJson(const QByteArray &json, QJsonDocument &doc) const;
  QString processErrorString(const QProcess &proc) const;
  bool insertMolecule(QJsonObject &json, const Core::Molecule &mol) const;
  QString generateCoordinateBlock(const QString &spec,
                                  const Core::Molecule &mol) const;
  void replaceKeywords(QString &str, const Core::Molecule &mol) const;

  bool m_debug;
  mutable InputMoleculeFormat m_inputMoleculeFormat;
  mutable QString m_scriptFilePath;
  mutable QString m_displayName;
  mutable QJsonObject m_options;
  mutable QStringList m_errors;

  QStringList m_filenames;
  QMap<QString, QString> m_files;

};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_INPUTGENERATOR_H
