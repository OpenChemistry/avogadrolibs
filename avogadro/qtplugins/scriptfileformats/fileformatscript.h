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

#ifndef AVOGADRO_QTPLUGINS_FILEFORMATSCRIPT_H
#define AVOGADRO_QTPLUGINS_FILEFORMATSCRIPT_H

#include <avogadro/io/fileformat.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QString>

class QJsonObject;

namespace Avogadro {
namespace QtGui {
class PythonScript;
}

namespace QtPlugins {

/**
 * @brief The FileFormatScript class interfaces with external scripts that
 * implement chemical file reader/writers.
 *
 * Script Entry Points
 * ===================
 *
 * The script must handle the following command line arguments:
 * - `--metadata` Print metadata describing the format and the script's
 *   abilities and exit.
 * - `--read` Read data from standard input and produce a standard
 *   representation on standard output.
 * - `--write` Read a standard representation from standard input and write
 *   the formatted result to standard output.
 *
 * Identify the Format with `--metadata`
 * =====================================
 *
 * Running the script with the `--metadata` option should print a JSON object
 * of the following form:
~~~{.js}
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
~~~
 *
 * Details:
 * - `inputFormat` indicates the format that the script can convert to the
 *   implemented format by the `--write` command. Allowed values are `"cml"`,
 *   `"cjson"`, or `"xyz"`. See the `--write` documentation for more detail.
 * - `outputFormat` indicates the format that the script can convert to from the
 *   implemented format by the `--read` command. Allowed values are `"cml"`,
 *   `"cjson"`, or `"xyz"`. See the `--read` documentation for more detail.
 * - `operations` specifies the scripts capabilies. The array should contain
 *   `"read"` if the script implements the `--read` option, and/or `"write"` if
 *   `--write` is available.
 * - `identifier` is a unique identifier. The value must only be unique amongst
 *   script formats, as it will be prefixed with "User Script: " internally by
 *   Avogadro.
 * - `name` is a user-friendly name for the format.
 * - `description` is a description of the format, along with any relevant help
 *   text for users.
 * - `specificationUrl` is the URL of the format specification if available
 *   (or relevant web page/wiki otherwise).
 * - `fileExtensions` is an array specifying the file extensions that this
 *   format supports.
 * - `mimeTypes` is an array specifying the mime types that this format
 *   supports.
 *
 * Required members are
 * - `operations`
 * - `inputFormat` (if `"write"` is specified in `operations`)
 * - `outputFormat` (if `"read"` is specified in `operations`)
 * - `identifier`
 * - `name`
 *
 * Optional members are
 * - `description`
 * - `specificationUrl`
 * - `fileExtensions`
 * - `mimeTypes`
 *
 * Reading a format with `--read`
 * ==============================
 *
 * If `"read"` is specified in the `operations` `--metadata` output along with
 * a valid `outputFormat`, Avogadro will call the script with `--read` and
 * write the implemented format to the script's standard input. The script shall
 * convert the input to `outputFormat` and print it to standard output.
 *
 * Writing a format with `--write`
 * ===============================
 *
 * If `"write"` is specified in the `operations` `--metadata` output along with
 * a valid `inputFormat`, Avogadro will call the script with `--write` and
 * write the `inputFormat` to the script's standard input. The script shall
 * convert the input to the implemented format and print it to standard output.
 */
class FileFormatScript : public Avogadro::Io::FileFormat
{
public:
  /** Formats that may be written to the script's input/output formats. */
  enum Format {NotUsed, Cjson, Cml, Xyz};

  FileFormatScript(const QString &scriptFileName);
  ~FileFormatScript() AVO_OVERRIDE;

  QString scriptFilePath() const;

  Format inputFormat() const { return m_inputFormat; }

  Format outputFormat() const { return m_outputFormat; }

  bool isValid() const { return m_valid; }

  FileFormat *newInstance() const AVO_OVERRIDE;

  bool read(std::istream &in, Core::Molecule &molecule) AVO_OVERRIDE;

  bool write(std::ostream &out, const Core::Molecule &molecule) AVO_OVERRIDE;

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return m_operations;
  }

  std::string identifier() const AVO_OVERRIDE
  {
    return m_identifier;
  }

  std::string name() const AVO_OVERRIDE
  {
    return m_name;
  }

  std::string description() const AVO_OVERRIDE
  {
    return m_description;
  }

  std::string specificationUrl() const AVO_OVERRIDE
  {
    return m_specificationUrl;
  }

  std::vector<std::string> fileExtensions() const AVO_OVERRIDE
  {
    return m_fileExtensions;
  }

  std::vector<std::string> mimeTypes() const AVO_OVERRIDE
  {
    return m_mimeTypes;
  }

private:
  static Format stringToFormat(const std::string &str);
  static Io::FileFormat* createFileFormat(Format fmt);
  void resetMetaData();
  void readMetaData();
  bool parseString(const QJsonObject &ob, const QString &key,
                   std::string &str);
  bool parseStringArray(const QJsonObject &ob, const QString &key,
                        std::vector<std::string> &array);

private:
  QtGui::PythonScript *m_interpreter;
  bool m_valid;
  Operations m_operations;
  Format m_inputFormat;
  Format m_outputFormat;
  std::string m_identifier;
  std::string m_name;
  std::string m_description;
  std::string m_specificationUrl;
  std::vector<std::string> m_fileExtensions;
  std::vector<std::string> m_mimeTypes;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_FILEFORMATSCRIPT_H
