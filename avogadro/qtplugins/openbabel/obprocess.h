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

#ifndef AVOGADRO_QTPLUGINS_OBPROCESS_H
#define AVOGADRO_QTPLUGINS_OBPROCESS_H

#include <QtCore/QMap>
#include <QtCore/QObject>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The OBProcess class provides an interface to the `obabel` executable,
 * which is run in a separate process.
 *
 * The `obabel` executable can be overriden by setting the AVO_OBABEL_EXECUTABLE
 * environment variable.
 */
class OBProcess : public QObject
{
  Q_OBJECT
public:
  explicit OBProcess(QObject *parent_ = 0);

  /**
   * The `obabel` executable used by the process.
   * @{
   */
  void setObabelExecutable(const QString &exec) { m_obabelExecutable = exec; }
  QString obabelExecutable() const { return m_obabelExecutable; }
  /**@}*/

  /**
   * @name File Format Support
   * Query the obabel executable for supported file formats.
   * @{
   */
public slots:
  /**
   * Request a list of all supporting input formats from obabel.
   *
   * After calling this method, the queryReadFormatsFinished signal will be
   * emitted. This method executes
   *
   * `obabel -L formats read`
   *
   * and parses the output into a map (keys are format descriptions, values are
   * format extensions).
   */
  void queryReadFormats();

signals:
  /**
   * Triggered when the process started by queryReadFormats() completes.
   * @param readFormats The input file formats that OpenBabel understands. Keys
   * are non-translated (english), human-readable descriptions of the formats,
   * and the values are the corresponding file extensions.
   *
   * @note readFormats will usually contain more than one extensions per format,
   * so accessing the values with QMap::values() (instead of QMap::value()) is
   * required.
   *
   * If an error occurs, readFormats will be empty.
   */
  void queryReadFormatsFinished(QMap<QString, QString> readFormats);

private slots:
  void queryReadFormatsPrepare();
  /**@}*/

  /**
   * @name File Reading
   * Used to open a file with obabel and return a CML representation
   * of the molecule.
   * @{
   */
public slots:
  /**
   * Request that obabel read a file from disk.
   * @param filename The output file to read.
   * @param outputFormat The format used to represent the molecule. Default: cml
   * @param inputFormatOverride Optional override to the input file's format.
   * If not specified, the format is guessed from @a filename's extension.
   *
   * After calling this method, the readFileFinished signal will be emitted to
   * indicate return status along with the requested representation of the
   * molecule, or an error message.
   *
   * The conversion is performed as:
   * `obabel -i<filename extension> <filename> -o<outputFormat>`
   *
   * The standard output is recorded and returned by readFileFinished.
   */
  void readFile(const QString &filename, const QString &outputFormat = "cml",
                const QString &inputFormatOverride = QString());

signals:
  /**
   * Emitted after a call to readFile.
   * @param output The molecule in the requested format, or an empty QByteArray
   * if an error occurred.
   */
  void readFileFinished(const QByteArray &output);

private slots:
  void readFilePrepareOutput();
/**@}*/

private:
  QString m_obabelExecutable;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OBPROCESS_H
