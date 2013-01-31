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

class QProcess;

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The OBProcess class provides an interface to the `obabel` executable,
 * which is run in a separate process.
 *
 * The `obabel` executable used by this class can be overridden by setting the
 * AVO_OBABEL_EXECUTABLE environment variable.
 */
class OBProcess : public QObject
{
  Q_OBJECT
public:
  explicit OBProcess(QObject *parent_ = 0);

  /**
   * @name Process Management
   * Methods, slots, and signals used to interact with the OpenBabel process.
   * @{
   */
public:
  /**
   * The `obabel` executable used by the process.
   */
  QString obabelExecutable() const { return m_obabelExecutable; }

  /**
   * @return True if the process is in use, false otherwise.
   */
  bool inUse() const { return m_processLocked; }

public slots:
  /**
   * Abort any currently running processes.
   *
   * This will cause aborted() to be emitted, but not any of the
   * operation-specific "finished" signals.
   */
  void abort();

signals:
  /**
   * Emitted when the abort() method has been called.
   */
  void aborted();

  // end Process Management doxygen group
  /**@}*/

  /**
   * @name File Format Support
   * Query the obabel executable for supported file formats.
   * @{
   */
public slots:
  /**
   * Request a list of all supported input formats from obabel.
   *
   * After calling this method, the queryReadFormatsFinished signal will be
   * emitted. This method executes
   *
   * `obabel -L formats read`
   *
   * and parses the output into a map (keys are format descriptions, values are
   * format extensions).
   *
   * If an error occurs, queryReadFormatsFinished will be emitted with an empty
   * argument.
   *
   * @return True if the process started successfully, false otherwise.
   */
  bool queryReadFormats();

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

  // end File Format Support doxygen group
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
   *
   * @return True if the process started successfully, false otherwise.
   */
  bool readFile(const QString &filename, const QString &outputFormat = "cml",
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

  // end File Reading doxygen group
  /**@}*/

  /**
   * @name Force Fields
   * Methods, signals, and slots pertaining to geometry optimizations.
   * @{
   */

public slots:
  /**
   * Request a list of all supported force fields from obabel.
   *
   * After calling this method, the queryForceFieldsFinished signal will be
   * emitted. This method executes
   *
   * `obabel -L forcefields`
   *
   * and parses the output.
   *
   * If an error occurs, queryReadFormatsFinished will be emitted with an empty
   * argument.
   *
   * @return True if the process started successfully, false otherwise.
   */
  bool queryForceFields();

signals:
  /**
   * Triggered when the process started by queryForceFields() completes.
   * @param forceFields The force fields supported by OpenBabel. Keys
   * are unique identifiers for the force fields, and the values are
   * non-translated (english), human-readable descriptions.
   *
   * If an error occurs, forceFields will be empty.
   */
  void queryForceFieldsFinished(const QMap<QString, QString> &forceFields);

private slots:
  void queryForceFieldsPrepare();

public slots:
  /// @todo document
  bool optimizeGeometry(const QByteArray &cml, const QStringList &options);
signals:
  /// @todo document
  void optimizeGeometryFinished(const QByteArray &cml);
private slots:
  void optimizeGeometryPrepare();

  // end Force Fields doxygen group
  /**@}*/

private:
  /**
   * Internal method for launching the obabel executable.
   * @param options List of options to pass to QProcess::start
   * @param receiver A QObject subclass instance that has @a slot as a member.
   * @param slot The slot to call when completed. Must have no arguments.
   * @param obabelStdin Standard input for the obabel process (optional).
   *
   * Call this method like so:
@code
QStringList options;
<Populate options>
executeObabel(options, this, SLOT(mySlot()));
@endcode
   *
   * @a slot will be connected to QProcess::finished(int) and
   * QProcess::error(QProcess::ProcessError) with @a receiver as receiver and
   * @a m_process as sender. @a m_process is then started using
   * m_obabelExecutable and options as arguments. If provided, the obabelStdin
   * data will be written to the obabel stdin channel.
   */
  void executeObabel(const QStringList &options, QObject *receiver,
                     const char *slot,
                     const QByteArray &obabelStdin = QByteArray());

  void resetState();

  // Not thread safe -- just uses a bool.
  bool tryLockProcess()
  {
    if (m_processLocked)
      return false;
    m_processLocked = true;
    resetState();
    return true;
  }

  void releaseProcess()
  {
    m_processLocked = false;
  }

  bool m_processLocked;
  bool m_aborted;
  QProcess *m_process;
  QString m_obabelExecutable;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OBPROCESS_H
