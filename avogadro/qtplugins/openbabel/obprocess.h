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
#include <QtCore/QStringList>

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
  explicit OBProcess(QObject* parent_ = nullptr);

  /**
   * @return The output of obabel -V.
   */
  QString version();

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

  /**
   * Called when an error in the process occurs.
   */
  void obError();

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

  /**
   * Request a list of all supported output formats from obabel.
   *
   * After calling this method, the queryWriteFormatsFinished signal will be
   * emitted. This method executes
   *
   * `obabel -L formats write`
   *
   * and parses the output into a map (keys are format descriptions, values are
   * format extensions).
   *
   * If an error occurs, queryWriteFormatsFinished will be emitted with an empty
   * argument.
   *
   * @return True if the process started successfully, false otherwise.
   */
  bool queryWriteFormats();

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

  /**
   * Triggered when the process started by queryWriteFormats() completes.
   * @param writeFormats The file formats that OpenBabel can write. Keys
   * are non-translated (english), human-readable descriptions of the formats,
   * and the values are the corresponding file extensions.
   *
   * @note writeFormats will usually contain more than one extensions per
   * format, so accessing the values with QMap::values() (instead of
   * QMap::value()) is required.
   *
   * If an error occurs, writeFormats will be empty.
   */
  void queryWriteFormatsFinished(QMap<QString, QString> writeFormats);

private slots:
  void queryReadFormatsPrepare();
  void queryWriteFormatsPrepare();

  // end File Format Support doxygen group
  /**@}*/

  /**
   * @name Format Operations
   * Operations that manipulate molecular representations.
   * @{
   */
public slots:
  /**
   * Convert the text representation in @a input from @a inFormat to
   * @a outFormat.
   *
   * @param input Text representation of molecule in @a inFormat format.
   * @param inFormat File extension corresponding to input format
   * (see `obabel -L formats`).
   * @param outFormat File extension corresponding to output format.
   * @param options Additional options passed to obabel.
   *
   * After calling this method, the convertFinished signal will be emitted to
   * indicate return status along with the requested representation of the
   * molecule.
   *
   * The conversion is performed as:
   * `obabel -i<inFormat> -o<outFormat> <options> < input > output`
   *
   * @return True if the process started successfully, false otherwise.
   */
  bool convert(const QByteArray& input, const QString& inFormat,
               const QString& outFormat,
               const QStringList& options = QStringList());

  /**
   * Convert the file @a filename from @a inFormat to @a outFormat.
   *
   * @param filename File containing molecule representation in @a inFormat
   * format.
   * @param inFormat File extension corresponding to input format
   * (see `obabel -L formats`).
   * @param outFormat File extension corresponding to output format.
   * @param options Additional options passed to obabel.
   *
   * After calling this method, the convertFinished signal will be emitted to
   * indicate return status along with the requested representation of the
   * molecule.
   *
   * The conversion is performed as:
   * `obabel -i<inFormat> <filename> -o<outFormat> <options> > output`
   *
   * @return True if the process started successfully, false otherwise.
   */
  bool convert(const QString& filename, const QString& inFormat,
               const QString& outFormat,
               const QStringList& options = QStringList());

signals:
  /**
   * Emitted after a call to convert() finishes.
   * @param output The molecule in CML format, or an empty QByteArray if an e
   * error occurred.
   */
  void convertFinished(const QByteArray& output);

private slots:
  void convertPrepareOutput();

  // end Format Operations doxygen group
  /**@}*/

  /**
   * @name Force Fields
   * Methods, signals, and slots pertaining to force fields (e.g. geometry
   * optimizations).
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
  void queryForceFieldsFinished(const QMap<QString, QString>& forceFields);

private slots:
  void queryForceFieldsPrepare();

public slots:
  /**
   * Request that obabel optimize a molecular structure using its minimize
   * operation.
   * @param cml A Chemical Markup Language representation of the molecule.
   * @param options Options for the optimization. See OBForceFieldDialog::prompt
   * for an easy method way to get the options from the user.
   *
   * After calling this method, the optimizeGeometryStatusUpdate signal will be
   * emitted periodically to indicate the optimization's progress. Once the
   * optimization finishes, optimizeGeometryFinished will be emitted with the
   * result of the optimization.
   *
   * The optimization is started with
   * `obabel -icml -ocml --minimize <options>`
   *
   * The standard output is recorded and returned by optimizeGeometryFinished.
   * If @a options contains `--log`, the obabel process's standard error stream
   * is monitored for the data used in the optimizeGeometryStatusUpdate progress
   * updates.
   *
   * @return True if the process started successfully, false otherwise.
   */
  bool optimizeGeometry(const QByteArray& cml, const QStringList& options);
signals:
  /**
   * Emitted with the standard output of the process when it finishes.
   * If an error occurs, the argument will not be valid CML.
   */
  void optimizeGeometryFinished(const QByteArray& cml);
  /**
   * Emitted every 10 steps of the optimization to indicate the current
   * progress.
   * @param step The current step of the minimization algorithm.
   * @param maxSteps The maximum number of steps before the minimization is
   * aborted.
   * @param currentEnergy The energy of the molecule at the current step.
   * @param lastEnergy The energy of the molecule at the previous minimization
   * step.
   */
  void optimizeGeometryStatusUpdate(int step, int maxSteps,
                                    double currentEnergy, double lastEnergy);
private slots:
  void optimizeGeometryPrepare();
  void optimizeGeometryReadLog();

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
  void executeObabel(const QStringList& options, QObject* receiver = nullptr,
                     const char* slot = nullptr,
                     const QByteArray& obabelStdin = QByteArray());

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

  void releaseProcess() { m_processLocked = false; }

  bool m_processLocked;
  bool m_aborted;
  QProcess* m_process;
  QString m_obabelExecutable;

  // Optimize geometry ivars:
  int m_optimizeGeometryMaxSteps;
  QString m_optimizeGeometryLog;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OBPROCESS_H
