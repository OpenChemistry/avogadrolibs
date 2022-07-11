/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2019 Geoffrey R. Hutchison

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OBMMPROCESS_H
#define AVOGADRO_QTPLUGINS_OBMMPROCESS_H

#include <QtCore/QMap>
#include <QtCore/QObject>
#include <QtCore/QStringList>

class QProcess;

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The OBMMProcess class provides an interface to the `obmm` executable,
 * which is run in a separate process.
 *
 * The `obmm` executable used by this class can be overridden by setting the
 * AVO_OBABEL_EXECUTABLE environment variable.
 */
class OBMMProcess : public QObject
{
  Q_OBJECT
public:
  explicit OBMMProcess(QObject* parent_ = 0);

  /**
   * @name Process Management
   * Methods, slots, and signals used to interact with the OpenBabel process.
   * @{
   */
public:
  /**
   * The `obmm` executable used by the process.
   */
  QString obmmExecutable() const { return m_obmmExecutable; }

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


private:
  /**
   * Internal method for launching the obmm executable.
   * @param options List of options to pass to QProcess::start
   * @param receiver A QObject subclass instance that has @a slot as a member.
   * @param slot The slot to call when completed. Must have no arguments.
   * @param obmmStdin Standard input for the obmm process (optional).
   *
   * Call this method like so:
@code
QStringList options;
<Populate options>
executeobmm(options, this, SLOT(mySlot()));
@endcode
   *
   * @a slot will be connected to QProcess::finished(int) and
   * QProcess::error(QProcess::ProcessError) with @a receiver as receiver and
   * @a m_process as sender. @a m_process is then started using
   * m_obmmExecutable and options as arguments. If provided, the obmmStdin
   * data will be written to the obmm stdin channel.
   */
  void executeobmm(const QStringList& options, QObject* receiver = nullptr,
                     const char* slot = nullptr,
                     const QByteArray& obmmStdin = QByteArray());

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
  QString m_obmmExecutable;

};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OBMMProcess_H
