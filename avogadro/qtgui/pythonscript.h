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

#ifndef AVOGADRO_QTGUI_PYTHONSCRIPT_H
#define AVOGADRO_QTGUI_PYTHONSCRIPT_H

#include <QtCore/QObject>
#include "avogadroqtguiexport.h"

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QStringList>

class QProcess;

namespace Avogadro {
namespace QtGui {

/**
 * @brief The PythonScript class implements a interface for calling short-lived
 * python utility scripts.
 */
class AVOGADROQTGUI_EXPORT PythonScript : public QObject
{
  Q_OBJECT
public:
  /**
   * Constructors
   * @param scriptFilePath_ Absolute path to python script.
   * @{
   */
  explicit PythonScript(const QString &scriptFilePath_,
                        QObject *parent_ = nullptr);
  explicit PythonScript(QObject *parent_ = nullptr);
  /**@}*/

  ~PythonScript() override;

  /**
   * @return True if debugging of python I/O is enabled.
   */
  bool debug() const { return m_debug; }

  /**
   * @return The path to the generator file.
   */
  QString scriptFilePath() const { return m_scriptFilePath; }

  /**
   * Set the path to the input generator script file. This will reset any
   * cached data held by this class.
   */
  void setScriptFilePath(const QString &scriptFile);

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
   * Reset the python interpretor path. The following are checked, in order:
   * - The AVO_PYTHON_INTERPRETER environment variable
   * - The "interpreters/python" QSettings value
   * - The path specified in avogadropython.h.
   */
  void setDefaultPythonInterpretor();

  /**
   * Start a new process to execute:
   * "<m_pythonInterpreter> <scriptFilePath()> [args ...]",
   * optionally passing scriptStdin to the processes standard input. Returns
   * the standard output of the process when finished.
   */
  QByteArray execute(const QStringList &args,
                     const QByteArray &scriptStdin = QByteArray());

public slots:
  /**
   * Enable/disable debugging.
   */
  void setDebug(bool d) { m_debug = d; }

protected:
  bool m_debug;
  QString m_pythonInterpreter;
  QString m_scriptFilePath;
  QStringList m_errors;

private:
  QString processErrorString(const QProcess &proc) const;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_PYTHONSCRIPT_H
