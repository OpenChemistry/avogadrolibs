/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_PYTHONSCRIPT_H
#define AVOGADRO_QTGUI_PYTHONSCRIPT_H

#include "avogadroqtguiexport.h"
#include <QtCore/QObject>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QByteArray>
#include <QtCore/QProcess>
#include <QtCore/QString>
#include <QtCore/QStringList>

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
  explicit PythonScript(const QString& scriptFilePath_,
                        QObject* parent_ = nullptr);
  explicit PythonScript(QObject* parent_ = nullptr);
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
  void setScriptFilePath(const QString& scriptFile);

  /**
   * Enable package mode. In this mode, execute() runs
   * "pixi run <command> <identifier> [args]" with packageDir as the
   * working directory, instead of launching a script file via python.
   */
  void setPackageInfo(const QString& packageDir, const QString& command,
                      const QString& identifier);

  /**
   * @return True if this script is in package mode.
   */
  bool isPackageMode() const { return m_packageMode; }

  /**
   * @return The package directory (only meaningful in package mode).
   */
  QString packageDir() const { return m_packageDir; }

  /**
   * @return The package command (only meaningful in package mode).
   */
  QString packageCommand() const { return m_packageCommand; }

  /**
   * @return The package identifier (only meaningful in package mode).
   */
  QString packageIdentifier() const { return m_packageIdentifier; }

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
  void setDefaultPythonInterpreter();

  /**
   * Start a new process to execute:
   * "<m_pythonInterpreter> <scriptFilePath()> [args ...]",
   * optionally passing scriptStdin to the processes standard input. Returns
   * the standard output of the process when finished.
   */
  QByteArray execute(const QStringList& args,
                     const QByteArray& scriptStdin = QByteArray());

  /**
   * Start a new process to execute asynchronously
   * "<m_pythonInterpreter> <scriptFilePath()> [args ...]",
   * optionally passing scriptStdin to the processes standard input.
   *
   * Will send asyncFinished() signal when finished
   */
  void asyncExecute(const QStringList& args,
                    const QByteArray& scriptStdin = QByteArray());

  /**
   * Write input to the asynchronous process' standard input and return the
   * standard output when ready. Does not wait for the process to terminate
   * before returning (e.g. "server mode").
   *
   * @param input The input to write to the process' standard input
   * @return The standard output of the process
   */
  QByteArray asyncWriteAndResponse(QByteArray input);

  /**
   * Terminate the asynchronous process.
   */
  void asyncTerminate();

  /**
   * Returns the standard output of the asynchronous process when finished.
   */
  QByteArray asyncResponse();

signals:
  /**
   * The asynchronous execution is finished or timed out
   */
  void finished();

public slots:
  /**
   * Enable/disable debugging.
   */
  void setDebug(bool d) { m_debug = d; }

  /**
   * Handle a finished process;
   */
  void processFinished(int exitCode, QProcess::ExitStatus exitStatus);

protected:
  bool m_debug;
  bool m_packageMode = false;
  QString m_pythonInterpreter;
  QString m_pixi;
  QString m_scriptFilePath;
  QString m_packageDir;
  QString m_packageCommand;
  QString m_packageIdentifier;
  QStringList m_errors;
  QProcess* m_process;

private:
  QString processErrorString(const QProcess& proc) const;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_PYTHONSCRIPT_H
