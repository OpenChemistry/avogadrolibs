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
#include <QtCore/QJsonObject>
#include <QtCore/QList>
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
                      const QString& identifier,
                      const QString& displayName = QString());

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
   * @return The package display name from metadata, if one was provided.
   */
  QString packageDisplayName() const { return m_packageDisplayName; }

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
   * If @p closeWriteChannel is false, stdin remains open for follow-up writes.
   *
   * Will send asyncFinished() signal when finished
   *
   * Returns true if the process was started; false if it could not be
   * launched, in which case finished() will never be emitted and errorList()
   * describes the failure.
   */
  bool asyncExecute(const QStringList& args,
                    const QByteArray& scriptStdin = QByteArray(),
                    bool mergedChannels = true, bool closeWriteChannel = true);

  /**
   * Enable incremental scanning of the asynchronous process' standard output
   * for progress envelopes, i.e. single lines of the form
   * `{"avogadro": { ... }}`. Matching lines are removed from the output and
   * reported through the asyncProgress() signal; every other line is kept and
   * returned by asyncResponse() as usual.
   *
   * This must be set before asyncExecute(). It is opt-in because scanning
   * drains the process' output as it arrives, which is incompatible with
   * callers that read the process directly (e.g. asyncWriteAndResponse() in
   * "server mode").
   *
   * When enabled, the script is run with `AVO_PROGRESS_PROTOCOL` set in its
   * environment so it can tell that Avogadro is listening. Scripts must check
   * for it before printing envelopes: releases up to and including Avogadro
   * 2.0.0 read the script's whole standard output as a single JSON document,
   * and the extra lines make that parse fail outright.
   */
  void setProgressScanning(bool enable) { m_scanProgress = enable; }

  /**
   * @return True if standard output is being scanned for progress envelopes.
   */
  bool progressScanning() const { return m_scanProgress; }

  /**
   * Test whether a single line of script output is a progress envelope.
   *
   * To avoid mistaking part of a pretty-printed result for an envelope, the
   * line must parse as a complete JSON object with exactly one member, named
   * "avogadro".
   *
   * @param line The line to test, without its trailing newline.
   * @param payload Set to the contents of the "avogadro" member on success.
   * @return True if @p line is a progress envelope.
   */
  static bool parseProgressEnvelope(const QByteArray& line,
                                    QJsonObject& payload);

  /**
   * Split @p buffer into complete lines, appending the payload of any progress
   * envelope to @p payloads and every other line (newline included) verbatim
   * to @p output. A trailing partial line is left in @p buffer for the next
   * call.
   */
  static void filterProgressLines(QByteArray& buffer, QByteArray& output,
                                  QList<QJsonObject>& payloads);

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
   * Write input to the asynchronous process' standard input and return raw
   * bytes from stdout. Unlike asyncWriteAndResponse(), this does not require
   * line-oriented output and is suitable for framed binary protocols.
   */
  QByteArray asyncWriteAndResponseRaw(const QByteArray& input,
                                      int timeoutMs = 5000);

  /**
   * Terminate the asynchronous process.
   */
  void asyncTerminate();

  /**
   * Returns the standard output of the asynchronous process when finished.
   * If progress scanning is enabled, progress envelope lines have been
   * removed and the remainder is returned even after the process is gone.
   */
  QByteArray asyncResponse();

  /**
   * @return The standard error collected from the asynchronous process. Only
   * populated when the process was started with separate channels; useful for
   * reporting a python traceback that never reached standard output.
   */
  QByteArray asyncStandardError() const { return m_stderrBuffer; }

signals:
  /**
   * The asynchronous execution is finished or timed out
   */
  void finished();

  /**
   * A progress envelope was read from the asynchronous process' standard
   * output. Only emitted when setProgressScanning(true) was called before
   * asyncExecute().
   * @param payload The contents of the "avogadro" member of the envelope.
   */
  void asyncProgress(const QJsonObject& payload);

public slots:
  /**
   * Enable/disable debugging.
   */
  void setDebug(bool d) { m_debug = d; }

  /**
   * Handle a finished process;
   */
  void processFinished(int exitCode, QProcess::ExitStatus exitStatus);

private slots:
  /**
   * Drain whatever the asynchronous process has written so far, filtering
   * progress envelopes out of standard output.
   * @{
   */
  void readAsyncStandardOutput();
  void readAsyncStandardError();
  /**@}*/

protected:
  bool m_debug;
  bool m_packageMode = false;
  QString m_pythonInterpreter;
  QString m_pixi;
  QString m_scriptFilePath;
  QString m_packageDir;
  QString m_packageCommand;
  QString m_packageIdentifier;
  QString m_packageDisplayName;
  QStringList m_errors;
  QProcess* m_process;

private:
  // Scan the asynchronous process' stdout for progress envelopes, buffering
  // the rest for asyncResponse(). Off by default; see setProgressScanning().
  bool m_scanProgress = false;
  // Standard output with any progress envelopes removed.
  QByteArray m_stdoutBuffer;
  // Standard error, kept for diagnostics (separate channels only).
  QByteArray m_stderrBuffer;
  // Trailing partial line of standard output, awaiting its newline.
  QByteArray m_lineBuffer;

  /**
   * Resolve the executable and finalize the argument list for either
   * execute() or asyncExecute().  On entry @p realArgs already contains
   * the caller-supplied args plus --debug/--lang.  On return @p realArgs
   * is fully prepended and @p proc has its working directory set.
   * @return The program path to pass to QProcess::start(), or an empty
   *         string on error (m_errors will be populated).
   */
  QString resolveCommand(QStringList& realArgs, QProcess& proc);

  QString processErrorString(const QProcess& proc) const;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_PYTHONSCRIPT_H
