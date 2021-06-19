/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_MOLEQUEUE_MOLEQUEUEDIALOG_H
#define AVOGADRO_MOLEQUEUE_MOLEQUEUEDIALOG_H

#include "avogadromolequeueexport.h"
#include <QtWidgets/QDialog>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace MoleQueue {
class JobObject;
class MoleQueueWidget;

namespace Ui {
class MoleQueueDialog;
}

/**
 * @class MoleQueueDialog molequeuedialog.h
 * <avogadro/molequeue/molequeuedialog.h>
 * @brief The MoleQueueDialog class provides a thin wrapper around
 * MoleQueueWidget for standalone use.
 * @sa MoleQueueWidget MoleQueueManager
 */
class AVOGADROMOLEQUEUE_EXPORT MoleQueueDialog : public QDialog
{
  Q_OBJECT
public:
  explicit MoleQueueDialog(QWidget* parent_ = nullptr);
  ~MoleQueueDialog() override;

  /**
   * @brief Options controlling job submission behavior in the submitJob method.
   */
  enum SubmitOption
  {
    /**
     * Keep the dialog open until MoleQueue replies to the submission request.
     * If a submission error occurs, the user will have to opportunity to fix
     * it.
     */
    WaitForSubmissionResponse = 0x1,

    /**
     * Use the program in the template job to initialize the queue/program view.
     * All queues containing a matching program will be expanded, and the first
     * match will be selected.
     * To match, an existing program must contain the template program string,
     * and comparisons are case insensitive.
     */
    SelectProgramFromTemplate = 0x2
  };
  Q_DECLARE_FLAGS(SubmitOptions, SubmitOption)

  /**
   * @brief Return values from submitJob indicating result.
   */
  enum SubmitStatus
  {
    /**
     * The job was accepted by MoleQueue.
     * This can only be returned when WaitForSubmissionResponse IS set as an
     * option.
     */
    SubmissionSuccessful = 0,

    /**
     * The job was not submitted to MoleQueue, likely due to a disconnected
     * server.
     * This can only be returned when WaitForSubmissionResponse IS NOT
     * set as an option.
     */
    SubmissionFailed,

    /**
     * The job was submitted to MoleQueue. This can only be returned when
     * WaitForSubmissionResponse is NOT set as an option.
     */
    SubmissionAttempted,

    /**
     * The user canceled the submission.
     */
    SubmissionAborted,

    /**
     * The user requested that the job output be opened when finished, but
     * the job did not finish successfully (the job was either canceled or
     * failed).
     */
    JobFailed,

    /**
     * The user requested that the job output be opened when finished, and
     * the job completed without error. The jobTemplate argument of
     * submitJob will be overwritten with the current job details, fetched
     * from the server after the job enters the "Finished" state.
     */
    JobFinished
  };

  /**
   * Show a job configuration dialog and let the user submit the job to
   * MoleQueue.
   * @param parent_ The parent widget for parenting/layout purposes.
   * @param caption The dialog title.
   * @param jobTemplate A template job, used to initialize GUI options. If
   * the user requests that the job output is opened and the job finishes
   * successfully, this will be overwritten with the current job details, and
   * JobFinished is returned.
   * @param options Bitwise combination of flags that control dialog behavior.
   * @param moleQueueId If not nullptr, the variable referenced by this pointer
   * will be overwritten by the MoleQueue Id of the submitted job when the
   * option WaitForSubmissionResponse is set.
   * If an error occurs or the required option is not set, this value will be
   * set to MoleQueueWidget::InvalidMoleQueueId.
   * @param submissionRequestId If not nullptr, the variable referenced by this
   * pointer will be overwritten by the submitJob JSON-RPC 2.0 request id.
   * If an error occurs, this value will be set to -1.
   * @return A SubmitStatus enum value indicating the result of the submission.
   */
  static SubmitStatus submitJob(QWidget* parent_, const QString& caption,
                                JobObject& jobTemplate,
                                SubmitOptions options,
                                unsigned int* moleQueueId = nullptr,
                                int* submissionRequestId = nullptr);

  /**
   * Show a job configuration dialog and collect the user's selected options.
   * @param windowParent The parent of the dialog window.
   * @param caption Title of the dialog window.
   * @param jobTemplate JobObject with initial options. Will be overwritten
   * with the configured job options.
   * @return True on success, false otherwise.
   */
  static bool promptForJobOptions(QWidget* windowParent, const QString& caption,
                                  JobObject& jobTemplate);

  /**
   * @return A reference to the internal MoleQueueWidget instance.
   * @{
   */
  MoleQueueWidget& widget();
  const MoleQueueWidget& widget() const;
  /** @} */

public slots:
  void done(int r) override;

private:
  typedef QPair<QObject*, const char*> MetaMethod;
  /**
   * Wait @a timeout milliseconds for @a source to emit @a signal.
   * @param signalList List of QObject* and const char* (signals) to listen for.
   * @param msTimeout Timeout in milliseconds. A negative value will wait
   * forever.
   * @return True if a signal in @a signalList is received, false on timeout.
   */
  bool waitForSignal(const QList<MetaMethod>& signalList,
                     int msTimeout = 5000) const;

  Ui::MoleQueueDialog* m_ui;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(MoleQueueDialog::SubmitOptions)

} // namespace MoleQueue
} // namespace Avogadro
#endif // AVOGADRO_MOLEQUEUE_MOLEQUEUEDIALOG_H
