/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_MOLEQUEUE_MOLEQUEUEWIDGET_H
#define AVOGADRO_MOLEQUEUE_MOLEQUEUEWIDGET_H

#include "avogadromolequeueexport.h"
#include <QtWidgets/QWidget>

#include <avogadro/core/avogadrocore.h>

#include "client/jobobject.h"

namespace Avogadro {
namespace MoleQueue {

namespace Ui {
class MoleQueueWidget;
}

/**
 * @class MoleQueueWidget molequeuewidget.h
 * <avogadro/molequeue/molequeuewidget.h>
 * @brief The MoleQueueWidget class provides a widget for configuring and
 * submitting a MoleQueue::JobObject.
 */
class AVOGADROMOLEQUEUE_EXPORT MoleQueueWidget : public QWidget
{
  Q_OBJECT
public:
  explicit MoleQueueWidget(QWidget* parent_ = nullptr);
  ~MoleQueueWidget() override;

  /**
   * A "template" MoleQueue::JobObject that is used to initialize the GUI.
   * Should be fully configured to submit, as this is used to initialize job
   * that will be submitted by submitJobRequest.
   * @{
   */
  JobObject& jobTemplate();
  const JobObject& jobTemplate() const;
public slots:
  void setJobTemplate(const JobObject& job);

public:
  /** @} */

  /**
   * Expand all queue nodes that contain a program that matches @a programName
   * and select the first matching program node.
   * Matches are case insensitive.
   */
  void showAndSelectProgram(const QString& programName);

  /**
   * @return True if the last submission was successful. Only valid after
   * jobSubmitted has been emitted.
   */
  bool submissionSuccess() const { return m_moleQueueId != InvalidMoleQueueId; }

  /**
   * @return True if the last submission was successful. Only valid after
   * jobSubmitted has been emitted.
   */
  QString jobState() const { return m_jobState; }

  /**
   * @return True if the job has finished running.
   */
  bool jobCompleted() const
  {
    return (m_jobState == QLatin1String("Finished") ||
            m_jobState == QLatin1String("Error") ||
            m_jobState == QLatin1String("Canceled"));
  }

  /**
   * @return true if the job completed without error.
   */
  bool jobSuccess() const { return m_jobState == QLatin1String("Finished"); }

  /**
   * @return The request id associated with the last call to submitJobRequest.
   * -1 if there was a submission error.
   */
  int requestId() const { return m_requestId; }

  /**
   * Indicates an invalid MoleQueue ID in the moleQueueId() result.
   */
  static const unsigned int InvalidMoleQueueId;

  /**
   * @return The MoleQueue ID associated with the last submitJobRequest() call.
   * Only valid after jobSubmitted has been emitted.
   * @note If an error occurs, InvalidMoleQueueId will be returned.
   */
  unsigned int moleQueueId() const { return m_moleQueueId; }

  /**
   * @return A string describing the submission error when submissionSuccess()
   * return false.
   */
  QString submissionError() const { return m_submissionError; }

  /**
   * @return True if the user has requested that the output file be opened when
   * the calculation completes.
   */
  bool openOutput() const;

  /**
   * @brief Request the current state of the job identified by moleQueueId()
   * from the server. The result will be emitted in the jobUpdated() signal.
   * @return True if moleQueueId() is valid and the server is connected, false
   * if the request cannot be sent.
   */
  bool requestJobLookup();

  /**
   * If the widget is in 'batch mode', options that don't make sense are hidden
   * (such as 'open output when finished').
   */
  void setBatchMode(bool batch);
  bool batchMode() const;
  /**@}*/

  /**
   * @return True if the user has selected a program, false otherwise.
   */
  bool programSelected();

  /**
   * @return A JobObject with the GUI options. Any settings in jobTemplate that
   * are not handled by the GUI are passed through untouched to the new object.
   */
  JobObject configuredJob() const;

public slots:
  /**
   * Query the MoleQueue server (if available) for the list of available queues
   * and programs.
   */
  void refreshPrograms();

  /**
   * Submit the job returned by configuredJob() to MoleQueue.
   * @return The request id associated with the submission, or -1 on error.
   * @note The result of the submission request can be checked by monitoring
   * jobSubmitted, which will always be emitted after this slot is called.
   */
  int submitJobRequest();

signals:
  /**
   * Emitted after a call to submitJobRequest
   * @param success True if the job has been accepted by MoleQueue.
   */
  void jobSubmitted(bool success);

  /**
   * Emitted after jobSubmitted is emitted and the job completes.
   * @param success True if the job enters the "Finished" state. False if the
   * job enters the "Canceled" or "Error" states.
   */
  void jobFinished(bool success);

  /**
   * Emitted after a successful call to requestJobLookup().
   * @param job The result of the lookupJob() RPC query.
   */
  void jobUpdated(const JobObject& job);

private slots:
  void showAndSelectProgramHandler();

  void onLookupJobReply(int reqId, const QJsonObject& result);

  void onSubmissionSuccess(int localId, unsigned int moleQueueId);
  void onSubmissionFailure(int localId, unsigned int, const QString& error);

  void onJobStateChange(unsigned int mqId, const QString& oldState,
                        const QString& newState);

private:
  void listenForLookupJobReply(bool listen = true);
  void listenForJobSubmitReply(bool listen = true);
  void listenForJobStateChange(bool listen = true);

  Ui::MoleQueueWidget* m_ui;
  JobObject m_jobTemplate;
  QString m_jobState;
  QString m_submissionError;
  int m_requestId;
  unsigned int m_moleQueueId;
};

} // namespace MoleQueue
} // namespace Avogadro

#endif // AVOGADRO_MOLEQUEUE_MOLEQUEUEWIDGET_H
