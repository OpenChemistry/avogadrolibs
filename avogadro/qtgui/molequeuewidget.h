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

#ifndef AVOGADRO_QTGUI_MOLEQUEUEWIDGET_H
#define AVOGADRO_QTGUI_MOLEQUEUEWIDGET_H

#include <QtGui/QWidget>
#include "avogadroqtguiexport.h"

#include <avogadro/core/avogadrocore.h>

#include <molequeue/client/job.h>

namespace Avogadro {
namespace QtGui {

namespace Ui {
class MoleQueueWidget;
}

/**
 * @class MoleQueueWidget molequeuewidget.h <avogadro/qtcore/molequeuewidget.h>
 * @brief The MoleQueueWidget class provides a widget for configuring and
 * submitting a MoleQueue::JobObject.
 */
class AVOGADROQTGUI_EXPORT MoleQueueWidget : public QWidget
{
  Q_OBJECT
public:
  explicit MoleQueueWidget(QWidget *parent_ = 0);
  ~MoleQueueWidget() AVO_OVERRIDE;

  /**
   * A "template" MoleQueue::JobObject that is used to initialize the GUI.
   * Should be fully configured to submit, as this is used to initialize job
   * that will be submitted by submitJobRequest.
   * @{
   */
  MoleQueue::JobObject& jobTemplate();
  const MoleQueue::JobObject& jobTemplate() const;
  void setJobTemplate(const MoleQueue::JobObject &job);
  /** @} */

  /**
   * Expand all queue nodes that contain a program that matches @a programName
   * and select the first matching program node.
   * Matches are case insensitive.
   */
  void showAndSelectProgram(const QString &programName);

  /**
   * @return A JobObject with the GUI options. Any settings in jobTemplate that
   * are not handled by the GUI are passed through untouched to the new object.
   */
  MoleQueue::JobObject configuredJob() const;

  /**
   * @return True if the last submission was successful. Only valid after
   * jobSubmitted has been emitted.
   */
  bool submissionSuccess() const { return m_moleQueueId != InvalidMoleQueueId; }

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

private slots:
  void showAndSelectProgramHandler();

  void onSubmissionSuccess(int localId, unsigned int moleQueueId);
  void onSubmissionFailure(int localId, unsigned int, const QString &error);

private:
  void listenForReply(bool listen = true);

private:
  Ui::MoleQueueWidget *m_ui;
  MoleQueue::JobObject m_jobTemplate;
  QString m_submissionError;
  int m_requestId;
  unsigned int m_moleQueueId;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_MOLEQUEUEWIDGET_H
