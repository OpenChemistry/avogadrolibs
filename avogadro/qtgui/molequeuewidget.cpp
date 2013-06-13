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

#include "molequeuewidget.h"
#include "ui_molequeuewidget.h"

#include <avogadro/qtgui/molequeuemanager.h>

#include <QtGui/QMessageBox>

#include <QtCore/QTimer>

namespace Avogadro {
namespace QtGui {

MoleQueueWidget::MoleQueueWidget(QWidget *parent_) :
  QWidget(parent_),
  m_ui(new Ui::MoleQueueWidget),
  m_requestId(-1),
  m_moleQueueId(InvalidMoleQueueId)
{
  m_ui->setupUi(this);

  connect(m_ui->refreshProgramsButton, SIGNAL(clicked()),
          SLOT(refreshPrograms()));

  MoleQueueManager &mqManager = MoleQueueManager::instance();
  m_ui->queueListView->setModel(&mqManager.queueListModel());

  if (mqManager.connectIfNeeded())
    mqManager.requestQueueList();
}

MoleQueueWidget::~MoleQueueWidget()
{
  delete m_ui;
}

MoleQueue::JobObject &MoleQueueWidget::jobTemplate()
{
  return m_jobTemplate;
}

const MoleQueue::JobObject &MoleQueueWidget::jobTemplate() const
{
  return m_jobTemplate;
}

void MoleQueueWidget::setJobTemplate(const MoleQueue::JobObject &job)
{
  m_jobTemplate = job;

  m_ui->numberOfCores->setValue(job.value("numberOfCores", 1).toInt());
  m_ui->cleanRemoteFiles->setChecked(job.value("cleanRemoteFiles",
                                               false).toBool());
  m_ui->hideFromGui->setChecked(job.value("hideFromGui",
                                          false).toBool());
  m_ui->popupOnStateChange->setChecked(job.value("popupOnStateChange",
                                                 false).toBool());
}

void MoleQueueWidget::refreshPrograms()
{
  MoleQueueManager &mqManager = MoleQueueManager::instance();
  if (!mqManager.connectIfNeeded()) {
    QMessageBox::information(this, tr("Cannot connect to MoleQueue"),
                             tr("Cannot connect to MoleQueue server. Please "
                                "ensure that it is running and try again."));
    return;
  }
  mqManager.requestQueueList();
}

int MoleQueueWidget::submitJobRequest()
{
  m_submissionError.clear();
  m_requestId = -1;
  m_moleQueueId = InvalidMoleQueueId;

  MoleQueueManager &mqManager = MoleQueueManager::instance();
  if (!mqManager.connectIfNeeded())
    return -1;

  MoleQueue::JobObject job(configuredJob());
  if (job.queue().isEmpty()) // if the queue is not set, the job config failed.
    return -1;

  m_requestId = mqManager.client().submitJob(job);
  if (m_requestId >= 0) {
    listenForReply();
  }
  else {
    m_submissionError = tr("Client failed to submit job to MoleQueue.");
    // Single shot ensures that this signal is emitted after control returns
    // to the event loop
    QTimer::singleShot(0, this, SIGNAL(jobSubmitted(false)));
  }
  return m_requestId;
}

void MoleQueueWidget::showAndSelectProgram(const QString &programName)
{
  MoleQueueManager &mqManager = MoleQueueManager::instance();
  setProperty("selectProgramName", programName);

  connect(&mqManager, SIGNAL(queueListUpdated()),
          SLOT(showAndSelectProgramHandler()));

  if (mqManager.connectIfNeeded())
    mqManager.requestQueueList();
}

MoleQueue::JobObject MoleQueueWidget::configuredJob() const
{
  MoleQueueManager &mqManager = MoleQueueManager::instance();

  // get queue/program
  QModelIndexList sel(m_ui->queueListView->selectionModel()->selectedIndexes());
  if (sel.size() < 1) {
    QMessageBox::information(parentWidget(), tr("No program selected."),
                             tr("Please select the target program from the "
                                "\"Queue and Program\" list."));
    return MoleQueue::JobObject();
  }

  QString queue;
  QString program;
  if (!mqManager.queueListModel().lookupProgram(sel.first(), queue, program)) {
    QMessageBox::critical(parentWidget(),
                          tr("Internal error."),
                          tr("Unable to resolve program selection. This is "
                             "a bug."));
    return MoleQueue::JobObject();
  }

  MoleQueue::JobObject job(m_jobTemplate);
  job.setQueue(queue);
  job.setProgram(program);
  job.setValue("numberOfCores", m_ui->numberOfCores->value());
  job.setValue("cleanRemoteFiles", m_ui->cleanRemoteFiles->isChecked());
  job.setValue("hideFromGui", m_ui->hideFromGui->isChecked());
  job.setValue("popupOnStateChange", m_ui->popupOnStateChange->isChecked());

  return job;
}

void MoleQueueWidget::showAndSelectProgramHandler()
{
  MoleQueueManager &mqManager = MoleQueueManager::instance();
  const QString program(property("selectProgramName").toString());
  setProperty("selectProgramName", QVariant());
  disconnect(&mqManager, SIGNAL(queueListUpdated()),
             this, SLOT(showAndSelectProgramHandler()));

  // Get all program nodes that match the name
  QModelIndexList list(mqManager.queueListModel().findProgramIndices(program));

  // Expand the corresponding queues
  foreach (const QModelIndex &mi, list)
    m_ui->queueListView->expand(mi.parent());

  // Select the first entry
  if (!list.isEmpty()) {
    m_ui->queueListView->selectionModel()->select(
          list.first(), QItemSelectionModel::ClearAndSelect);
    m_ui->queueListView->scrollTo(list.first());
  }
}

void MoleQueueWidget::onSubmissionSuccess(int localId, unsigned int mqId)
{
  if (localId != m_requestId)
    return;

  listenForReply(false);
  m_moleQueueId = mqId;
  emit jobSubmitted(true);
}

void MoleQueueWidget::onSubmissionFailure(int localId, unsigned int,
                                          const QString &error)
{
  if (localId != m_requestId)
    return;

  listenForReply(false);
  m_submissionError = error;
  emit jobSubmitted(false);
}

void MoleQueueWidget::listenForReply(bool listen)
{
  MoleQueue::Client &mqClient(MoleQueueManager::instance().client());

  if (listen) {
    connect(&mqClient, SIGNAL(submitJobResponse(int,uint)),
            this, SLOT(onSubmissionSuccess(int,uint)));
    connect(&mqClient, SIGNAL(errorReceived(int,uint,QString)),
            this, SLOT(onSubmissionFailure(int,uint,QString)));
  }
  else {
    disconnect(&mqClient, SIGNAL(submitJobResponse(int,uint)),
               this, SLOT(onSubmissionSuccess(int,uint)));
    disconnect(&mqClient, SIGNAL(errorReceived(int,uint,QString)),
               this, SLOT(onSubmissionFailure(int,uint,QString)));
  }
}

} // namespace QtGui
} // namespace Avogadro
