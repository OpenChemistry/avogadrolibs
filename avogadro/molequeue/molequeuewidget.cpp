/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molequeuewidget.h"
#include "ui_molequeuewidget.h"

#include "molequeuemanager.h"

#include <QtWidgets/QMessageBox>

#include <QtCore/QTimer>

#include <limits>

namespace Avogadro {
namespace MoleQueue {

const unsigned int MoleQueueWidget::InvalidMoleQueueId(
  std::numeric_limits<unsigned int>::max());

MoleQueueWidget::MoleQueueWidget(QWidget* parent_)
  : QWidget(parent_), m_ui(new Ui::MoleQueueWidget), m_jobState("Unknown"),
    m_requestId(-1), m_moleQueueId(InvalidMoleQueueId)
{
  m_ui->setupUi(this);

  connect(m_ui->refreshProgramsButton, SIGNAL(clicked()),
          SLOT(refreshPrograms()));

  MoleQueueManager& mqManager = MoleQueueManager::instance();
  m_ui->queueListView->setModel(&mqManager.queueListModel());

  if (mqManager.connectIfNeeded())
    mqManager.requestQueueList();
}

MoleQueueWidget::~MoleQueueWidget()
{
  delete m_ui;
}

JobObject& MoleQueueWidget::jobTemplate()
{
  return m_jobTemplate;
}

const JobObject& MoleQueueWidget::jobTemplate() const
{
  return m_jobTemplate;
}

void MoleQueueWidget::setJobTemplate(const JobObject& job)
{
  m_jobTemplate = job;

  m_ui->numberOfCores->setValue(job.value("numberOfCores", 1).toInt());
  m_ui->cleanRemoteFiles->setChecked(
    job.value("cleanRemoteFiles", false).toBool());
  m_ui->hideFromGui->setChecked(job.value("hideFromGui", false).toBool());
  m_ui->popupOnStateChange->setChecked(
    job.value("popupOnStateChange", false).toBool());
}

void MoleQueueWidget::refreshPrograms()
{
  MoleQueueManager& mqManager = MoleQueueManager::instance();
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
  m_jobState = "Unknown";
  m_requestId = -1;
  m_moleQueueId = InvalidMoleQueueId;

  MoleQueueManager& mqManager = MoleQueueManager::instance();
  if (!mqManager.connectIfNeeded())
    return -1;

  MoleQueue::JobObject job(configuredJob());
  if (job.queue().isEmpty()) // if the queue is not set, the job config failed.
    return -1;

  m_requestId = mqManager.client().submitJob(job);
  if (m_requestId >= 0) {
    listenForJobSubmitReply();
    listenForJobStateChange();
  } else {
    m_submissionError = tr("Client failed to submit job to MoleQueue.");
    // Single shot ensures that this signal is emitted after control returns
    // to the event loop
    QTimer::singleShot(0, this, SIGNAL(jobSubmitted(false)));
  }
  return m_requestId;
}

void MoleQueueWidget::showAndSelectProgram(const QString& programName)
{
  MoleQueueManager& mqManager = MoleQueueManager::instance();
  setProperty("selectProgramName", programName);

  connect(&mqManager, SIGNAL(queueListUpdated()),
          SLOT(showAndSelectProgramHandler()));

  if (mqManager.connectIfNeeded())
    mqManager.requestQueueList();
}

bool MoleQueueWidget::openOutput() const
{
  return m_ui->openOutput->isChecked();
}

bool MoleQueueWidget::requestJobLookup()
{
  MoleQueueManager& mqManager = MoleQueueManager::instance();
  if (m_moleQueueId != InvalidMoleQueueId && mqManager.connectIfNeeded()) {
    listenForLookupJobReply();
    int reqId = mqManager.client().lookupJob(m_moleQueueId);
    setProperty("lookupJobRequestId", reqId);
    return true;
  }
  return false;
}

MoleQueue::JobObject MoleQueueWidget::configuredJob() const
{
  MoleQueueManager& mqManager = MoleQueueManager::instance();

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
    QMessageBox::critical(parentWidget(), tr("Internal error."),
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

void MoleQueueWidget::setBatchMode(bool batch)
{
  m_ui->openOutput->setHidden(batch);
  m_ui->openOutputLabel->setHidden(batch);
}

bool MoleQueueWidget::batchMode() const
{
  return m_ui->openOutput->isHidden();
}

void MoleQueueWidget::showAndSelectProgramHandler()
{
  MoleQueueManager& mqManager = MoleQueueManager::instance();
  const QString program(property("selectProgramName").toString());
  setProperty("selectProgramName", QVariant());
  disconnect(&mqManager, SIGNAL(queueListUpdated()), this,
             SLOT(showAndSelectProgramHandler()));

  // Get all program nodes that match the name
  QModelIndexList list(mqManager.queueListModel().findProgramIndices(program));

  // Expand the corresponding queues
  foreach (const QModelIndex& mi, list)
    m_ui->queueListView->expand(mi.parent());

  // Select the first entry
  if (!list.isEmpty()) {
    m_ui->queueListView->selectionModel()->select(
      list.first(), QItemSelectionModel::ClearAndSelect);
    m_ui->queueListView->scrollTo(list.first());
  }
}

void MoleQueueWidget::onLookupJobReply(int reqId, const QJsonObject& result)
{
  QVariant reqIdVariant(property("lookupJobRequestId"));
  bool ok;
  int myReqId = reqIdVariant.toInt(&ok);
  if (ok && reqId == myReqId) {
    setProperty("lookupJobRequestId", QVariant());
    listenForLookupJobReply(false);
    MoleQueue::JobObject job;
    job.fromJson(result);
    emit jobUpdated(job);
  }
}

void MoleQueueWidget::onSubmissionSuccess(int localId, unsigned int mqId)
{
  if (localId != m_requestId)
    return;

  listenForJobSubmitReply(false);
  m_moleQueueId = mqId;
  emit jobSubmitted(true);
}

void MoleQueueWidget::onSubmissionFailure(int localId, unsigned int,
                                          const QString& error)
{
  if (localId != m_requestId)
    return;

  listenForJobSubmitReply(false);
  m_submissionError = error;
  emit jobSubmitted(false);
}

void MoleQueueWidget::onJobStateChange(unsigned int mqId, const QString&,
                                       const QString& newState)
{
  if (mqId != m_moleQueueId)
    return;

  m_jobState = newState;

  if (m_jobState == QLatin1String("Finished")) {
    listenForJobStateChange(false);
    emit jobFinished(true);
  } else if (m_jobState == QLatin1String("Error") ||
             m_jobState == QLatin1String("Canceled")) {
    listenForJobStateChange(false);
    emit jobFinished(false);
  }
}

void MoleQueueWidget::listenForLookupJobReply(bool listen)
{
  Client& mqClient(MoleQueueManager::instance().client());
  if (listen) {
    connect(&mqClient, SIGNAL(lookupJobResponse(int, QJsonObject)), this,
            SLOT(onLookupJobReply(int, QJsonObject)));
  } else {
    disconnect(&mqClient, SIGNAL(lookupJobResponse(int, QJsonObject)), this,
               SLOT(onLookupJobReply(int, QJsonObject)));
  }
}

void MoleQueueWidget::listenForJobSubmitReply(bool listen)
{
  MoleQueue::Client& mqClient(MoleQueueManager::instance().client());

  if (listen) {
    connect(&mqClient, SIGNAL(submitJobResponse(int, uint)), this,
            SLOT(onSubmissionSuccess(int, uint)));
    connect(&mqClient, SIGNAL(errorReceived(int, uint, QString)), this,
            SLOT(onSubmissionFailure(int, uint, QString)));
  } else {
    disconnect(&mqClient, SIGNAL(submitJobResponse(int, uint)), this,
               SLOT(onSubmissionSuccess(int, uint)));
    disconnect(&mqClient, SIGNAL(errorReceived(int, uint, QString)), this,
               SLOT(onSubmissionFailure(int, uint, QString)));
  }
}

void MoleQueueWidget::listenForJobStateChange(bool listen)
{
  MoleQueue::Client& mqClient(MoleQueueManager::instance().client());

  if (listen) {
    connect(&mqClient, SIGNAL(jobStateChanged(uint, QString, QString)), this,
            SLOT(onJobStateChange(uint, QString, QString)));
  } else {
    disconnect(&mqClient, SIGNAL(jobStateChanged(uint, QString, QString)), this,
               SLOT(onJobStateChange(uint, QString, QString)));
  }
}

bool MoleQueueWidget::programSelected()
{
  QModelIndexList sel(m_ui->queueListView->selectionModel()->selectedIndexes());
  return sel.size() > 0;
}

} // namespace MoleQueue
} // namespace Avogadro
