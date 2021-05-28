/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "batchjob.h"
#include "molequeuemanager.h"

#include <QtCore/QDebug>

#include <limits>

namespace Avogadro {
namespace MoleQueue {

// initialize statics
const BatchJob::BatchId BatchJob::InvalidBatchId = -1;
const BatchJob::RequestId BatchJob::InvalidRequestId = -1;
const BatchJob::ServerId BatchJob::InvalidServerId =
  std::numeric_limits<BatchJob::ServerId>::max();

BatchJob::BatchJob(QObject* par) : QObject(par)
{
  setup();
}

BatchJob::BatchJob(const QString& scriptFilePath, QObject* par)
  : QObject(par), m_inputGenerator(scriptFilePath)
{
  setup();
}

BatchJob::~BatchJob()
{
}

BatchJob::BatchId BatchJob::submitNextJob(const Core::Molecule& mol)
{
  // Is everything configured?
  if (!m_inputGenerator.isValid() || m_inputGeneratorOptions.empty() ||
      m_moleQueueOptions.empty()) {
    return InvalidBatchId;
  }

  // Verify that molequeue is running:
  MoleQueueManager& mqManager = MoleQueueManager::instance();
  if (!mqManager.connectIfNeeded())
    return InvalidBatchId;

  // Generate the input:
  if (!m_inputGenerator.generateInput(m_inputGeneratorOptions, mol)) {
    if (!m_inputGenerator.errorList().isEmpty()) {
      qWarning() << "BatchJob::submitNextJob() error:\n\t"
                 << m_inputGenerator.errorList().join("\n\t");
    }
    return InvalidBatchId;
  }

  // Warnings are non-fatal -- just print them for now:
  if (!m_inputGenerator.warningList().isEmpty()) {
    qWarning() << "BatchJob::submitNextJob() warning:\n\t"
               << m_inputGenerator.warningList().join("\n\t");
  }

  BatchId bId = m_jobObjects.size();

  // Create the job object:
  JobObject job;
  job.fromJson(m_moleQueueOptions);
  job.setDescription(
    tr("Batch Job #%L1 (%2)").arg(bId + 1).arg(job.description()));

  // Main input file:
  const QString mainFileName = m_inputGenerator.mainFileName();
  job.setInputFile(mainFileName, m_inputGenerator.fileContents(mainFileName));

  // Any additional input files:
  QStringList fileNames = m_inputGenerator.fileNames();
  fileNames.removeOne(mainFileName);
  foreach (const QString& fn, fileNames)
    job.appendAdditionalInputFile(fn, m_inputGenerator.fileContents(fn));

  // Submit the job
  RequestId rId = mqManager.client().submitJob(job);

  // Was submission successful?
  if (rId < 0)
    return InvalidBatchId;

  // Register the job and assign the ID.
  m_jobObjects.push_back(job);
  m_states.push_back(None);
  m_requests.insert(rId, Request(Request::SubmitJob, bId));

  return bId;
}

bool BatchJob::lookupJob(BatchId bId)
{
  ServerId sId = serverId(static_cast<BatchId>(bId));
  if (sId == InvalidServerId)
    return false;

  // Verify that molequeue is running:
  MoleQueueManager& mqManager = MoleQueueManager::instance();
  if (!mqManager.connectIfNeeded())
    return false;

  Client& client = mqManager.client();
  RequestId rId = client.lookupJob(sId);
  m_requests.insert(rId, Request(Request::LookupJob, bId));
  return true;
}

void BatchJob::handleSubmissionReply(int rId, unsigned int sId)
{
  Request req = m_requests.value(rId);
  if (req.isValid()) {
    m_requests.remove(rId);
    if (req.batchId >= m_jobObjects.size()) {
      qWarning() << "BatchJob::handleSubmissionReply(): batchID out of range.";
      return;
    }
    m_jobObjects[req.batchId].setValue("moleQueueId",
                                       QVariant(static_cast<ServerId>(sId)));
    m_serverIds.insert(sId, req.batchId);
    // Request full job details:
    lookupJob(req.batchId);
  }
}

void BatchJob::handleJobStateChange(unsigned int sId, const QString&,
                                    const QString&)
{
  BatchId bId = m_serverIds.value(static_cast<ServerId>(sId), InvalidBatchId);
  if (bId == InvalidBatchId)
    return;
  // Update full job details:
  lookupJob(bId);
}

void BatchJob::handleLookupJobReply(int rId, const QJsonObject& jobInfo)
{
  Request req = m_requests.value(rId);
  if (req.isValid()) {
    m_requests.remove(rId);
    if (req.batchId >= m_jobObjects.size()) {
      qWarning() << "BatchJob::handleSubmissionReply(): batchID out of range.";
      return;
    }
    JobObject& job(m_jobObjects[req.batchId]);
    job.fromJson(jobInfo);

    JobState oldState = m_states[req.batchId];
    JobState newState = stringToState(job.value("jobState").toString());
    m_states[req.batchId] = newState;
    emit jobUpdated(req.batchId, true);
    if (!isTerminal(oldState) && isTerminal(newState))
      emit jobCompleted(req.batchId, newState);
  }
}

void BatchJob::handleErrorResponse(int requestId, int errorCode,
                                   const QString& errorMessage,
                                   const QJsonValue& errorData)
{
  qDebug() << "Error rcv'd: {"
           << "requestId:" << requestId << "errorCode:" << errorCode
           << "errorMessage:" << errorMessage << "errorData:" << errorData
           << "}";

  Request req = m_requests.value(requestId);

  if (!req.isValid())
    return;

  m_requests.remove(requestId);

  if (req.batchId < m_jobObjects.size())
    return;

  switch (req.type) {
    case Request::SubmitJob:
      // The job was rejected:
      qDebug() << "Batch job" << req.batchId << "was rejected by MoleQueue.";
      m_states[req.batchId] = Rejected;
      m_jobObjects[req.batchId].fromJson(QJsonObject());
      break;
    case Request::LookupJob:
      qDebug() << "Batch job" << req.batchId << "failed to update.";
      emit jobUpdated(req.batchId, false);
      break;
    default:
    case Request::InvalidType:
      break;
  }
}

void BatchJob::setup()
{
  static bool metaTypesRegistered = false;
  if (!metaTypesRegistered) {
    qRegisterMetaType<BatchId>("Avogadro::QtGui::BatchJob::BatchId");
    qRegisterMetaType<BatchId>("BatchId");
    qRegisterMetaType<ServerId>("Avogadro::QtGui::BatchJob::ServerId");
    qRegisterMetaType<ServerId>("ServerId");
    qRegisterMetaType<RequestId>("Avogadro::QtGui::BatchJob::RequestId");
    qRegisterMetaType<RequestId>("RequestId");
    metaTypesRegistered = true;
  }

  MoleQueueManager& mqManager = MoleQueueManager::instance();
  Client& client = mqManager.client();
  connect(&client, SIGNAL(submitJobResponse(int, uint)),
          SLOT(handleSubmissionReply(int, uint)));
  connect(&client, SIGNAL(lookupJobResponse(int, QJsonObject)),
          SLOT(handleLookupJobReply(int, QJsonObject)));
  connect(&client, SIGNAL(jobStateChanged(uint, QString, QString)),
          SLOT(handleJobStateChange(uint, QString, QString)));
  connect(&client, SIGNAL(errorReceived(int, int, QString, QJsonValue)),
          SLOT(handleErrorResponse(int, int, QString, QJsonValue)));
}

} // namespace MoleQueue
} // namespace Avogadro
