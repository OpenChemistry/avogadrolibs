/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_BATCHJOB_H
#define AVOGADRO_QTGUI_BATCHJOB_H

#include <QtCore/QObject>

#include "inputgenerator.h"

#include <avogadro/core/avogadrocore.h>

#include "client/jobobject.h"

#include <QtCore/QJsonObject>
#include <QtCore/QMap>
#include <QtCore/QVector>

namespace Avogadro {
namespace Core {
class Molecule;
} // end namespace Core

namespace MoleQueue {

/**
 * @brief The BatchJob class manages a collection of jobs that are configured
 * using the same InputGenerator and MoleQueue options. For use with
 * InputGeneratorDialog::configureBatchJob(BatchJob&).
 */
class AVOGADROMOLEQUEUE_EXPORT BatchJob : public QObject
{
  Q_OBJECT
public:
  /**
   * Job status. Same as those defined in molequeueglobal.h. The 'Rejected'
   * state is added to identify jobs that rejected by molequeue prior to having
   * a MoleQueue id (ServerId) set.
   */
  enum JobState
  {
    Rejected = -2,
    Unknown = -1,
    None = 0,
    Accepted,
    QueuedLocal,
    Submitted,
    QueuedRemote,
    RunningLocal,
    RunningRemote,
    Finished,
    Canceled,
    Error
  };

  /**
   * Type used to identify a job within this batch. Unique to this object.
   */
  typedef int BatchId;
  static const BatchId InvalidBatchId;

  /**
   * Type used to identify requests sent to the MoleQueue server.
   */
  typedef int RequestId;
  static const RequestId InvalidRequestId;

  /**
   * Type used by MoleQueue to identify jobs. Unique across the connected
   * MoleQueue server.
   */
  typedef unsigned int ServerId;
  static const ServerId InvalidServerId;

  /**
   * Construct a new BatchJob object. If provided, ese scriptFilePath to setup
   * the input generator.
   */
  explicit BatchJob(QObject* parent = nullptr);
  explicit BatchJob(const QString& scriptFilePath, QObject* parent = nullptr);
  ~BatchJob() override;

  /**
   * Options for the input generator.
   * @{
   */
  void setInputGeneratorOptions(const QJsonObject& opts);
  QJsonObject inputGeneratorOptions() const;
  /**@}*/

  /**
   * Options for MoleQueue.
   * @{
   */
  void setMoleQueueOptions(const QJsonObject& opts);
  QJsonObject moleQueueOptions() const;
  JobObject moleQueueJobTemplate() const;
  /**@}*/

  /**
   * The internal InputGenerator.
   * @{
   */
  const InputGenerator& inputGenerator() const;
  InputGenerator& inputGenerator();
  /**@}*/

  /**
   * A string that will be used in the MoleQueue interface to identify this
   * batch job. Taken from the InputGenerator configured title.
   */
  QString description() const;

  /**
   * @return The state of the job with the batch id @a batchId.
   */
  JobState jobState(BatchId batchId) const;

  /**
   * @return The server id of the job with the batch id @a batchId.
   */
  ServerId serverId(BatchId batchId) const;

  /**
   * @return The most recent JobObject for the job with the batch id @a batchId.
   * These are updated for each change in job state.
   */
  JobObject jobObject(BatchId batchId) const;

  /**
   * @return True if @a state corresponds to a job that is finished running.
   */
  static bool isTerminal(JobState state);

  /**
   * @return True if there are still running jobs.
   */
  bool hasUnfinishedJobs() const;

  /**
   * @return The number of jobs that are running.
   */
  int unfinishedJobCount() const;

  /**
   * @return The number of completed jobs.
   */
  int finishedJobCount() const;

  /**
   * @return The total number of jobs in the batch.
   */
  int jobCount() const;

public slots:
  /**
   * Submit a job using the current configuration for @a mol.
   * @return The BatchId of the job, or InvalidBatchId if there was an error.
   */
  virtual BatchId submitNextJob(const Core::Molecule& mol);

  /**
   * Request updated job details from the MoleQueue server for the job with
   * the batch id @a batchId.
   *
   * jobUpdated is emitted when the request is complete.
   *
   * @return True if the request is sent.
   */
  bool lookupJob(BatchId batchId);

signals:
  /**
   * Emitted when the reply from lookupJob is received. @a success will be false
   * if MoleQueue sends an error response (likely because the job was removed
   * from the job manager).
   */
  void jobUpdated(Avogadro::MoleQueue::BatchJob::BatchId batchId, bool success);

  /**
   * Emitted when the job associated with @a batchId completes. @a status
   * is the final state of the jobs and can be used to determine whether or not
   * the job finished successfully.
   */
  void jobCompleted(Avogadro::MoleQueue::BatchJob::BatchId batchId,
                    Avogadro::MoleQueue::BatchJob::JobState status);

private slots:
  void handleSubmissionReply(int requestId, unsigned int serverId);
  void handleJobStateChange(unsigned int serverId, const QString& oldState,
                            const QString& newState);
  void handleLookupJobReply(int requestId, const QJsonObject& jobInfo);
  void handleErrorResponse(int requestId, int errorCode,
                           const QString& errorMessage,
                           const QJsonValue& errorData);

private: // structs
  /**
   * Internal struct for tracking request metadata.
   */
  struct Request
  {
    enum Type
    {
      InvalidType,
      SubmitJob,
      LookupJob
    };
    explicit Request(Type t = InvalidType, BatchId b = InvalidBatchId);
    bool isValid() const { return type != InvalidType; }

    Type type;
    BatchId batchId;
  };

private: // methods
  void setup();
  static JobState stringToState(const QString& string);
  static QString stateToString(JobState state);

private: // variables
  InputGenerator m_inputGenerator;
  QJsonObject m_inputGeneratorOptions;
  QJsonObject m_moleQueueOptions;

  /// Cached job states.
  QList<JobObject> m_jobObjects;
  /// Lookup batch ids from server ids.
  QMap<ServerId, BatchId> m_serverIds;
  /// Job states. For fast lookups without string conversions.
  QVector<JobState> m_states;
  /// Pending requests.
  QMap<RequestId, Request> m_requests;
};

inline BatchJob::Request::Request(Type t, BatchId b) : type(t), batchId(b)
{
}

inline void BatchJob::setInputGeneratorOptions(const QJsonObject& opts)
{
  m_inputGeneratorOptions = opts;
}

inline QJsonObject BatchJob::inputGeneratorOptions() const
{
  return m_inputGeneratorOptions;
}

inline void BatchJob::setMoleQueueOptions(const QJsonObject& opts)
{
  m_moleQueueOptions = opts;
}

inline QJsonObject BatchJob::moleQueueOptions() const
{
  return m_moleQueueOptions;
}

inline JobObject BatchJob::moleQueueJobTemplate() const
{
  JobObject result;
  result.fromJson(m_moleQueueOptions);
  return result;
}

inline const InputGenerator& BatchJob::inputGenerator() const
{
  return m_inputGenerator;
}

inline InputGenerator& BatchJob::inputGenerator()
{
  return m_inputGenerator;
}

inline QString BatchJob::description() const
{
  return moleQueueJobTemplate().description();
}

inline BatchJob::JobState BatchJob::jobState(BatchJob::BatchId id) const
{
  return id < m_states.size() ? m_states[id] : Unknown;
}

inline BatchJob::ServerId BatchJob::serverId(BatchJob::BatchId id) const
{
  return id < m_jobObjects.size()
           ? m_jobObjects[id]
               .value("moleQueueId", InvalidServerId)
               .value<ServerId>()
           : InvalidServerId;
}

inline JobObject BatchJob::jobObject(BatchJob::BatchId id) const
{
  return id < m_jobObjects.size() ? m_jobObjects[id] : JobObject();
}

inline bool BatchJob::isTerminal(BatchJob::JobState state)
{
  switch (state) {
    case Rejected:
    case Finished:
    case Canceled:
    case Error:
      return true;
    default:
      return false;
  }
}

inline bool BatchJob::hasUnfinishedJobs() const
{
  for (QVector<JobState>::const_iterator it = m_states.begin(),
                                         itEnd = m_states.end();
       it != itEnd; ++it) {
    if (!isTerminal(*it))
      return true;
  }
  return false;
}

inline int BatchJob::unfinishedJobCount() const
{
  int result = 0;
  for (QVector<JobState>::const_iterator it = m_states.begin(),
                                         itEnd = m_states.end();
       it != itEnd; ++it) {
    if (!isTerminal(*it))
      ++result;
  }
  return result;
}

inline int BatchJob::finishedJobCount() const
{
  int result = 0;
  for (QVector<JobState>::const_iterator it = m_states.begin(),
                                         itEnd = m_states.end();
       it != itEnd; ++it) {
    if (isTerminal(*it))
      ++result;
  }
  return result;
}

inline int BatchJob::jobCount() const
{
  return m_serverIds.size();
}

inline BatchJob::JobState BatchJob::stringToState(const QString& str)
{
  if (str == QLatin1String("None"))
    return None;
  else if (str == QLatin1String("Rejected"))
    return Rejected;
  else if (str == QLatin1String("Accepted"))
    return Accepted;
  else if (str == QLatin1String("QueuedLocal"))
    return QueuedLocal;
  else if (str == QLatin1String("Submitted"))
    return Submitted;
  else if (str == QLatin1String("QueuedRemote"))
    return QueuedRemote;
  else if (str == QLatin1String("RunningLocal"))
    return RunningLocal;
  else if (str == QLatin1String("RunningRemote"))
    return RunningRemote;
  else if (str == QLatin1String("Finished"))
    return Finished;
  else if (str == QLatin1String("Canceled"))
    return Canceled;
  else if (str == QLatin1String("Error"))
    return Error;
  else
    return Unknown;
}

inline QString BatchJob::stateToString(BatchJob::JobState state)
{
  switch (state) {
    case None:
      return QString("None");
    case Accepted:
      return QString("Accepted");
    case Rejected:
      return QString("Rejected");
    case QueuedLocal:
      return QString("QueuedLocal");
    case Submitted:
      return QString("Submitted");
    case QueuedRemote:
      return QString("QueuedRemote");
    case RunningLocal:
      return QString("RunningLocal");
    case RunningRemote:
      return QString("RunningRemote");
    case Finished:
      return QString("Finished");
    case Canceled:
      return QString("Canceled");
    case Error:
      return QString("Error");
    default:
    case Unknown:
      return QString("Unknown");
  }
}

} // namespace MoleQueue
} // namespace Avogadro

#endif // AVOGADRO_MOLEQUEUE_BATCHJOB_H
