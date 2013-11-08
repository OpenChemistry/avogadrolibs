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

#ifndef AVOGADRO_QTGUI_BATCHJOB_H
#define AVOGADRO_QTGUI_BATCHJOB_H

#include <QtCore/QObject>
#include "avogadroqtguiexport.h"

#include <avogadro/qtgui/inputgenerator.h>

#include <avogadro/core/avogadrocore.h>

#include <molequeue/client/jobobject.h>

#include <qjsonobject.h>

#include <QtCore/QMap>
#include <QtCore/QVector>

namespace Avogadro {
namespace Core {
class Molecule;
} // end namespace Core

namespace QtGui {

class AVOGADROQTGUI_EXPORT BatchJob : public QObject
{
  Q_OBJECT
public:
  /**
   * Job status. Same as those defined in molequeueglobal.h. The 'Rejected'
   * state is added to identify jobs that rejected by molequeue prior to having
   * a MoleQueue id (ServerId) set.
   */
  enum JobState {
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

  explicit BatchJob(QObject *parent = NULL);
  explicit BatchJob(const QString &scriptFilePath, QObject *parent = NULL);
  ~BatchJob() AVO_OVERRIDE;

  BatchId submitNextJob(const Core::Molecule &mol);

  void setInputGeneratorOptions(const QJsonObject &opts);
  QJsonObject inputGeneratorOptions() const;

  void setMoleQueueOptions(const QJsonObject &opts);
  QJsonObject moleQueueOptions() const;

  const InputGenerator &inputGenerator() const;
  InputGenerator &inputGenerator();

  JobState jobState(BatchId batchId) const;
  ServerId serverId(BatchId batchId) const;
  static bool isTerminal(JobState state);
  bool hasUnfinishedJobs() const;

public slots:
  bool lookupJob(BatchId batchId); // (async, signal: jobUpdated(batchId))

signals:
  void jobUpdated(BatchId batchId, bool success);

private slots:
  void handleSubmissionReply(int requestId, unsigned int serverId);
  void handleJobStateChange(unsigned int serverId, const QString &oldState,
                            const QString &newState);
  void handleLookupJobReply(int requestId, const QJsonObject &jobInfo);
  void handleErrorResponse(int requestId, int errorCode,
                           const QString &errorMessage,
                           const QJsonValue &errorData);

private: // structs
  /**
   * Internal struct for tracking request metadata.
   */
  struct Request
  {
    enum Type {
      InvalidType,
      SubmitJob,
      LookupJob
    };
    explicit Request(Type t = InvalidType, BatchId b = InvalidBatchId);
    Request(const Request &o) : type(o.type), batchId(o.batchId) {}
    Request& operator=(Request other)
    {
      using std::swap;
      swap(*this, other);
      return *this;
    }
    friend void swap(Request &lhs, Request &rhs)
    {
      using std::swap;
      swap(lhs.type, rhs.type);
      swap(lhs.batchId, rhs.batchId);
    }
    bool isValid() const { return type != InvalidType; }

    Type type;
    BatchId batchId;
  };

private: // methods
  void setup();
  static JobState stringToState(const QString &string);
  static QString stateToString(JobState state);

private: // variables
  InputGenerator m_inputGenerator;
  QJsonObject m_inputGeneratorOptions;
  QJsonObject m_moleQueueOptions;

  /// Cached job states.
  QList<MoleQueue::JobObject> m_jobObjects;
  /// Lookup batch ids from server ids.
  QMap<ServerId, BatchId> m_serverIds;
  /// Job states. For fast lookups without string conversions.
  QVector<JobState> m_states;
  /// Pending requests.
  QMap<RequestId, Request> m_requests;
};

inline BatchJob::BatchJob::Request::Request(Type t, BatchId b) : type(t), batchId(b) {}

inline void BatchJob::setInputGeneratorOptions(const QJsonObject &opts)
{
  m_inputGeneratorOptions = opts;
}

inline QJsonObject BatchJob::inputGeneratorOptions() const
{
  return m_inputGeneratorOptions;
}

inline void BatchJob::setMoleQueueOptions(const QJsonObject &opts)
{
  m_moleQueueOptions = opts;
}

inline QJsonObject BatchJob::moleQueueOptions() const
{
  return m_moleQueueOptions;
}

inline const InputGenerator &BatchJob::inputGenerator() const
{
  return m_inputGenerator;
}

inline InputGenerator &BatchJob::inputGenerator()
{
  return m_inputGenerator;
}

inline BatchJob::JobState BatchJob::jobState(BatchJob::BatchId id) const
{
  return id < m_states.size() ? m_states[id] : Unknown;
}

inline BatchJob::ServerId BatchJob::serverId(BatchJob::BatchId id) const
{
  return id < m_jobObjects.size()
      ? m_jobObjects[id].value("moleQueueId", InvalidServerId).value<ServerId>()
      : InvalidServerId;
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
       itEnd = m_states.end(); it != itEnd; ++it) {
    if (!isTerminal(*it))
      return false;
  }
  return true;
}

inline BatchJob::JobState BatchJob::stringToState(const QString &str)
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

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_BATCHJOB_H
