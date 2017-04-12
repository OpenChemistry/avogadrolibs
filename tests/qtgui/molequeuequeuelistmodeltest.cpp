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

#include <gtest/gtest.h>

#include <avogadro/molequeue/molequeuequeuelistmodel.h>

#include <QtCore/QListIterator>

using Avogadro::MoleQueue::MoleQueueQueueListModel;

// Allow access to protected members (like ctor, setQueueList)
class MoleQueueQueueListModelTestBridge
{
private:
  MoleQueueQueueListModel m_model;

public:
  MoleQueueQueueListModel& model() { return m_model; }

  void setQueueList(QList<QString> queueList, QList<QStringList> programList)
  {
    m_model.setQueueList(queueList, programList);
  }
};

namespace {

// Populate the model with a testing set of queues and programs. The queues and
// programs arguments will be overwritten by the data set in the model.
// Queues are named "Queue M", where M is in the range (0, numQueues].
// Programs are named "QMPN", where M is the queue id, and N is the program id.
// The number of programs is determined by N = ((M+3) * (M+2)) % 5 + 2.
void populateModel(MoleQueueQueueListModelTestBridge& model, int numQueues,
                   QStringList& queues, QList<QStringList>& programs)
{
  queues.clear();
  programs.clear();
  for (int queueId = 1; queueId <= numQueues; ++queueId) {
    queues.append(QString("Queue %1").arg(queueId));
    programs.append(QStringList());
    QStringList& programList = programs.back();
    const int numPrograms = ((queueId + 3) * (queueId + 2)) % 5 + 2;
    for (int programId = 1; programId <= numPrograms; ++programId)
      programList.append(QString("Q%1P%2").arg(queueId).arg(programId));
  }
  model.setQueueList(queues, programs);
}

} // end anon namespace

TEST(MoleQueueQueueListModelTest, setQueues)
{
  MoleQueueQueueListModelTestBridge modelBridge;
  MoleQueueQueueListModel& model = modelBridge.model();
  QStringList refQueues;
  QList<QStringList> refPrograms;
  populateModel(modelBridge, 10, refQueues, refPrograms);

  EXPECT_EQ(10, model.queues().size());
  EXPECT_EQ(refQueues, model.queues());

  QListIterator<QString> queueIter(refQueues);
  QListIterator<QStringList> programIter(refPrograms);
  while (queueIter.hasNext() && programIter.hasNext())
    EXPECT_EQ(programIter.next(), model.programs(queueIter.next()));
  EXPECT_FALSE(programIter.hasNext() || queueIter.hasNext())
    << "queue/program size mismatch.";
}

TEST(MoleQueueQueueListModelTest, findQueueIndices)
{
  MoleQueueQueueListModelTestBridge modelBridge;
  MoleQueueQueueListModel& model = modelBridge.model();
  QStringList refQueues;
  QList<QStringList> refPrograms;
  populateModel(modelBridge, 10, refQueues, refPrograms);

  QModelIndexList matches = model.findQueueIndices("Queue 7");
  EXPECT_EQ(1, matches.size());
  EXPECT_EQ(
    model.data(matches.front(), Qt::DisplayRole).toString().toStdString(),
    std::string("Queue 7"));
}

TEST(MoleQueueQueueListModelTest, findProgramIndices)
{
  MoleQueueQueueListModelTestBridge modelBridge;
  MoleQueueQueueListModel& model = modelBridge.model();
  QStringList refQueues;
  QList<QStringList> refPrograms;
  populateModel(modelBridge, 10, refQueues, refPrograms);

  QModelIndexList matches = model.findProgramIndices("Q7P2");
  EXPECT_EQ(1, matches.size());
  EXPECT_EQ(
    model.data(matches.front(), Qt::DisplayRole).toString().toStdString(),
    std::string("Q7P2"));

  // All 10 queues should have a program #2:
  matches = model.findProgramIndices("P2");
  EXPECT_EQ(10, matches.size());

  // Should match programs from queue 1 and 10:
  matches = model.findProgramIndices("P2", "Queue 1");
  EXPECT_EQ(2, matches.size());

  // nothing should match this
  matches = model.findProgramIndices("No match");
  EXPECT_EQ(0, matches.size());
}

TEST(MoleQueueQueueListModelTest, lookupProgram)
{
  MoleQueueQueueListModelTestBridge modelBridge;
  MoleQueueQueueListModel& model = modelBridge.model();
  QStringList refQueues;
  QList<QStringList> refPrograms;
  populateModel(modelBridge, 10, refQueues, refPrograms);

  QModelIndexList matches = model.findProgramIndices("Q7P2");
  EXPECT_EQ(1, matches.size());
  QString queue;
  QString program;
  EXPECT_TRUE(model.lookupProgram(matches.front(), queue, program));
  EXPECT_EQ(std::string("Queue 7"), queue.toStdString());
  EXPECT_EQ(std::string("Q7P2"), program.toStdString());
}
