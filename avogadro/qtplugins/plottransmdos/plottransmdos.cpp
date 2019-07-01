/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "plottransmdos.h"

#include "plottransmdosdialog.h"

#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/io/fileformat.h>

#include <molequeue/client/jobobject.h>

#include <QtCore/QDebug>

#include <QtWidgets/QMessageBox>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace QtPlugins {

using ::MoleQueue::JobObject;

//using QtGui::FileFormatDialog; // ADDED BY C.SALGADO ON 2016-07-16 FOR openJobOutput.

PlotTransmDos::PlotTransmDos(QObject *parent_) :
  ExtensionPlugin(parent_),
  m_action(new QAction(this)),
  m_molecule(NULL),
  m_dialog(NULL),
  m_outputFormat(NULL)//,
  //m_savePath("")
{
  m_action->setEnabled(true);
  m_action->setText(tr("&PlotTransmDos"));
  connect(m_action, SIGNAL(triggered()), SLOT(menuActivated()));
}

PlotTransmDos::~PlotTransmDos()
{
}

QList<QAction *> PlotTransmDos::actions() const
{
  QList<QAction *> actions_;
  actions_.append(m_action);
  return actions_;
}

QStringList PlotTransmDos::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&Quantum") << tr("Input Generators");
  return path;
}

void PlotTransmDos::setMolecule(QtGui::Molecule *mol)
{
  if (m_dialog)
    //m_dialog->setMolecule(mol);
  m_molecule = mol;
}

void PlotTransmDos::openJobOutput(const JobObject &job)
{
  m_outputFormat = NULL;
  m_outputFileName.clear();

  QString outputPath(job.value("outputDirectory").toString());
  qDebug()<<"job.value(\"description\").toString() = "<<job.value("description").toString();
  qDebug()<<"job.value(\"jobState\").toString() = "<<job.value("jobState").toString();
  qDebug()<<"job.value(\"localWorkingDirectory\").toString() = "<<job.value("localWorkingDirectory").toString();
  qDebug()<<"job.value(\"moleQueueId\").toString() = "<<job.value("moleQueueId").toString();
  qDebug()<<"job.value(\"outputDirectory\").toString() = "<<job.value("outputDirectory").toString();
  qDebug()<<"outputPath = "<<outputPath;

  using QtGui::FileFormatDialog; // TRIED TO COMMENT, BY C.SALGADO ON 2016-07-16 FOR openJobOutput.
  FileFormatDialog::FormatFilePair result =
      FileFormatDialog::fileToRead(qobject_cast<QWidget*>(parent()),
                                   tr("Open Output File"), outputPath);

  if (result.first == NULL) // User canceled
    return;

  m_outputFormat = result.first;
  m_outputFileName = result.second;

  emit moleculeReady(1);
}

bool PlotTransmDos::readMolecule(QtGui::Molecule &mol)
{
  Io::FileFormat *reader = m_outputFormat->newInstance();
  bool success = reader->readFile(m_outputFileName.toStdString(), mol);
  if (!success) {
    QMessageBox::information(qobject_cast<QWidget*>(parent()),
                             tr("Error"),
                             tr("Error reading output file '%1':\n%2")
                             .arg(m_outputFileName)
                             .arg(QString::fromStdString(reader->error())));
  }

  m_outputFormat = NULL;
  m_outputFileName.clear();

  return success;
}

void PlotTransmDos::menuActivated()
{
  if (!m_dialog) {
    m_dialog = new PlotTransmDosDialog(qobject_cast<QWidget*>(parent()));
    //m_dialog = new PlotTransmDosDialog();
    //connect(m_dialog, SIGNAL(openJobOutput(MoleQueue::JobObject)),
    //        this, SLOT(openJobOutput(MoleQueue::JobObject)));
  }
  //m_dialog->setMolecule(m_molecule);
  m_dialog->show();
}

} // end namespace QtPlugins
} // end namespace Avogadro
