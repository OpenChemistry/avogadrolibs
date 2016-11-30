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

#include "ImportPQR.h"

#include "PQRWidget.h"

#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/io/fileformat.h>

#include <molequeue/client/jobobject.h>

#include <QtCore/QDebug>
#include <QtWidgets/QAction>

#include <QtWidgets/QMessageBox>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace QtPlugins {

using ::MoleQueue::JobObject;

ImportPQR::ImportPQR(QObject *parent_) :
  ExtensionPlugin(parent_),
  m_action(new QAction(this)),
  m_molecule(NULL),
  m_dialog(NULL),
  m_outputFormat(NULL)
{
  m_action->setEnabled(true);
  m_action->setText(tr("&Import From PQR"));
  connect(m_action, SIGNAL(triggered()), SLOT(menuActivated()));
}

ImportPQR::~ImportPQR()
{
}

QList<QAction *> ImportPQR::actions() const
{
  QList<QAction *> actions_;
  actions_.append(m_action);
  return actions_;
}

QStringList ImportPQR::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&File");
  return path;
}

void ImportPQR::setMolecule(QtGui::Molecule *mol)
{
  /**
  if (m_dialog)
    m_dialog->setMolecule(mol);
  m_molecule = mol;
  **/
}

void ImportPQR::openJobOutput(const JobObject &job)
{
  m_outputFormat = NULL;
  m_outputFileName.clear();

  QString outputPath(job.value("outputDirectory").toString());

  using QtGui::FileFormatDialog;
  FileFormatDialog::FormatFilePair result =
      FileFormatDialog::fileToRead(qobject_cast<QWidget*>(parent()),
                                   tr("Open Output File"), outputPath);

  if (result.first == NULL) // User canceled
    return;

  m_outputFormat = result.first;
  m_outputFileName = result.second;

  emit moleculeReady(1);
}

bool ImportPQR::readMolecule(QtGui::Molecule &mol)
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

void ImportPQR::menuActivated()
{
  if (!m_dialog) {
    m_dialog = new PQRWidget(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, SIGNAL(openJobOutput(MoleQueue::JobObject)),
            this, SLOT(openJobOutput(MoleQueue::JobObject)));
  }
//  m_dialog->setMolecule(m_molecule);
  m_dialog->show();
}

}
}
