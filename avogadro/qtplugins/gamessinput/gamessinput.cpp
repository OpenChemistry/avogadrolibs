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

#include "gamessinput.h"

#include "gamessinputdialog.h"

#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/molequeuemanager.h> // For MoleQueue::JobObject

#include <avogadro/io/fileformat.h>

#include <QtCore/QtPlugin>
#include <QtCore/QDebug>
#include <QtCore/QStringList>

#include <QtGui/QAction>
#include <QtGui/QDialog>

#include <qjsonvalue.h>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace QtPlugins {

GamessInput::GamessInput(QObject *parent_) :
  ExtensionPlugin(parent_),
  m_action(new QAction(this)),
  m_molecule(NULL),
  m_dialog(NULL),
  m_outputFormat(NULL)
{
  m_action->setEnabled(true);
  m_action->setText(tr("&GAMESS"));
  connect(m_action, SIGNAL(triggered()), SLOT(menuActivated()));
}

GamessInput::~GamessInput()
{
}

QList<QAction *> GamessInput::actions() const
{
  QList<QAction *> actions_;
  actions_.append(m_action);
  return actions_;
}

QStringList GamessInput::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&Quantum") << tr("Input Generators");
  return path;
}

void GamessInput::setMolecule(QtGui::Molecule *mol)
{
  if (m_dialog)
    m_dialog->setMolecule(mol);
  m_molecule = mol;
}

void GamessInput::openJobOutput(const MoleQueue::JobObject &job)
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

bool GamessInput::readMolecule(QtGui::Molecule &mol)
{
  Io::FileFormat *reader = m_outputFormat->newInstance();
  bool success = reader->readFile(m_outputFileName.toStdString(), mol);
  if (!success) {
    qWarning() << "Error reading output file" << m_outputFileName
               << "\n\t" << QString::fromStdString(reader->error());
  }

  m_outputFormat = NULL;
  m_outputFileName.clear();

  return success;
}

void GamessInput::menuActivated()
{
  if (!m_dialog) {
    m_dialog = new GamessInputDialog(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, SIGNAL(openJobOutput(MoleQueue::JobObject)),
            this, SLOT(openJobOutput(MoleQueue::JobObject)));
  }
  m_dialog->setMolecule(m_molecule);
  m_dialog->show();
}

}
}
