/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2020 Geoffrey Hutchison

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "insertfragment.h"
#include "insertfragmentdialog.h"

#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <QtCore/QDebug>
#include <QtCore/QFileInfo>

#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;
using Avogadro::QtGui::FileFormatDialog;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

InsertFragment::InsertFragment(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_crystalDialog(nullptr),
    m_moleculeDialog(nullptr), m_reader(nullptr), m_molecule(nullptr)
{
  QAction* action = new QAction(tr("Fragment..."), this);
  action->setData("molecules"); // will also work for crystals
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(tr("Crystal..."), this);
  action->setData("crystals"); // will also work for crystals
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);
}

InsertFragment::~InsertFragment()
{
  delete m_reader;
}

QList<QAction*> InsertFragment::actions() const
{
  return m_actions;
}

QStringList InsertFragment::menuPath(QAction* action) const
{
  if (action->data() == "crystals")
    return QStringList() << tr("&File") << tr("&Import");
  else
    return QStringList() << tr("&Build") << tr("&Insert");
}

void InsertFragment::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void InsertFragment::showDialog()
{
  if (!m_molecule)
    return;

  QWidget* parentAsWidget = qobject_cast<QWidget*>(parent());
  QAction* theSender = qobject_cast<QAction*>(sender());

  // Prompt user for input:
  bool crystal = theSender->data().toString() == "crystals";
  if (crystal) {
    // create the dialog if it doesn't exist
    if (!m_crystalDialog) {
      m_crystalDialog = new InsertFragmentDialog(parentAsWidget, "crystals");
      connect(m_crystalDialog, &InsertFragmentDialog::performInsert, this,
              &InsertFragment::performInsert);
    }
    m_crystalDialog->show();
  } else {
    // fragments - create the dialog if it doesn't exist
    if (!m_moleculeDialog) {
      m_moleculeDialog = new InsertFragmentDialog(parentAsWidget, "molecules");
      connect(m_moleculeDialog, &InsertFragmentDialog::performInsert, this,
              &InsertFragment::performInsert);
    }
    m_moleculeDialog->show();
  }
}

void InsertFragment::performInsert(const QString& fileName, bool crystal)
{
  if (m_molecule == nullptr)
    return;

  // read the file into the new fragment
  Avogadro::QtGui::Molecule newMol(m_molecule->parent());
  bool ok =
    Io::FileFormatManager::instance().readFile(newMol, fileName.toStdString());
  if (!ok) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Error reading file (%1).").arg(fileName));
    return;
  }

  if (crystal) {
    Molecule::MoleculeChanges changes =
      (Molecule::Atoms | Molecule::Bonds | Molecule::Added | Molecule::Removed);
    m_molecule->undoMolecule()->modifyMolecule(newMol, changes,
                                               tr("Import Crystal"));
    emit requestActiveTool("Navigator");
  } else {
    // insert mol into m_molecule
    m_molecule->undoMolecule()->appendMolecule(newMol, tr("Insert Fragment"));
    emit requestActiveTool("Manipulator");
  }
}

} // namespace QtPlugins
} // namespace Avogadro
