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

#include "quantuminput.h"

#include "gamessinputdialog.h"

#include <QtCore/QtPlugin>
#include <QtCore/QStringList>

#include <QtGui/QAction>
#include <QtGui/QDialog>

#include <QtCore/QDebug>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace QtPlugins {

QuantumInput::QuantumInput(QObject *parent_) : ExtensionPlugin(parent_),
  m_dialog(NULL),
  m_molecule(NULL)
{
  m_action = new QAction(this);
  m_action->setEnabled(true);
  m_action->setText(tr("&GAMESS Input Generator"));
  connect(m_action, SIGNAL(triggered()), SLOT(menuActivated()));
}

QuantumInput::~QuantumInput()
{
  if (m_dialog)
    m_dialog->deleteLater();
}

QList<QAction *> QuantumInput::actions() const
{
  QList<QAction *> actions_;
  actions_.append(m_action);
  return actions_;
}

QStringList QuantumInput::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&Extensions");
  return path;
}

void QuantumInput::setMolecule(Core::Molecule *mol)
{
  if (m_dialog)
    m_dialog->setMolecule(mol);
  m_molecule = mol;
}

void QuantumInput::menuActivated()
{
  if (!m_dialog)
    m_dialog = new GamessInputDialog;
  m_dialog->setMolecule(m_molecule);
  m_dialog->show();
}

}
}

Q_EXPORT_PLUGIN2(quantuminput, Avogadro::QtPlugins::QuantumInputFactory)
