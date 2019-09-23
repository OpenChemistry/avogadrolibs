/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2019 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "mongochem.h"
#include "mongochemwidget.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QDebug>
#include <QDialog>
#include <QVBoxLayout>

namespace Avogadro {
namespace QtPlugins {

MongoChem::MongoChem(QObject* parent)
  : ExtensionPlugin(parent), m_action(new QAction(this))
{
  m_action->setText(tr("&MongoChem"));
  m_actions.push_back(m_action.data());
  connect(m_action.data(), &QAction::triggered, this,
          &MongoChem::menuActivated);
}

MongoChem::~MongoChem() = default;

QStringList MongoChem::menuPath(QAction*) const
{
  return { tr("&Extensions") };
}

void MongoChem::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

bool MongoChem::readMolecule(QtGui::Molecule& mol)
{
  Q_UNUSED(mol)

  return false;
}

void MongoChem::menuActivated()
{

  if (!m_dialog) {
    m_dialog.reset(new QDialog(qobject_cast<QWidget*>(this)));
    auto* layout = new QVBoxLayout;
    layout->addWidget(new MongoChemWidget);
    m_dialog->setLayout(layout);
    m_dialog->setWindowTitle("MongoChem");
  }

  m_dialog->show();
}

} // namespace QtPlugins
} // namespace Avogadro
