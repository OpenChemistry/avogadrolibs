/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "select.h"

#include <avogadro/core/residue.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/periodictableview.h>

#include <QtCore/QRegularExpression>
#include <QtCore/QRegularExpressionMatch>
#include <QtGui/QKeySequence>
#include <QtWidgets/QAction>
#include <QtWidgets/QInputDialog>

#include <QtCore/QStringList>

using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

Select::Select(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_layerManager("Select"),
    m_molecule(nullptr), m_elements(nullptr)
{
  QAction* action = new QAction(tr("Select All"), this);
  action->setShortcut(QKeySequence("Ctrl+A"));
  connect(action, SIGNAL(triggered()), SLOT(selectAll()));
  m_actions.append(action);

  action = new QAction(tr("Select None"), this);
  action->setShortcut(QKeySequence("Ctrl+Shift+A"));
  connect(action, SIGNAL(triggered()), SLOT(selectNone()));
  m_actions.append(action);

  action = new QAction(this);
  action->setSeparator(true);
  m_actions.append(action);

  action = new QAction(tr("Invert Selection"), this);
  connect(action, SIGNAL(triggered()), SLOT(invertSelection()));
  m_actions.append(action);

  action = new QAction(tr("Select by Element..."), this);
  connect(action, SIGNAL(triggered()), SLOT(selectElement()));
  m_actions.append(action);

  action = new QAction(tr("Select by Atom Index..."), this);
  connect(action, SIGNAL(triggered()), SLOT(selectAtomIndex()));
  m_actions.append(action);

  action = new QAction(tr("Select by Residue..."), this);
  connect(action, SIGNAL(triggered()), SLOT(selectResidue()));
  m_actions.append(action);
}

Select::~Select()
{
  if (m_elements)
    m_elements->deleteLater();
}

QString Select::description() const
{
  return tr("Change selections");
}

QList<QAction*> Select::actions() const
{
  return m_actions;
}

QStringList Select::menuPath(QAction*) const
{
  return QStringList() << tr("&Select");
}

void Select::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

bool Select::evalSelect(bool input, Index index) const
{
  return !m_layerManager.atomLocked(index) && input;
}

void Select::selectAll()
{
  if (m_molecule) {
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      m_molecule->atom(i).setSelected(evalSelect(true, i));
    }

    m_molecule->emitChanged(Molecule::Atoms);
  }
}

void Select::selectNone()
{
  if (m_molecule) {
    for (Index i = 0; i < m_molecule->atomCount(); ++i)
      m_molecule->atom(i).setSelected(false);

    m_molecule->emitChanged(Molecule::Atoms);
  }
}

void Select::selectElement()
{
  if (!m_molecule)
    return;

  if (m_elements == nullptr) {
    m_elements = new QtGui::PeriodicTableView(qobject_cast<QWidget*>(parent()));
    connect(m_elements, SIGNAL(elementChanged(int)), this,
            SLOT(selectElement(int)));
  }

  m_elements->show();
}

void Select::selectElement(int element)
{
  if (!m_molecule)
    return;

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (m_molecule->atomicNumber(i) == element) {
      m_molecule->atom(i).setSelected(evalSelect(true, i));
    } else
      m_molecule->atom(i).setSelected(false);
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void Select::selectAtomIndex()
{
  if (!m_molecule)
    return;

  bool ok;
  QString text = QInputDialog::getText(
    qobject_cast<QWidget*>(parent()), tr("Select Atoms by Index"),
    tr("Atoms to Select:"), QLineEdit::Normal, QString(), &ok);

  if (!ok || text.isEmpty())
    return;

  auto list = text.simplified().split(',');
  foreach (const QString item, list) {
    // check if it's a range
    if (item.contains('-')) {
      auto range = item.split('-');
      if (range.size() >= 2) {
        bool ok1, ok2;
        int start = range.first().toInt(&ok1);
        int last = range.back().toInt(&ok2);
        if (ok1 && ok2) {
          for (Index i = start; i <= last; ++i) {
            m_molecule->atom(i).setSelected(evalSelect(true, i));
          }
        }
      }
    } else {
      int i = item.toInt(&ok);
      if (ok)
        m_molecule->atom(i).setSelected(evalSelect(true, i));
    }
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void Select::selectResidue()
{
  if (!m_molecule)
    return;

  bool ok;
  QString text = QInputDialog::getText(
    qobject_cast<QWidget*>(parent()), tr("Select Atoms by Residue"),
    tr("Residues to Select:"), QLineEdit::Normal, QString(), &ok);

  if (!ok || text.isEmpty())
    return;

  auto list = text.simplified().split(',');
  foreach (const QString item, list) {
    const QString label = item.simplified(); // get rid of whitespace
    // check if it's a number - select that residue index
    bool ok;
    int index = label.toInt(&ok);
    if (ok) {
      auto residueList = m_molecule->residues();
      if (index >= 1 && index < residueList.size()) {
        auto residue = residueList[index];
        for (auto& atom : residue.residueAtoms()) {
          atom.setSelected(evalSelect(true, atom.index()));
        }
      } // index makes sense
      continue;
    }

    // okay it's not just a number, so see if it's HIS57, etc.
    QRegularExpression re("([a-zA-Z]+)([0-9]+)");
    QRegularExpressionMatch match = re.match(label);
    if (match.hasMatch()) {
      QString name = match.captured(1);
      int index = match.captured(2).toInt();

      auto residueList = m_molecule->residues();
      if (index >= 1 && index < residueList.size()) {
        auto residue = residueList[index];
        if (name == residue.residueName().c_str()) {
          for (auto atom : residue.residueAtoms()) {
            atom.setSelected(evalSelect(true, atom.index()));
          }
        } // check if name matches specified (e.g. HIS57 is really a HIS)
      }   // index makes sense
    } else {
      // standard residue name
      for (auto residue : m_molecule->residues()) {
        if (label == residue.residueName().c_str()) {
          // select the atoms of the residue
          for (auto atom : residue.residueAtoms()) {
            atom.setSelected(evalSelect(true, atom.index()));
          }
        } // residue matches label
      }   // for(residues)
      continue;
    } // 3-character labels
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void Select::invertSelection()
{
  if (m_molecule) {
    for (Index i = 0; i < m_molecule->atomCount(); ++i)
      m_molecule->atom(i).setSelected(
        evalSelect(!m_molecule->atomSelected(i), i));
    m_molecule->emitChanged(Molecule::Atoms);
  }
}

} // namespace QtPlugins
} // namespace Avogadro
