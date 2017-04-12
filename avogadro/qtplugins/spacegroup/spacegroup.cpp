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

#include "spacegroup.h"

#include <avogadro/core/avospglib.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtWidgets/QAbstractItemView>
#include <QtWidgets/QAction>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QLayout>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QTableView>
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QStringList>

#include <QtGui/QStandardItemModel>

#include <sstream>

using Avogadro::Core::AvoSpglib;
using Avogadro::Core::CrystalTools;
using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

SpaceGroup::SpaceGroup(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_actions(QList<QAction*>()),
    m_molecule(nullptr), m_spgTol(1e-5),
    m_perceiveSpaceGroupAction(new QAction(this)),
    m_reduceToPrimitiveAction(new QAction(this)),
    m_conventionalizeCellAction(new QAction(this)),
    m_symmetrizeAction(new QAction(this)),
    m_fillUnitCellAction(new QAction(this)),
    m_reduceToAsymmetricUnitAction(new QAction(this)),
    m_setToleranceAction(new QAction(this))
{
  m_perceiveSpaceGroupAction->setText(tr("Perceive Space Group"));
  connect(m_perceiveSpaceGroupAction, SIGNAL(triggered()),
          SLOT(perceiveSpaceGroup()));
  m_actions.push_back(m_perceiveSpaceGroupAction);
  m_perceiveSpaceGroupAction->setProperty("menu priority", 90);

  m_reduceToPrimitiveAction->setText(tr("Reduce to Primitive"));
  connect(m_reduceToPrimitiveAction, SIGNAL(triggered()),
          SLOT(reduceToPrimitive()));
  m_actions.push_back(m_reduceToPrimitiveAction);
  m_reduceToPrimitiveAction->setProperty("menu priority", 80);

  m_conventionalizeCellAction->setText(tr("Conventionalize Cell"));
  connect(m_conventionalizeCellAction, SIGNAL(triggered()),
          SLOT(conventionalizeCell()));
  m_actions.push_back(m_conventionalizeCellAction);
  m_conventionalizeCellAction->setProperty("menu priority", 70);

  m_symmetrizeAction->setText(tr("Symmetrize"));
  connect(m_symmetrizeAction, SIGNAL(triggered()), SLOT(symmetrize()));
  m_actions.push_back(m_symmetrizeAction);
  m_symmetrizeAction->setProperty("menu priority", 60);

  m_fillUnitCellAction->setText(tr("Fill Unit Cell"));
  connect(m_fillUnitCellAction, SIGNAL(triggered()), SLOT(fillUnitCell()));
  m_actions.push_back(m_fillUnitCellAction);
  m_fillUnitCellAction->setProperty("menu priority", 50);

  m_reduceToAsymmetricUnitAction->setText(tr("Reduce to Asymmetric Unit"));
  connect(m_reduceToAsymmetricUnitAction, SIGNAL(triggered()),
          SLOT(reduceToAsymmetricUnit()));
  m_actions.push_back(m_reduceToAsymmetricUnitAction);
  m_reduceToAsymmetricUnitAction->setProperty("menu priority", 40);

  m_setToleranceAction->setText(tr("Set Tolerance"));
  connect(m_setToleranceAction, SIGNAL(triggered()), SLOT(setTolerance()));
  m_actions.push_back(m_setToleranceAction);
  m_setToleranceAction->setProperty("menu priority", 0);

  updateActions();
}

SpaceGroup::~SpaceGroup()
{
  qDeleteAll(m_actions);
  m_actions.clear();
}

QList<QAction*> SpaceGroup::actions() const
{
  return m_actions;
}

QStringList SpaceGroup::menuPath(QAction*) const
{
  return QStringList() << tr("&Crystal") << tr("Space Group");
}

void SpaceGroup::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;

  if (m_molecule)
    connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));

  updateActions();
}

void SpaceGroup::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  Molecule::MoleculeChanges changes = static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::UnitCell) {
    if (changes & Molecule::Added || changes & Molecule::Removed)
      updateActions();
  }
}

void SpaceGroup::updateActions()
{
  // Disable everything for nullptr molecules.
  if (!m_molecule) {
    foreach (QAction* action, m_actions)
      action->setEnabled(false);
    return;
  }

  if (m_molecule->unitCell()) {
    foreach (QAction* action, m_actions)
      action->setEnabled(true);

  } else {
    foreach (QAction* action, m_actions)
      action->setEnabled(false);
  }
}

void SpaceGroup::perceiveSpaceGroup()
{
  unsigned short hallNumber = AvoSpglib::getHallNumber(*m_molecule, m_spgTol);
  unsigned short intNum = Core::SpaceGroups::internationalNumber(hallNumber);
  std::string hallSymbol = Core::SpaceGroups::hallSymbol(hallNumber);
  std::string intShort = Core::SpaceGroups::internationalShort(hallNumber);

  // Success!
  if (hallNumber != 0) {
    // Let's make the message
    std::stringstream ss;
    ss << "Tolerance: " << m_spgTol << "  Å"
       << "\nSpace Group: " << intNum << "\nHall symbol: " << hallSymbol
       << "\nInternational symbol: " << intShort;

    // Now let's make the Message Box
    QMessageBox retMsgBox;
    retMsgBox.setText(tr(ss.str().c_str()));
    retMsgBox.exec();
  }
  // Failure
  else {
    // Ask if the user wants to try again with a different tolerance
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(nullptr, tr("Failure"),
                                  tr("Space group perception failed.\n"
                                     "Would you like to try again with a "
                                     "different tolerance?"),
                                  QMessageBox::Yes | QMessageBox::No);
    if (reply == QMessageBox::Yes) {
      setTolerance();
      perceiveSpaceGroup(); // Recursion!
    }
  }
}

void SpaceGroup::reduceToPrimitive()
{
  // Confirm the tolerance
  QMessageBox::StandardButton reply;
  reply = QMessageBox::question(nullptr, tr("Primitive Reduction"),
                                tr("The tolerance is currently set to: %1.\n"
                                   "Proceed with this tolerance?")
                                  .arg(m_spgTol),
                                QMessageBox::Yes | QMessageBox::No);
  if (reply == QMessageBox::No)
    setTolerance();

  // Primitive reduction!
  bool success = m_molecule->undoMolecule()->reduceCellToPrimitive(m_spgTol);

  if (!success) {
    // Print an error message.
    QMessageBox retMsgBox;
    retMsgBox.setText(tr("Primitive reduction failed.\n"
                         "Please check your crystal and try again "
                         "with a different tolerance."));
    retMsgBox.exec();
  }
}

void SpaceGroup::conventionalizeCell()
{
  // Confirm the tolerance
  QMessageBox::StandardButton reply;
  reply = QMessageBox::question(nullptr, tr("Conventionalize Cell"),
                                tr("The tolerance is currently set to: %1.\n"
                                   "Proceed with this tolerance?")
                                  .arg(m_spgTol),
                                QMessageBox::Yes | QMessageBox::No);
  if (reply == QMessageBox::No)
    setTolerance();

  // Conventionalize the cell!
  bool success = m_molecule->undoMolecule()->conventionalizeCell(m_spgTol);

  if (!success) {
    // Print an error message.
    QMessageBox retMsgBox;
    retMsgBox.setText(tr("Conventionalize cell failed.\n"
                         "Please check your crystal and try again "
                         "with a different tolerance."));
    retMsgBox.exec();
  }
}

void SpaceGroup::symmetrize()
{
  // Confirm the tolerance
  QMessageBox::StandardButton reply;
  reply = QMessageBox::question(nullptr, tr("Symmetrize Cell"),
                                tr("The tolerance is currently set to: %1.\n"
                                   "Proceed with this tolerance?")
                                  .arg(m_spgTol),
                                QMessageBox::Yes | QMessageBox::No);
  if (reply == QMessageBox::No)
    setTolerance();

  bool success = m_molecule->undoMolecule()->symmetrizeCell(m_spgTol);

  if (!success) {
    // Print an error message.
    QMessageBox retMsgBox;
    retMsgBox.setText(tr("Symmetrization failed.\n"
                         "Please check your crystal and try again "
                         "with a different tolerance."));
    retMsgBox.exec();
  }
}

void SpaceGroup::fillUnitCell()
{
  // Ask the user to select a space group
  unsigned short hallNumber = selectSpaceGroup();
  // If the hall number is zero, the user canceled
  if (hallNumber == 0)
    return;

  m_molecule->undoMolecule()->fillUnitCell(hallNumber, m_spgTol);
}

void SpaceGroup::reduceToAsymmetricUnit()
{
  // Let's gather some information about the space group first
  unsigned short hallNumber = AvoSpglib::getHallNumber(*m_molecule, m_spgTol);
  unsigned short intNum = Core::SpaceGroups::internationalNumber(hallNumber);
  std::string hallSymbol = Core::SpaceGroups::hallSymbol(hallNumber);
  std::string intShort = Core::SpaceGroups::internationalShort(hallNumber);

  // Ask the user if he/she wants to use this space group
  std::stringstream ss;
  ss << "With a tolerance of " << m_spgTol << "  Å, "
     << "the space group information was perceived to be the following:"
     << "\nSpace Group: " << intNum << "\nHall symbol: " << hallSymbol
     << "\nInternational symbol: " << intShort
     << "\n\nProceed with this space group?";
  QMessageBox::StandardButton reply;
  reply = QMessageBox::question(nullptr, tr("Reduce to Asymmetric Unit"),
                                tr(ss.str().c_str()),
                                QMessageBox::Yes | QMessageBox::No);

  // If the user does not want to use the perceived space group,
  // let the user set it.
  if (reply == QMessageBox::No)
    hallNumber = selectSpaceGroup();

  // If 0 was set, that means the user cancelled
  if (hallNumber == 0)
    return;

  // Perform the operation!
  m_molecule->undoMolecule()->reduceCellToAsymmetricUnit(hallNumber, m_spgTol);
}

void SpaceGroup::setTolerance()
{
  bool ok;
  double tol = QInputDialog::getDouble(nullptr,
                                       tr("Avogadro2"),              // title
                                       tr("Select tolerance in Å:"), // label
                                       m_spgTol,                     // initial
                                       1e-5,                         // min
                                       0.5,                          // max
                                       5,                            // decimals
                                       &ok);
  if (!ok)
    return;

  m_spgTol = tol;
}

unsigned short SpaceGroup::selectSpaceGroup()
{
  QStandardItemModel spacegroups;
  QStringList modelHeader;
  modelHeader << tr("International") << tr("Hall") << tr("Hermann-Mauguin");
  spacegroups.setHorizontalHeaderLabels(modelHeader);
  for (unsigned short i = 1; i <= 530; ++i) {
    QList<QStandardItem*> row;
    row << new QStandardItem(
             QString::number(Core::SpaceGroups::internationalNumber(i)))
        << new QStandardItem(QString(Core::SpaceGroups::hallSymbol(i)))
        << new QStandardItem(QString(Core::SpaceGroups::internationalShort(i)));
    spacegroups.appendRow(row);
  }

  QDialog dialog;
  dialog.setLayout(new QVBoxLayout);
  dialog.setWindowTitle(tr("Select Space Group"));
  QTableView* view = new QTableView;
  view->setSelectionBehavior(QAbstractItemView::SelectRows);
  view->setSelectionMode(QAbstractItemView::SingleSelection);
  view->setCornerButtonEnabled(false);
  view->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
  view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  view->verticalHeader()->hide();
  view->setModel(&spacegroups);
  dialog.layout()->addWidget(view);
  view->selectRow(0);
  view->resizeColumnsToContents();
  view->resizeRowsToContents();
  view->setMinimumWidth(view->horizontalHeader()->length() +
                        view->verticalScrollBar()->sizeHint().width());
  connect(view, SIGNAL(activated(QModelIndex)), &dialog, SLOT(accept()));
  QDialogButtonBox* buttons =
    new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  connect(buttons, SIGNAL(accepted()), &dialog, SLOT(accept()));
  connect(buttons, SIGNAL(rejected()), &dialog, SLOT(reject()));
  dialog.layout()->addWidget(buttons);
  if (dialog.exec() != QDialog::Accepted)
    return 0;

  // This should be hall number
  return view->currentIndex().row() + 1;
}

} // namespace QtPlugins
} // namespace Avogadro
