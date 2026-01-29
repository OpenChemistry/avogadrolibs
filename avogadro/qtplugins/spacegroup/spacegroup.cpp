/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "spacegroup.h"

#include <cmath>

#include <avogadro/core/avospglib.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/richtextdelegate.h>

#include <QAction>
#include <QDebug>
#include <QtWidgets/QAbstractItemView>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QLayout>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTableView>
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QStringList>

#include <QtGui/QFont>
#include <QtGui/QStandardItemModel>

#include <cmath>
#include <sstream>

using Avogadro::Core::AvoSpglib;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RichTextDelegate;

namespace Avogadro::QtPlugins {

SpaceGroup::SpaceGroup(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_actions(QList<QAction*>()),
    m_molecule(nullptr), m_spgTol(1e-5),
    m_perceiveSpaceGroupAction(new QAction(this)),
    m_reduceToPrimitiveAction(new QAction(this)),
    m_conventionalizeCellAction(new QAction(this)),
    m_symmetrizeAction(new QAction(this)),
    m_fillTranslationalCellAction(new QAction(this)),
    m_fillUnitCellAction(new QAction(this)),
    m_reduceToAsymmetricUnitAction(new QAction(this)),
    m_setToleranceAction(new QAction(this))
{
  m_perceiveSpaceGroupAction->setText(tr("Perceive Space Group…"));
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

  m_reduceToAsymmetricUnitAction->setText(tr("Reduce to Asymmetric Unit"));
  connect(m_reduceToAsymmetricUnitAction, SIGNAL(triggered()),
          SLOT(reduceToAsymmetricUnit()));
  m_actions.push_back(m_reduceToAsymmetricUnitAction);
  m_reduceToAsymmetricUnitAction->setProperty("menu priority", 40);

  m_setToleranceAction->setText(tr("Set Tolerance…"));
  connect(m_setToleranceAction, SIGNAL(triggered()), SLOT(setTolerance()));
  m_actions.push_back(m_setToleranceAction);
  m_setToleranceAction->setProperty("menu priority", 0);

  // should fall next to the "Wrap Atoms to Unit Cell" action on Crystal menu
  m_fillUnitCellAction->setText(tr("Fill Unit Cell…"));
  connect(m_fillUnitCellAction, SIGNAL(triggered()), SLOT(fillUnitCell()));
  m_actions.push_back(m_fillUnitCellAction);
  m_fillUnitCellAction->setProperty("menu priority", 185);

  m_fillTranslationalCellAction->setText(tr(
    "Fill Translation Cell…", "fill the translationally unique repeat unit"));
  connect(m_fillTranslationalCellAction, SIGNAL(triggered()),
          SLOT(fillTranslationalCell()));
  m_actions.push_back(m_fillTranslationalCellAction);
  m_fillTranslationalCellAction->setProperty("menu priority", 184);

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

QStringList SpaceGroup::menuPath(QAction* action) const
{
  if (action == m_fillUnitCellAction || action == m_fillTranslationalCellAction)
    return QStringList() << tr("&Crystal");

  return QStringList() << tr("&Crystal") << tr("Space Group");
}

void SpaceGroup::registerCommands()
{
  emit registerCommand(
    "fillUnitCell",
    tr("Fill symmetric atoms based on the crystal space group."));
  emit registerCommand("fillTranslationalCell",
                       tr("Fill all atoms based on the crystal space group."));
}

bool SpaceGroup::handleCommand(const QString& command,
                               [[maybe_unused]] const QVariantMap& options)
{
  if (m_molecule == nullptr)
    return false; // No molecule to handle the command.

  if (command == "fillUnitCell") {
    fillUnitCell();
    return true;
  } else if (command == "fillTranslationalCell") {
    fillTranslationalCell();
    return true;
  }
  return false;
}

const QString SpaceGroup::toleranceToString()
{
  // Convert to scientific notation to extract mantissa and exponent
  int exponent = static_cast<int>(std::floor(std::log10(m_spgTol)));
  double mantissa = m_spgTol / std::pow(10.0, exponent);

  // UTF-8 superscript characters
  const QString superscriptDigits[] = {
    QStringLiteral("⁰"), QStringLiteral("¹"), QStringLiteral("²"),
    QStringLiteral("³"), QStringLiteral("⁴"), QStringLiteral("⁵"),
    QStringLiteral("⁶"), QStringLiteral("⁷"), QStringLiteral("⁸"),
    QStringLiteral("⁹")
  };
  const QString superscriptMinus = QStringLiteral("⁻");

  // Build the exponent string with superscripts
  QString expStr;
  int absExp = std::abs(exponent);
  if (exponent < 0)
    expStr += superscriptMinus;

  QString digits = QString::number(absExp);
  for (const QChar& c : digits) {
    expStr += superscriptDigits[c.digitValue()];
  }

  return QStringLiteral("%1 × 10%2").arg(mantissa, 0, 'f', 1).arg(expStr);
}

const QString SpaceGroup::symbolToString(unsigned short hallNumber,
                                         bool replaceOverlines)
{
  QString symbol(Core::SpaceGroups::internationalShort(hallNumber));

  // Replace -N notation with N̅ (number with combining overline U+0305)
  // for rotoinversion axes in Hermann-Mauguin symbols
  if (replaceOverlines) {
    QString htmlOverline(
      "<span style=\"text-decoration: overline;\">%1</span>");
    symbol.replace(QStringLiteral("-1"), htmlOverline.arg(QStringLiteral("1")));
    symbol.replace(QStringLiteral("-2"), htmlOverline.arg(QStringLiteral("2")));
    symbol.replace(QStringLiteral("-3"), htmlOverline.arg(QStringLiteral("3")));
    symbol.replace(QStringLiteral("-4"), htmlOverline.arg(QStringLiteral("4")));
    symbol.replace(QStringLiteral("-6"), htmlOverline.arg(QStringLiteral("6")));
  }

  // Replace screw axis notation with subscripts
  // e.g., "21" -> "2₁", "42" -> "4₂", etc.
  // Unicode subscript digits: ₁=U+2081, ₂=U+2082, ₃=U+2083, ₄=U+2084, ₅=U+2085
  symbol.replace(QStringLiteral("2_1"), QStringLiteral("2₁"));
  symbol.replace(QStringLiteral("3_1"), QStringLiteral("3₁"));
  symbol.replace(QStringLiteral("3_2"), QStringLiteral("3₂"));
  symbol.replace(QStringLiteral("4_1"), QStringLiteral("4₁"));
  symbol.replace(QStringLiteral("4_2"), QStringLiteral("4₂"));
  symbol.replace(QStringLiteral("4_3"), QStringLiteral("4₃"));
  symbol.replace(QStringLiteral("6_1"), QStringLiteral("6₁"));
  symbol.replace(QStringLiteral("6_2"), QStringLiteral("6₂"));
  symbol.replace(QStringLiteral("6_3"), QStringLiteral("6₃"));
  symbol.replace(QStringLiteral("6_4"), QStringLiteral("6₄"));
  symbol.replace(QStringLiteral("6_5"), QStringLiteral("6₅"));

  return symbol;
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

  // add a heuristic to completely fill the cell if it's a solid
  if (m_molecule != nullptr && m_molecule->unitCell()) {
    // check if there's carbon and hydrogen atoms and at least 5 total atoms
    bool hasCarbon = false;
    bool hasHydrogen = false;
    for (unsigned int i = 0; i < m_molecule->atomCount(); ++i) {
      if (m_molecule->atom(i).atomicNumber() == 6)
        hasCarbon = true;
      else if (m_molecule->atom(i).atomicNumber() == 1)
        hasHydrogen = true;
    }

    if (m_molecule->atomCount() <= 5 || !(hasCarbon && hasHydrogen)) {
      fillUnitCell();
    }
  }
}

void SpaceGroup::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  auto changes = static_cast<Molecule::MoleculeChanges>(c);

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
  // only do this if we don't have a Hall number set
  if (m_molecule == nullptr)
    return;

  if (m_molecule->hallNumber() != 0) {
    // Ask if the user wants to overwrite the current space group
    std::string hallSymbol =
      Core::SpaceGroups::hallSymbol(m_molecule->hallNumber());

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(nullptr, tr("Perceive Space Group"),
                                  tr("The space group is already set to: %1.\n"
                                     "Would you like to overwrite it?")
                                    .arg(hallSymbol.c_str()),
                                  QMessageBox::Yes | QMessageBox::No);
    if (reply == QMessageBox::No)
      return;
  }

  unsigned short hallNumber = AvoSpglib::getHallNumber(*m_molecule, m_spgTol);
  unsigned short intNum = Core::SpaceGroups::internationalNumber(hallNumber);
  std::string hallSymbol = Core::SpaceGroups::hallSymbol(hallNumber);
  QString intShort = symbolToString(hallNumber);

  // Success!
  if (hallNumber != 0) {
    // Let's make the message
    QString message = tr("Space group perception succeeded:\n"
                         "Tolerance: %1  Å\n"
                         "Space Group: %2\n"
                         "Hall symbol: %3\n"
                         "International symbol: %4")
                        .arg(toleranceToString())
                        .arg(intNum)
                        .arg(hallSymbol.c_str())
                        .arg(intShort);

    // Now let's make the Message Box
    QMessageBox::information(nullptr, tr("Perceive Space Group"), message);
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
                                  .arg(toleranceToString()),
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
                                  .arg(toleranceToString()),
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
                                  .arg(toleranceToString()),
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
  unsigned short hallNumber = m_molecule->hallNumber();

  // If it's not set, ask the user to select a space group
  if (hallNumber == 0)
    hallNumber = selectSpaceGroup();
  // If the hall number is zero, the user canceled
  if (hallNumber == 0)
    return;

  if (!checkPrimitiveCell(hallNumber))
    return;

  // true here to fill all copies, including edges and corners
  m_molecule->undoMolecule()->fillUnitCell(hallNumber, m_spgTol, true);
}

void SpaceGroup::fillTranslationalCell()
{
  unsigned short hallNumber = m_molecule->hallNumber();

  // If it's not set, ask the user to select a space group
  if (hallNumber == 0)
    hallNumber = selectSpaceGroup();
  // If the hall number is zero, the user canceled
  if (hallNumber == 0)
    return;

  if (!checkPrimitiveCell(hallNumber))
    return;

  m_molecule->undoMolecule()->fillUnitCell(hallNumber, m_spgTol);
}

void SpaceGroup::reduceToAsymmetricUnit()
{
  // Let's gather some information about the space group first
  unsigned short hallNumber = AvoSpglib::getHallNumber(*m_molecule, m_spgTol);
  unsigned short intNum = Core::SpaceGroups::internationalNumber(hallNumber);
  std::string hallSymbol = Core::SpaceGroups::hallSymbol(hallNumber);
  QString intShort = symbolToString(hallNumber);

  // Ask the user if he/she wants to use this space group
  QString message =
    tr("With a tolerance of %1  Å, "
       "the space group information was perceived to be the following:\n"
       "International number: %2\n"
       "Hall symbol: %3\n"
       "International symbol: %4\n\n"
       "Proceed with this space group?")
      .arg(toleranceToString())
      .arg(intNum)
      .arg(hallSymbol.c_str())
      .arg(intShort);
  QMessageBox::StandardButton reply;
  reply = QMessageBox::question(nullptr, tr("Reduce to Asymmetric Unit"),
                                message, QMessageBox::Yes | QMessageBox::No);

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

const QString SpaceGroup::crystalSystem(unsigned short hallNumber)
{
  auto cs = Core::SpaceGroups::crystalSystem(hallNumber);
  switch (cs) {
    case Core::Triclinic:
      return tr("Triclinic");
    case Core::Monoclinic:
      return tr("Monoclinic");
    case Core::Orthorhombic:
      return tr("Orthorhombic");
    case Core::Tetragonal:
      return tr("Tetragonal");
    case Core::Trigonal:
      return tr("Trigonal");
    case Core::Rhombohedral:
      return tr("Rhombohedral");
    case Core::Hexagonal:
      return tr("Hexagonal");
    case Core::Cubic:
      return tr("Cubic");
    default:
      return tr("Unknown");
  }
}

bool SpaceGroup::checkPrimitiveCell(unsigned short hallNumber)
{
  // Check if the cell appears to be primitive but the space group expects
  // a centered cell. This can cause unexpected atom duplication.
  std::string hallSymbol = Core::SpaceGroups::hallSymbol(hallNumber);
  if (!hallSymbol.empty()) {
    char centering = hallSymbol[0];
    // F, I, A, B, C are centered lattice types
    if (centering == 'F' || centering == 'I' || centering == 'A' ||
        centering == 'B' || centering == 'C') {
      // Check if cell angles deviate significantly from 90 degrees
      // which would suggest a primitive cell basis
      Core::UnitCell* uc = m_molecule->unitCell();
      if (uc) {
        double alpha = uc->alpha() * 180.0 / M_PI;
        double beta = uc->beta() * 180.0 / M_PI;
        double gamma = uc->gamma() * 180.0 / M_PI;
        double tolerance = 5.0; // degrees

        bool nonConventionalAngles = (std::abs(alpha - 90.0) > tolerance) ||
                                     (std::abs(beta - 90.0) > tolerance) ||
                                     (std::abs(gamma - 90.0) > tolerance);

        if (nonConventionalAngles) {
          QMessageBox::StandardButton reply;
          reply = QMessageBox::warning(
            nullptr, tr("Primitive Cell Detected"),
            tr(
              "The current unit cell appears to be a primitive cell "
              "(non-90° angles), but the space group %1 expects a "
              "centered conventional cell.\n\n"
              "Filling the unit cell may create unexpected duplicate atoms.\n\n"
              "Would you like to create a conventional cell first?")
              .arg(hallSymbol.c_str()),
            QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);

          if (reply == QMessageBox::Cancel)
            return false;
          if (reply == QMessageBox::Yes) {
            // Conventionalize first, then fill
            if (!m_molecule->undoMolecule()->conventionalizeCell(m_spgTol)) {
              QMessageBox::warning(nullptr, tr("Error"),
                                   tr("Failed to conventionalize the cell."));
              return false;
            }
          }
          // If No, continue with fill anyway (user's choice)
        }
      }
    }
  }
  return true;
}

unsigned short SpaceGroup::selectSpaceGroup()
{
  QStandardItemModel spacegroups;
  QStringList modelHeader;
  modelHeader << tr("International") << tr("Hall") << tr("Hermann-Mauguin")
              << tr("Crystal System");
  spacegroups.setHorizontalHeaderLabels(modelHeader);
  for (unsigned short i = 1; i <= 530; ++i) {
    QList<QStandardItem*> row;
    // Use setData with int type so the column sorts numerically
    auto* intItem = new QStandardItem();
    intItem->setData(Core::SpaceGroups::internationalNumber(i),
                     Qt::DisplayRole);
    intItem->setEditable(false);
    auto* hallItem =
      new QStandardItem(QString(Core::SpaceGroups::hallSymbol(i)));
    hallItem->setEditable(false);
    // true = replace the overlines with HTML
    auto* hmItem = new QStandardItem(symbolToString(i, true));
    hmItem->setEditable(false);
    auto* csItem = new QStandardItem(crystalSystem(i));
    csItem->setEditable(false);
    row << intItem << hallItem << hmItem << csItem;
    spacegroups.appendRow(row);
  }

  // Create a proxy model for filtering
  QSortFilterProxyModel proxyModel;
  proxyModel.setSourceModel(&spacegroups);
  proxyModel.setFilterCaseSensitivity(Qt::CaseInsensitive);
  proxyModel.setFilterKeyColumn(-1); // Search all columns

  QDialog dialog;
  dialog.setLayout(new QVBoxLayout);
  dialog.setWindowTitle(tr("Select Space Group"));

  // Add search box
  auto* searchBox = new QLineEdit;
  searchBox->setClearButtonEnabled(true);
  dialog.layout()->addWidget(searchBox);

  auto* view = new QTableView;

  // Rich text delegate for symbol
  auto* symbolDelegate = new RichTextDelegate(this);
  view->setItemDelegateForColumn(2, symbolDelegate);

  QFont font = view->font();
  font.setPointSize(font.pointSize() + 1);
  view->setFont(font);
  view->setAlternatingRowColors(true);
  view->setSelectionBehavior(QAbstractItemView::SelectRows);
  view->setSelectionMode(QAbstractItemView::SingleSelection);
  view->setCornerButtonEnabled(false);
  view->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
  view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  view->verticalHeader()->hide();
  view->setModel(&proxyModel);
  view->setSortingEnabled(true);
  view->sortByColumn(0, Qt::AscendingOrder);
  dialog.layout()->addWidget(view);
  view->selectRow(0);
  view->resizeColumnsToContents();
  view->resizeRowsToContents();
  view->setMinimumWidth(view->horizontalHeader()->length() +
                        view->verticalScrollBar()->sizeHint().width());

  // Connect search box to filter
  QObject::connect(searchBox, &QLineEdit::textChanged, &proxyModel,
                   &QSortFilterProxyModel::setFilterFixedString);

  connect(view, SIGNAL(activated(QModelIndex)), &dialog, SLOT(accept()));
  auto* buttons =
    new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  connect(buttons, SIGNAL(accepted()), &dialog, SLOT(accept()));
  connect(buttons, SIGNAL(rejected()), &dialog, SLOT(reject()));
  dialog.layout()->addWidget(buttons);
  if (dialog.exec() != QDialog::Accepted)
    return 0;

  // Map the proxy index back to the source model to get the hall number
  QModelIndex proxyIndex = view->currentIndex();
  QModelIndex sourceIndex = proxyModel.mapToSource(proxyIndex);
  return sourceIndex.row() + 1;
}

} // namespace Avogadro::QtPlugins
