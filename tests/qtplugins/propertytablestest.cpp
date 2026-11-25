/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertymodel.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/chargemodel.h>
#include <avogadro/core/matrix.h>
#include <avogadro/qtgui/molecule.h>

#include "propertyview.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QLocale>
#include <QtCore/QSortFilterProxyModel>
#include <QtWidgets/QAbstractItemDelegate>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QStyleOptionViewItem>

#include <gtest/gtest.h>

#include <cmath>
#include <memory>
#include <string>

#include <avogadro/core/residue.h>

using Avogadro::MatrixX;
using Avogadro::PropertyModel;
using Avogadro::PropertyType;
using Avogadro::QtGui::Molecule;

namespace {

int s_computations = 0;

// Counts how often it is asked, and returns all zeros, which is what made
// OBCharges rerun obabel on every request.
class CountingChargeModel : public Avogadro::Calc::ChargeModel
{
public:
  CountingChargeModel* newInstance() const override
  {
    return new CountingChargeModel;
  }
  std::string identifier() const override { return "countingfake"; }
  std::string name() const override { return "CountingFake"; }
  Avogadro::Core::Molecule::ElementMask elements() const override
  {
    Avogadro::Core::Molecule::ElementMask mask;
    mask.set();
    return mask;
  }
  MatrixX partialCharges(Avogadro::Core::Molecule& mol) const override
  {
    return partialCharges(static_cast<const Avogadro::Core::Molecule&>(mol));
  }
  MatrixX partialCharges(const Avogadro::Core::Molecule& mol) const override
  {
    ++s_computations;
    MatrixX charges(mol.atomCount(), 1);
    charges.fill(0.0);
    return charges;
  }
};

} // namespace

TEST(PropertyTablesChargeTest, ChargesComputedOncePerChange)
{
  Avogadro::Calc::ChargeManager::registerModel(new CountingChargeModel);

  Molecule mol;
  mol.addAtom(8);
  mol.addAtom(1);
  mol.addAtom(1);
  mol.setAtomPosition3d(1, Avogadro::Vector3(0.96, 0.0, 0.0));
  mol.setAtomPosition3d(2, Avogadro::Vector3(-0.24, 0.93, 0.0));

  PropertyModel model(PropertyType::AtomType);
  model.setMolecule(&mol);
  model.setChargeType("countingfake");

  // Find the partial charge column by its position in the atom table.
  int column = -1;
  for (int c = 0; c < model.columnCount(); ++c) {
    if (model.headerData(c, Qt::Horizontal).toString().contains("Charge") &&
        !model.headerData(c, Qt::Horizontal).toString().contains("Formal")) {
      column = c;
      break;
    }
  }
  ASSERT_GE(column, 0);

  s_computations = 0;
  for (int pass = 0; pass < 2; ++pass) {
    for (int row = 0; row < model.rowCount(); ++row) {
      QVariant v = model.data(model.index(row, column), Qt::DisplayRole);
      EXPECT_EQ(v.toString().toStdString(), "0.000");
    }
  }
  EXPECT_EQ(s_computations, 1);

  // A change to the molecule means the charges may differ.
  mol.setAtomPosition3d(1, Avogadro::Vector3(1.0, 0.0, 0.0));
  mol.emitChanged(Molecule::Atoms | Molecule::Modified);
  for (int row = 0; row < model.rowCount(); ++row)
    model.data(model.index(row, column), Qt::DisplayRole);
  EXPECT_EQ(s_computations, 2);

  // So does choosing another charge type and back again.
  model.setChargeType("countingfake");
  for (int row = 0; row < model.rowCount(); ++row)
    model.data(model.index(row, column), Qt::DisplayRole);
  EXPECT_EQ(s_computations, 3);

  Avogadro::Calc::ChargeManager::unregisterModel("countingfake");
}

// ---------------------------------------------------------------------------
// PropertyTablesLifetimeTest: the dialog outlives the molecule.
// ---------------------------------------------------------------------------

namespace {

class LifetimeChargeModel : public Avogadro::Calc::ChargeModel
{
public:
  LifetimeChargeModel* newInstance() const override
  {
    return new LifetimeChargeModel;
  }
  std::string identifier() const override { return "lifetimefake"; }
  std::string name() const override { return "LifetimeFake"; }
  Avogadro::Core::Molecule::ElementMask elements() const override
  {
    Avogadro::Core::Molecule::ElementMask mask;
    mask.set();
    return mask;
  }
  MatrixX partialCharges(Avogadro::Core::Molecule& mol) const override
  {
    return partialCharges(static_cast<const Avogadro::Core::Molecule&>(mol));
  }
  MatrixX partialCharges(const Avogadro::Core::Molecule& mol) const override
  {
    MatrixX charges(mol.atomCount(), 1);
    charges.fill(0.0);
    return charges;
  }
};

// H-O-O-H with a residue and two coordinate sets, so that all six tables
// have rows.
void buildLifetimeMolecule(Molecule& mol)
{
  mol.addAtom(1);
  mol.addAtom(8);
  mol.addAtom(8);
  mol.addAtom(1);
  mol.setAtomPosition3d(0, Avogadro::Vector3(-0.2, 0.9, 0.0));
  mol.setAtomPosition3d(1, Avogadro::Vector3(0.0, 0.0, 0.0));
  mol.setAtomPosition3d(2, Avogadro::Vector3(1.4, 0.0, 0.0));
  mol.setAtomPosition3d(3, Avogadro::Vector3(1.6, 0.4, 0.8));
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 1);
  mol.addBond(2, 3, 1);
  std::string name = "LIG";
  Avogadro::Index number = 1;
  char chain = 'A';
  auto& residue = mol.addResidue(name, number, chain);
  residue.addResidueAtom("O1", mol.atom(1));
  mol.setCoordinate3d(mol.atomPositions3d(), 0);
  mol.setCoordinate3d(mol.atomPositions3d(), 1);
  mol.setCoordinate3d(0);
}

const PropertyType kAllTables[] = {
  PropertyType::AtomType,    PropertyType::BondType,
  PropertyType::AngleType,   PropertyType::TorsionType,
  PropertyType::ResidueType, PropertyType::ConformerType
};

// Everything a view can ask a model, with no molecule behind it.
void queryEverything(QAbstractItemModel& model, int columns)
{
  for (int column = 0; column < columns + 2; ++column) {
    for (int role : { int(Qt::DisplayRole), int(Qt::TextAlignmentRole),
                      int(Qt::ToolTipRole), int(Qt::UserRole) }) {
      model.headerData(column, Qt::Horizontal, role);
      model.headerData(column, Qt::Vertical, role);
    }
    model.data(model.index(0, column), Qt::DisplayRole);
    model.flags(model.index(0, column));
  }
  EXPECT_EQ(model.rowCount(), 0);
}

} // namespace

TEST(PropertyTablesLifetimeTest, ModelSurvivesMoleculeDestruction)
{
  for (PropertyType type : kAllTables) {
    SCOPED_TRACE(static_cast<int>(type));
    auto* mol = new Molecule;
    buildLifetimeMolecule(*mol);
    PropertyModel model(type);
    model.setMolecule(mol);
    const int columns = model.columnCount();
    EXPECT_GT(model.rowCount(), 0);

    delete mol;

    queryEverything(model, columns);
    EXPECT_GE(model.columnCount(), 0);
    EXPECT_EQ(model.getAngleValue(0), 0.0);
    EXPECT_EQ(model.getTorsionValue(0), 0.0);
    model.setChargeType("");
    model.updateTable(Molecule::Atoms);
    EXPECT_FALSE(model.setData(model.index(0, 0), 1, Qt::EditRole));
  }
}

TEST(PropertyTablesLifetimeTest, ViewRepaintsAfterMoleculeDestruction)
{
  Avogadro::Calc::ChargeManager::registerModel(new LifetimeChargeModel);

  for (PropertyType type : kAllTables) {
    SCOPED_TRACE(static_cast<int>(type));
    auto* mol = new Molecule;
    buildLifetimeMolecule(*mol);

    // As PropertyTables::showDialog() builds them.
    auto model = std::make_unique<PropertyModel>(type);
    model->setMolecule(mol);
    model->setChargeType("lifetimefake");
    auto view = std::make_unique<Avogadro::PropertyView>(type);
    auto proxy = std::make_unique<QSortFilterProxyModel>();
    proxy->setSourceModel(model.get());
    proxy->setDynamicSortFilter(true);
    proxy->setSortLocaleAware(true);
    proxy->setSortRole(Qt::UserRole);
    view->setMolecule(mol);
    view->setModel(proxy.get());
    view->setSourceModel(model.get());
    view->resize(600, 300);
    view->show();
    QCoreApplication::processEvents();

    // No charge type chosen: the header asks the molecule for one.
    model->setChargeType("");
    delete mol;
    QCoreApplication::processEvents();
    view->repaint();
    QCoreApplication::processEvents();

    EXPECT_EQ(proxy->rowCount(), 0);
  }

  Avogadro::Calc::ChargeManager::unregisterModel("lifetimefake");
}

namespace {

// Sorts before every real identifier, and is none of the preferred ones.
class FirstChargeModel : public LifetimeChargeModel
{
public:
  FirstChargeModel* newInstance() const override
  {
    return new FirstChargeModel;
  }
  std::string identifier() const override { return "aaafake"; }
  std::string name() const override { return "AaaFake"; }
};

} // namespace

TEST(PropertyTablesChargeTest, HeaderNamesTheFallbackChargeType)
{
  Avogadro::Calc::ChargeManager::registerModel(new FirstChargeModel);

  Molecule mol;
  mol.addAtom(8);
  mol.addAtom(1);
  mol.addAtom(1);

  // No charge type chosen and none stored: the header picks one itself.
  PropertyModel model(PropertyType::AtomType);
  model.setMolecule(&mol);
  const QString header = model.headerData(3, Qt::Horizontal).toString();
  EXPECT_TRUE(header.startsWith("aaafake ")) << header.toStdString();

  Avogadro::Calc::ChargeManager::unregisterModel("aaafake");
}

TEST(PropertyTablesChargeTest, HeaderPrefersStoredChargesOverInstalledModels)
{
  Avogadro::Calc::ChargeManager::registerModel(new FirstChargeModel);

  Molecule mol;
  mol.addAtom(8);
  mol.addAtom(1);
  mol.addAtom(1);

  PropertyModel model(PropertyType::AtomType);
  model.setMolecule(&mol);
  // nothing stored: the installed model is the default
  EXPECT_TRUE(
    model.headerData(3, Qt::Horizontal).toString().startsWith("aaafake "));

  // charges read from a file win over the installed model
  MatrixX charges(3, 1);
  charges << -0.8, 0.4, 0.4;
  mol.setPartialCharges("Mulliken", charges);
  PropertyModel stored(PropertyType::AtomType);
  stored.setMolecule(&mol);
  const QString header = stored.headerData(3, Qt::Horizontal).toString();
  EXPECT_TRUE(header.startsWith("Mulliken ")) << header.toStdString();

  Avogadro::Calc::ChargeManager::unregisterModel("aaafake");
}

// ---------------------------------------------------------------------------
// PropertyTablesEditTest: numeric cells are edited in the user's locale.
// ---------------------------------------------------------------------------

namespace {

using Avogadro::Vector3;

// Restores the default locale when a test is done with it.
class LocaleGuard
{
public:
  explicit LocaleGuard(const QLocale& locale) : m_saved(QLocale())
  {
    QLocale::setDefault(locale);
  }
  ~LocaleGuard() { QLocale::setDefault(m_saved); }

private:
  QLocale m_saved;
};

struct LocaleCase
{
  const char* name;
  QLocale locale;
};

const LocaleCase kLocales[] = {
  { "en_US", QLocale(QLocale::English, QLocale::UnitedStates) },
  { "de_DE", QLocale(QLocale::German, QLocale::Germany) },
  { "fr_FR", QLocale(QLocale::French, QLocale::France) },
};

// Hydrogen peroxide, H0-O1-O2-H3, with a first hydrogen at x = -0.168439
// (the 0.97 A bond at 100 degrees to the O-O axis). The O-O bond, the first
// angle and the torsion are constrained, and O1 is frozen, so each kind of
// lock is on a cell.
void buildEditMolecule(Molecule& mol)
{
  const double pi = std::acos(-1.0);
  const double theta = 100.0 * pi / 180.0;
  const double phi = 110.0 * pi / 180.0;
  const Vector3 o1(0.0, 0.0, 0.0);
  const Vector3 o2(1.45, 0.0, 0.0);
  mol.addAtom(1);
  mol.addAtom(8);
  mol.addAtom(8);
  mol.addAtom(1);
  mol.setAtomPosition3d(
    0, o1 + 0.97 * Vector3(std::cos(theta), std::sin(theta), 0.0));
  mol.setAtomPosition3d(1, o1);
  mol.setAtomPosition3d(2, o2);
  mol.setAtomPosition3d(
    3, o2 + 0.97 * Vector3(-std::cos(theta), std::sin(theta) * std::cos(phi),
                           std::sin(theta) * std::sin(phi)));
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 1);
  mol.addBond(2, 3, 1);
  mol.setFrozenAtom(1, true);
  mol.addConstraint(1.45, 1, 2);
  mol.addConstraint(100.0, 0, 1, 2);
  mol.addConstraint(110.0, 0, 1, 2, 3);
}

// One table behind a sorting proxy and a view, as showDialog() builds them,
// edited through the view's own delegate.
class EditSession
{
public:
  explicit EditSession(PropertyType type,
                       void (*build)(Molecule&) = buildEditMolecule)
    : molecule(new Molecule), model(new PropertyModel(type)),
      proxy(new QSortFilterProxyModel), view(new Avogadro::PropertyView(type))
  {
    build(*molecule);
    model->setMolecule(molecule.get());
    proxy->setSourceModel(model.get());
    proxy->setDynamicSortFilter(true);
    proxy->setSortLocaleAware(true);
    proxy->setSortRole(Qt::UserRole);
    view->setMolecule(molecule.get());
    view->setModel(proxy.get());
    view->setSourceModel(model.get());
  }

  int undoCount() const
  {
    return molecule->undoMolecule()->undoStack().count();
  }

  QModelIndex index(int row, int column) const
  {
    return proxy->mapFromSource(model->index(row, column));
  }

  QString editText(int row, int column) const
  {
    return model->data(model->index(row, column), Qt::EditRole).toString();
  }

  QString displayText(int row, int column) const
  {
    return model->data(model->index(row, column), Qt::DisplayRole).toString();
  }

  // What the delegate does when the user opens a cell, optionally types
  // something, and presses Enter.
  void editThroughDelegate(int row, int column, const QString* typed)
  {
    const QModelIndex proxyIndex = index(row, column);
    auto* delegate = view->itemDelegateForIndex(proxyIndex);
    ASSERT_NE(delegate, nullptr);
    QStyleOptionViewItem option;
    option.initFrom(view->viewport());
    QWidget* editor =
      delegate->createEditor(view->viewport(), option, proxyIndex);
    ASSERT_NE(editor, nullptr);
    delegate->setEditorData(editor, proxyIndex);
    if (typed != nullptr) {
      auto* line = qobject_cast<QLineEdit*>(editor);
      ASSERT_NE(line, nullptr);
      line->setText(*typed);
    }
    delegate->setModelData(editor, proxy.get(), proxyIndex);
    delete editor;
  }

  std::unique_ptr<Molecule> molecule;
  std::unique_ptr<PropertyModel> model;
  std::unique_ptr<QSortFilterProxyModel> proxy;
  std::unique_ptr<Avogadro::PropertyView> view;
};

// Counts everything a rejected or unchanged edit must not send.
struct SignalCounter
{
  SignalCounter(PropertyModel* model, Molecule* molecule)
  {
    QObject::connect(model, &QAbstractItemModel::dataChanged, &context,
                     [this]() { ++dataChanged; });
    QObject::connect(model, &QAbstractItemModel::modelReset, &context,
                     [this]() { ++resets; });
    QObject::connect(molecule, &Molecule::changed, &context,
                     [this]() { ++moleculeChanged; });
  }
  int total() const { return dataChanged + resets + moleculeChanged; }

  QObject context;
  int dataChanged = 0;
  int resets = 0;
  int moleculeChanged = 0;
};

// Column numbers in the tables: atom X, bond length, angle, torsion.
constexpr int kAtomX = 4;
constexpr int kBondLength = 4;
constexpr int kAngleValue = 4;
constexpr int kTorsionValue = 5;

QString spelled(double value, int decimals)
{
  QLocale locale;
  locale.setNumberOptions(QLocale::OmitGroupSeparator);
  return locale.toString(value, 'f', decimals);
}

} // namespace

TEST(PropertyTablesEditTest, EditTextIsPlainAndInTheLocale)
{
  struct Expected
  {
    const char* locale;
    const char* normal;  // -0.168439 at 4 decimals
    const char* large;   // 1234.5678
    const char* display; // the same, as shown
  };
  const Expected expected[] = {
    { "en_US", "-0.1684", "1234.5678", "1,234.5678" },
    { "de_DE", "-0,1684", "1234,5678", "1.234,5678" },
    { "fr_FR", "-0,1684", "1234,5678", nullptr },
  };

  for (size_t i = 0; i < 3; ++i) {
    SCOPED_TRACE(expected[i].locale);
    LocaleGuard guard(kLocales[i].locale);

    EditSession session(PropertyType::AtomType);
    // The fixture's first hydrogen.
    EXPECT_EQ(session.editText(0, kAtomX).toStdString(), expected[i].normal);
    EXPECT_EQ(session.displayText(0, kAtomX).toStdString(), expected[i].normal);

    // A large value: the display groups digits, the editor must not.
    session.molecule->setAtomPosition3d(2, Vector3(1234.5678, 0.0, 0.0));
    EXPECT_EQ(session.editText(2, kAtomX).toStdString(), expected[i].large);
    if (expected[i].display != nullptr) {
      EXPECT_EQ(session.displayText(2, kAtomX).toStdString(),
                expected[i].display);
    } else {
      EXPECT_NE(session.displayText(2, kAtomX), session.editText(2, kAtomX));
    }

    // Locked values show the lock in the display only.
    EXPECT_TRUE(session.displayText(1, kAtomX).endsWith("🔒"));
    EXPECT_FALSE(session.editText(1, kAtomX).contains("🔒"));
    EXPECT_EQ(session.editText(1, kAtomX), spelled(0.0, 4));
  }

  // Display and sort values are as they were.
  LocaleGuard guard(kLocales[0].locale);
  EditSession session(PropertyType::AtomType);
  EXPECT_DOUBLE_EQ(
    session.model->data(session.model->index(0, kAtomX), Qt::UserRole)
      .toDouble(),
    session.molecule->atomPosition3d(0).x());
}

TEST(PropertyTablesEditTest, LockedMeasurementsHaveNoLockInEditText)
{
  for (const auto& entry : kLocales) {
    SCOPED_TRACE(entry.name);
    LocaleGuard guard(entry.locale);

    EditSession bonds(PropertyType::BondType);
    EXPECT_TRUE(bonds.displayText(1, kBondLength).endsWith("🔒"));
    EXPECT_EQ(bonds.editText(1, kBondLength), spelled(1.45, 3));
    EXPECT_FALSE(bonds.editText(0, kBondLength).contains("🔒"));

    EditSession angles(PropertyType::AngleType);
    EXPECT_TRUE(angles.displayText(0, kAngleValue).endsWith("🔒"));
    EXPECT_EQ(angles.editText(0, kAngleValue), spelled(100.0, 3));

    EditSession torsions(PropertyType::TorsionType);
    EXPECT_TRUE(torsions.displayText(0, kTorsionValue).endsWith("🔒"));
    EXPECT_EQ(torsions.editText(0, kTorsionValue), spelled(110.0, 3));
  }
}

TEST(PropertyTablesEditTest, UnchangedCellIsNotAnEdit)
{
  struct Cell
  {
    PropertyType type;
    int row;
    int column;
  };
  // Plain and locked cells of each numeric kind.
  const Cell cells[] = {
    { PropertyType::AtomType, 0, kAtomX },
    { PropertyType::AtomType, 1, kAtomX },
    { PropertyType::BondType, 0, kBondLength },
    { PropertyType::BondType, 1, kBondLength },
    { PropertyType::AngleType, 0, kAngleValue },
    { PropertyType::AngleType, 1, kAngleValue },
    { PropertyType::TorsionType, 0, kTorsionValue },
  };

  for (const auto& entry : kLocales) {
    LocaleGuard guard(entry.locale);
    for (const Cell& cell : cells) {
      SCOPED_TRACE(std::string(entry.name) + " type " +
                   std::to_string(static_cast<int>(cell.type)) + " row " +
                   std::to_string(cell.row));
      EditSession session(cell.type);
      std::vector<Vector3> before;
      for (Avogadro::Index i = 0; i < session.molecule->atomCount(); ++i)
        before.push_back(session.molecule->atomPosition3d(i));
      SignalCounter counter(session.model.get(), session.molecule.get());

      // Enter on the prefilled text.
      session.editThroughDelegate(cell.row, cell.column, nullptr);
      // The prefilled text with the lock the cell shows.
      const QString shown = session.displayText(cell.row, cell.column);
      session.editThroughDelegate(cell.row, cell.column, &shown);

      EXPECT_EQ(session.undoCount(), 0);
      EXPECT_EQ(counter.total(), 0);
      for (Avogadro::Index i = 0; i < session.molecule->atomCount(); ++i)
        EXPECT_EQ(session.molecule->atomPosition3d(i), before[i]);
    }
  }
}

TEST(PropertyTablesEditTest, FullPrecisionSurvivesAnUnchangedEdit)
{
  for (const auto& entry : kLocales) {
    SCOPED_TRACE(entry.name);
    LocaleGuard guard(entry.locale);
    EditSession session(PropertyType::AtomType);
    const double before = session.molecule->atomPosition3d(0).x();
    EXPECT_NEAR(before, -0.168439, 1e-6);
    session.editThroughDelegate(0, kAtomX, nullptr);
    EXPECT_EQ(session.molecule->atomPosition3d(0).x(), before);
    EXPECT_EQ(session.undoCount(), 0);
  }
}

TEST(PropertyTablesEditTest, AtomCoordinateEdits)
{
  for (const auto& entry : kLocales) {
    SCOPED_TRACE(entry.name);
    LocaleGuard guard(entry.locale);
    EditSession session(PropertyType::AtomType);

    // The locale's own spelling.
    QString typed = spelled(2.5, 4);
    session.editThroughDelegate(0, kAtomX, &typed);
    EXPECT_EQ(session.molecule->atomPosition3d(0).x(), 2.5);
    EXPECT_EQ(session.undoCount(), 1);

    // A period, whatever the locale.
    typed = "3.25";
    session.editThroughDelegate(0, kAtomX, &typed);
    EXPECT_EQ(session.molecule->atomPosition3d(0).x(), 3.25);
    EXPECT_EQ(session.undoCount(), 2);

    // A frozen cell: unchanged is a no-op, changed is applied.
    typed = session.displayText(1, kAtomX);
    session.editThroughDelegate(1, kAtomX, &typed);
    EXPECT_EQ(session.undoCount(), 2);
    typed = spelled(0.5, 4) + "🔒";
    session.editThroughDelegate(1, kAtomX, &typed);
    EXPECT_EQ(session.molecule->atomPosition3d(1).x(), 0.5);
    EXPECT_EQ(session.undoCount(), 3);

    // Another axis edits only that axis.
    typed = spelled(-1.5, 4);
    session.editThroughDelegate(2, kAtomX + 1, &typed);
    EXPECT_EQ(session.molecule->atomPosition3d(2).y(), -1.5);
    EXPECT_EQ(session.molecule->atomPosition3d(2).x(), 1.45);
  }
}

TEST(PropertyTablesEditTest, MeasurementEdits)
{
  for (const auto& entry : kLocales) {
    SCOPED_TRACE(entry.name);
    LocaleGuard guard(entry.locale);

    {
      EditSession session(PropertyType::BondType);
      // An unlocked bond, then the constrained one with its lock shown.
      QString typed = spelled(1.1, 3);
      session.editThroughDelegate(0, kBondLength, &typed);
      EXPECT_EQ(session.undoCount(), 1);
      auto bond = session.molecule->bond(0);
      EXPECT_NEAR(
        (bond.atom1().position3d() - bond.atom2().position3d()).norm(), 1.1,
        1e-9);
      typed = "1.5";
      session.editThroughDelegate(0, kBondLength, &typed);
      EXPECT_EQ(session.undoCount(), 2);
      bond = session.molecule->bond(0);
      EXPECT_NEAR(
        (bond.atom1().position3d() - bond.atom2().position3d()).norm(), 1.5,
        1e-9);

      typed = session.displayText(1, kBondLength);
      session.editThroughDelegate(1, kBondLength, &typed);
      EXPECT_EQ(session.undoCount(), 2);
      typed = spelled(1.4, 3) + "🔒";
      session.editThroughDelegate(1, kBondLength, &typed);
      EXPECT_EQ(session.undoCount(), 3);
    }
    {
      EditSession session(PropertyType::AngleType);
      QString typed = spelled(120.0, 3);
      session.editThroughDelegate(0, kAngleValue, &typed);
      EXPECT_EQ(session.undoCount(), 1);
      EXPECT_NEAR(session.model->getAngleValue(0), 120.0, 1e-6);
      typed = "130.5";
      session.editThroughDelegate(0, kAngleValue, &typed);
      EXPECT_EQ(session.undoCount(), 2);
      EXPECT_NEAR(session.model->getAngleValue(0), 130.5, 1e-6);
    }
    {
      EditSession session(PropertyType::TorsionType);
      QString typed = spelled(90.0, 3) + "🔒";
      session.editThroughDelegate(0, kTorsionValue, &typed);
      EXPECT_EQ(session.undoCount(), 1);
      EXPECT_NEAR(std::fabs(session.model->getTorsionValue(0)), 90.0, 1e-6);
      typed = "-45.25";
      session.editThroughDelegate(0, kTorsionValue, &typed);
      EXPECT_EQ(session.undoCount(), 2);
      EXPECT_NEAR(session.model->getTorsionValue(0), -45.25, 1e-6);
    }
  }
}

TEST(PropertyTablesEditTest, NumberParsingByLocale)
{
  struct Case
  {
    const char* text;
    double expected; // NaN: rejected
  };
  const double no = std::nan("");
  const std::vector<std::vector<Case>> cases = {
    // en_US
    { { "1.5", 1.5 },
      { "1,5", no },
      { "1,234.5", no },
      { "1.234,5", no },
      { " 1.5 🔒", 1.5 },
      { "1,5🔒", no },
      { "-2e1", -20.0 } },
    // de_DE
    { { "1,5", 1.5 },
      { "1.5", 1.5 },
      { "1.234,5", no },
      { "1,234.5", no },
      { " 1,5 🔒", 1.5 } },
    // fr_FR
    { { "1,5", 1.5 }, { "1.5", 1.5 }, { "1 234,5", no }, { "1.234,5", no } },
  };

  for (size_t i = 0; i < 3; ++i) {
    LocaleGuard guard(kLocales[i].locale);
    for (const Case& c : cases[i]) {
      SCOPED_TRACE(std::string(kLocales[i].name) + " \"" + c.text + "\"");
      EditSession session(PropertyType::AtomType);
      SignalCounter counter(session.model.get(), session.molecule.get());
      const bool ok = session.model->setData(session.model->index(0, kAtomX),
                                             QString::fromUtf8(c.text));
      if (std::isnan(c.expected)) {
        EXPECT_FALSE(ok);
        EXPECT_EQ(counter.total(), 0);
        EXPECT_EQ(session.undoCount(), 0);
      } else {
        EXPECT_TRUE(ok);
        EXPECT_EQ(session.molecule->atomPosition3d(0).x(), c.expected);
        EXPECT_EQ(session.undoCount(), 1);
      }
    }
  }
}

TEST(PropertyTablesEditTest, RejectedEditsChangeNothing)
{
  LocaleGuard guard(kLocales[0].locale);

  struct Case
  {
    PropertyType type;
    int column;
    QVariant value;
  };
  const std::vector<Case> cases = {
    { PropertyType::AtomType, kAtomX, "abc" },
    { PropertyType::AtomType, kAtomX, "" },
    { PropertyType::AtomType, kAtomX, "nan" },
    { PropertyType::AtomType, kAtomX, "inf" },
    { PropertyType::AtomType, kAtomX, "1e999" },
    { PropertyType::AtomType, kAtomX, QVariant() },
    { PropertyType::AtomType, kAtomX + 1, "x" },
    { PropertyType::AtomType, kAtomX + 2, "x" },
    { PropertyType::AtomType, 2, "abc" }, // formal charge
    { PropertyType::AtomType, 2, "1.5" },
    { PropertyType::BondType, kBondLength, "abc" },
    { PropertyType::BondType, kBondLength, "1,5" },
    { PropertyType::BondType, 3, "abc" }, // order
    { PropertyType::BondType, 3, "0" },
    { PropertyType::BondType, 3, "7" },
    { PropertyType::BondType, 3, "-1" },
    { PropertyType::BondType, 3, "" },
    { PropertyType::AngleType, kAngleValue, "abc" },
    { PropertyType::TorsionType, kTorsionValue, "abc" },
  };

  for (const Case& c : cases) {
    SCOPED_TRACE(std::to_string(static_cast<int>(c.type)) + " column " +
                 std::to_string(c.column) + " value " +
                 c.value.toString().toStdString());
    EditSession session(c.type);
    SignalCounter counter(session.model.get(), session.molecule.get());
    EXPECT_FALSE(
      session.model->setData(session.model->index(0, c.column), c.value));
    EXPECT_EQ(counter.total(), 0);
    EXPECT_EQ(session.undoCount(), 0);
  }

  // The accepted ends of the bond order range still work.
  for (const char* order : { "2", "6" }) {
    EditSession session(PropertyType::BondType);
    EXPECT_TRUE(session.model->setData(session.model->index(0, 3), order));
    EXPECT_EQ(session.undoCount(), 1);
  }
}

// ---------------------------------------------------------------------------
// PropertyTablesIntegerEditTest: formal charge and bond order.
// ---------------------------------------------------------------------------

namespace {

constexpr int kFormalCharge = 2;
constexpr int kBondOrder = 3;

struct IntegerEditResult
{
  bool accepted;
  int value;
  int undoSteps;
  int emissions;
};

IntegerEditResult editInteger(PropertyType type, int column,
                              const QVariant& value)
{
  EditSession session(type);
  SignalCounter counter(session.model.get(), session.molecule.get());
  IntegerEditResult result;
  result.accepted =
    session.model->setData(session.model->index(0, column), value);
  result.value = type == PropertyType::AtomType
                   ? session.molecule->formalCharge(0)
                   : session.molecule->bondOrder(0);
  result.undoSteps = session.undoCount();
  result.emissions = counter.total();
  return result;
}

} // namespace

TEST(PropertyTablesIntegerEditTest, FormalChargeRange)
{
  struct Case
  {
    QVariant value;
    int expected;
  };
  const std::vector<Case> accepted = {
    { 127, 127 }, { -128, -128 }, { "127", 127 }, { "-128", -128 },
    { 2.0, 2 },   { "2", 2 },     { " -1 ", -1 }, { 3LL, 3 },
  };
  for (const Case& c : accepted) {
    SCOPED_TRACE(c.value.toString().toStdString());
    const auto result =
      editInteger(PropertyType::AtomType, kFormalCharge, c.value);
    EXPECT_TRUE(result.accepted);
    EXPECT_EQ(result.value, c.expected);
    EXPECT_EQ(result.undoSteps, 1);
  }

  const std::vector<QVariant> rejected = {
    128,   -129, 1000,       1.5,          "1.5", "128",        "-129",
    "abc", "",   QVariant(), std::nan(""), 1e30,  quint64(300),
  };
  for (const QVariant& value : rejected) {
    SCOPED_TRACE(value.toString().toStdString());
    const auto result =
      editInteger(PropertyType::AtomType, kFormalCharge, value);
    EXPECT_FALSE(result.accepted);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.undoSteps, 0);
    EXPECT_EQ(result.emissions, 0);
  }
}

TEST(PropertyTablesIntegerEditTest, UnchangedValuesAreNotEdits)
{
  // The fixture has neutral atoms and single bonds.
  for (const QVariant& value : { QVariant(0), QVariant("0"), QVariant(0.0) }) {
    const auto result =
      editInteger(PropertyType::AtomType, kFormalCharge, value);
    EXPECT_TRUE(result.accepted);
    EXPECT_EQ(result.undoSteps, 0);
    EXPECT_EQ(result.emissions, 0);
  }
  for (const QVariant& value : { QVariant(1), QVariant("1") }) {
    const auto result = editInteger(PropertyType::BondType, kBondOrder, value);
    EXPECT_TRUE(result.accepted);
    EXPECT_EQ(result.undoSteps, 0);
    EXPECT_EQ(result.emissions, 0);
  }
}

TEST(PropertyTablesIntegerEditTest, ChangedValuesAreOneEdit)
{
  const auto charge = editInteger(PropertyType::AtomType, kFormalCharge, -1);
  EXPECT_TRUE(charge.accepted);
  EXPECT_EQ(charge.value, -1);
  EXPECT_EQ(charge.undoSteps, 1);
  EXPECT_GT(charge.emissions, 0);

  const auto order = editInteger(PropertyType::BondType, kBondOrder, "2");
  EXPECT_TRUE(order.accepted);
  EXPECT_EQ(order.value, 2);
  EXPECT_EQ(order.undoSteps, 1);
  EXPECT_GT(order.emissions, 0);

  for (const QVariant& value : { QVariant(0), QVariant(7), QVariant("1.5"),
                                 QVariant(2.5), QVariant("x") }) {
    const auto bad = editInteger(PropertyType::BondType, kBondOrder, value);
    EXPECT_FALSE(bad.accepted);
    EXPECT_EQ(bad.undoSteps, 0);
    EXPECT_EQ(bad.emissions, 0);
  }
}
