/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertymodel.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/chargemodel.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/matrix.h>
#include <avogadro/qtgui/molecule.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

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
// PropertyTablesElementTest: what the element column accepts.
// ---------------------------------------------------------------------------

namespace {

struct ElementEditResult
{
  bool accepted;
  int atomicNumber;
  int undoSteps;
  int emissions;
};

// Edit a hydrogen's element cell and report what happened.
ElementEditResult editElement(const QVariant& value)
{
  Molecule mol;
  mol.addAtom(1);
  PropertyModel model(PropertyType::AtomType);
  model.setMolecule(&mol);

  int count = 0;
  QObject context;
  QObject::connect(&model, &QAbstractItemModel::dataChanged, &context,
                   [&count]() { ++count; });
  QObject::connect(&mol, &Molecule::changed, &context, [&count]() { ++count; });

  ElementEditResult result;
  result.accepted = model.setData(model.index(0, 0), value);
  result.atomicNumber = mol.atomicNumber(0);
  result.undoSteps = mol.undoMolecule()->undoStack().count();
  result.emissions = count;
  return result;
}

} // namespace

TEST(PropertyTablesElementTest, AcceptedSpellings)
{
  struct Case
  {
    const char* text;
    int expected;
  };
  const Case cases[] = {
    { "Xx", 0 },     { "xx", 0 },     { "X", 0 },      { "x", 0 },
    { "du", 0 },     { "Du", 0 },     { "Q", 0 },      { "*", 0 },
    { " Xx ", 0 },   { "cl", 17 },    { "CL", 17 },    { "Cl", 17 },
    { "c", 6 },      { "6", 6 },      { "0", 0 },      { " 6 ", 6 },
    { "carbon", 6 }, { "Carbon", 6 }, { "CARBON", 6 }, { "dummy", 0 },
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(c.text);
    const auto result = editElement(QString::fromUtf8(c.text));
    EXPECT_TRUE(result.accepted);
    EXPECT_EQ(result.atomicNumber, c.expected);
    EXPECT_EQ(result.undoSteps, 1);
    EXPECT_GT(result.emissions, 0);
  }

  // A number handed over directly, as a spin box or script would.
  const auto direct = editElement(8);
  EXPECT_TRUE(direct.accepted);
  EXPECT_EQ(direct.atomicNumber, 8);
  EXPECT_EQ(direct.undoSteps, 1);
}

TEST(PropertyTablesElementTest, RejectedSpellings)
{
  const std::vector<QVariant> cases = {
    "200",         "-5",         "119",          "Zz",
    "Xaa",         "",           "  ",           "1.5",
    "Hx",          "nonsense",   "999999999999", QVariant(),
    QVariant(200), QVariant(-1), QVariant(1.5),
  };
  for (const QVariant& value : cases) {
    SCOPED_TRACE(value.toString().toStdString());
    const auto result = editElement(value);
    EXPECT_FALSE(result.accepted);
    EXPECT_EQ(result.atomicNumber, 1);
    EXPECT_EQ(result.undoSteps, 0);
    EXPECT_EQ(result.emissions, 0);
  }
}

TEST(PropertyTablesElementTest, TheSameElementIsNotAnEdit)
{
  for (const char* text : { "H", "h", "1", "Hydrogen", "hydrogen" }) {
    SCOPED_TRACE(text);
    const auto result = editElement(QString::fromUtf8(text));
    EXPECT_TRUE(result.accepted);
    EXPECT_EQ(result.atomicNumber, 1);
    EXPECT_EQ(result.undoSteps, 0);
    EXPECT_EQ(result.emissions, 0);
  }
}

TEST(PropertyTablesElementTest, ElementCountIsTheLimit)
{
  const int last = Avogadro::Core::Elements::elementCount() - 1;
  const auto inside = editElement(QString::number(last));
  EXPECT_TRUE(inside.accepted);
  EXPECT_EQ(inside.atomicNumber, last);
  EXPECT_FALSE(editElement(QString::number(last + 1)).accepted);
}
