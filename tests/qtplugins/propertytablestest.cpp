/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertymodel.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/chargemodel.h>
#include <avogadro/core/matrix.h>
#include <avogadro/qtgui/molecule.h>

#include <gtest/gtest.h>

#include <string>

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
