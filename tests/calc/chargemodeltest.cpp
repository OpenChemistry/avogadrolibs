/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/chargemodel.h>
#include <avogadro/calc/defaultmodel.h>

#include <avogadro/core/molecule.h>

#include <cmath>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using Avogadro::MatrixX;
using Avogadro::Vector3;

namespace {

Molecule waterMolecule()
{
  Molecule molecule;
  auto o = molecule.addAtom(8);
  auto h1 = molecule.addAtom(1);
  auto h2 = molecule.addAtom(1);
  o.setPosition3d(Vector3(0.0, 0.0, 0.0));
  h1.setPosition3d(Vector3(0.6, -0.5, 0.0));
  h2.setPosition3d(Vector3(-0.6, -0.5, 0.0));
  molecule.addBond(o, h1, 1);
  molecule.addBond(o, h2, 1);
  return molecule;
}

} // namespace

// --- DefaultModel ----------------------------------------------------------

TEST(ChargeModelTest, DefaultModelIdentifierAndName)
{
  DefaultModel model("gasteiger");
  EXPECT_EQ(model.identifier(), "gasteiger");
  EXPECT_EQ(model.name(), "gasteiger");
}

TEST(ChargeModelTest, DefaultModelDefaultConstructorIsEmptyIdentifier)
{
  DefaultModel model;
  EXPECT_EQ(model.identifier(), "");
}

TEST(ChargeModelTest, DefaultModelElementsCoversEverything)
{
  DefaultModel model("test");
  // DefaultModel does not know which molecule it will see, so it claims to
  // support every element.
  EXPECT_TRUE(model.elements().all());
}

TEST(ChargeModelTest, DefaultModelReturnsMoleculeStoredCharges)
{
  Molecule molecule = waterMolecule();
  MatrixX charges(3, 1);
  charges << -0.8, 0.4, 0.4;
  molecule.setPartialCharges("mulliken", charges);

  DefaultModel model("mulliken");

  const MatrixX fromNonConst = model.partialCharges(molecule);
  ASSERT_EQ(fromNonConst.rows(), 3);
  EXPECT_DOUBLE_EQ(fromNonConst(0, 0), -0.8);
  EXPECT_DOUBLE_EQ(fromNonConst(1, 0), 0.4);
  EXPECT_DOUBLE_EQ(fromNonConst(2, 0), 0.4);

  const Molecule& constMolecule = molecule;
  const MatrixX fromConst = model.partialCharges(constMolecule);
  ASSERT_EQ(fromConst.rows(), 3);
  EXPECT_DOUBLE_EQ(fromConst(0, 0), -0.8);
}

TEST(ChargeModelTest, DefaultModelUnknownIdentifierReturnsZeroFilledMatrix)
{
  Molecule molecule = waterMolecule();
  DefaultModel model("does-not-exist");

  const MatrixX charges = model.partialCharges(molecule);
  ASSERT_EQ(charges.rows(), 3);
  ASSERT_EQ(charges.cols(), 1);
  for (int i = 0; i < charges.rows(); ++i)
    EXPECT_DOUBLE_EQ(charges(i, 0), 0.0);
}

TEST(ChargeModelTest, DefaultModelEmptyMoleculeReturnsCleanly)
{
  Molecule molecule; // no atoms
  DefaultModel model("anything");

  const MatrixX charges = model.partialCharges(molecule);
  EXPECT_EQ(charges.rows(), 0);
}

TEST(ChargeModelTest, DefaultModelIndependentOfFormalCharges)
{
  // Formal charges (ion state) and partial charges are stored separately;
  // setting one must not perturb the other.
  Molecule molecule = waterMolecule();
  MatrixX charges(3, 1);
  charges << -0.8, 0.4, 0.4;
  molecule.setPartialCharges("mulliken", charges);

  molecule.setFormalCharge(0, -1);

  DefaultModel model("mulliken");
  const MatrixX result = model.partialCharges(molecule);
  ASSERT_EQ(result.rows(), 3);
  EXPECT_DOUBLE_EQ(result(0, 0), -0.8);
  EXPECT_DOUBLE_EQ(result(1, 0), 0.4);
  EXPECT_DOUBLE_EQ(result(2, 0), 0.4);
}

// --- ChargeModel base class: dipoleMoment / potential / potentials --------

namespace {

/// Returns rows > atomCount() and rows < atomCount() depending on how many
/// atoms the source molecule has, so a single class can drive both
/// dimension-mismatch directions with two differently-sized molecules.
class FixedRowsChargeModel : public ChargeModel
{
public:
  explicit FixedRowsChargeModel(Eigen::Index rows) : m_rows(rows) {}

  ChargeModel* newInstance() const override
  {
    return new FixedRowsChargeModel(m_rows);
  }
  std::string identifier() const override { return "fixed_rows"; }
  std::string name() const override { return "Fixed Rows"; }
  Molecule::ElementMask elements() const override
  {
    Molecule::ElementMask mask;
    mask.set();
    return mask;
  }
  MatrixX partialCharges(Molecule&) const override
  {
    return MatrixX::Constant(m_rows, 1, 1.0);
  }
  MatrixX partialCharges(const Molecule&) const override
  {
    return MatrixX::Constant(m_rows, 1, 1.0);
  }

private:
  Eigen::Index m_rows;
};

} // namespace

TEST(ChargeModelTest, DipoleMomentBoundedWhenFewerChargesThanAtoms)
{
  Molecule molecule = waterMolecule();
  FixedRowsChargeModel model(2); // 3 atoms, only 2 charge rows

  const Vector3 dipole = model.dipoleMoment(molecule);
  EXPECT_TRUE(std::isfinite(dipole.x()));
  EXPECT_TRUE(std::isfinite(dipole.y()));
  EXPECT_TRUE(std::isfinite(dipole.z()));

  // Only the first two atoms (O and the first H) contribute.
  const Vector3 expected =
    (Vector3(0.0, 0.0, 0.0) + Vector3(0.6, -0.5, 0.0)) * 4.80320471257;
  EXPECT_NEAR(dipole.x(), expected.x(), 1e-9);
  EXPECT_NEAR(dipole.y(), expected.y(), 1e-9);
}

TEST(ChargeModelTest, DipoleMomentBoundedWhenMoreChargesThanAtoms)
{
  Molecule molecule = waterMolecule();
  FixedRowsChargeModel model(5); // 3 atoms, 5 charge rows

  const Vector3 dipole = model.dipoleMoment(molecule);
  EXPECT_TRUE(std::isfinite(dipole.x()));

  // Only the three real atom positions contribute.
  const Vector3 expected = (Vector3(0.0, 0.0, 0.0) + Vector3(0.6, -0.5, 0.0) +
                            Vector3(-0.6, -0.5, 0.0)) *
                           4.80320471257;
  EXPECT_NEAR(dipole.x(), expected.x(), 1e-9);
  EXPECT_NEAR(dipole.y(), expected.y(), 1e-9);
}

TEST(ChargeModelTest, DipoleMomentEmptyMoleculeIsZero)
{
  Molecule molecule;
  FixedRowsChargeModel model(0);

  const Vector3 dipole = model.dipoleMoment(molecule);
  EXPECT_EQ(dipole, Vector3(0.0, 0.0, 0.0));
}

TEST(ChargeModelTest, DipoleMomentSingleAtomIsZero)
{
  // dipoleMoment() special-cases atomCount() < 2.
  Molecule molecule;
  molecule.addAtom(6);
  FixedRowsChargeModel model(1);

  const Vector3 dipole = model.dipoleMoment(molecule);
  EXPECT_EQ(dipole, Vector3(0.0, 0.0, 0.0));
}

TEST(ChargeModelTest, PotentialIsFiniteAndBoundedByChargeCount)
{
  Molecule molecule = waterMolecule();
  FixedRowsChargeModel model(2); // only O and the first H contribute

  const Vector3 probe(3.0, 1.0, -2.0);
  const double potential = model.potential(molecule, probe);
  EXPECT_TRUE(std::isfinite(potential));

  const double expected = 1.0 / (Vector3(0.0, 0.0, 0.0) - probe).norm() +
                          1.0 / (Vector3(0.6, -0.5, 0.0) - probe).norm();
  EXPECT_NEAR(potential, expected, 1e-9);
}

TEST(ChargeModelTest, PotentialsBatchMatchesIndividualPotential)
{
  Molecule molecule = waterMolecule();
  FixedRowsChargeModel model(3);

  Array<Vector3> points;
  points.push_back(Vector3(2.0, 0.0, 0.0));
  points.push_back(Vector3(0.0, 2.0, 0.0));
  points.push_back(Vector3(-1.0, -1.0, 3.0));

  const Array<double> batch = model.potentials(molecule, points);
  ASSERT_EQ(batch.size(), points.size());
  for (size_t i = 0; i < points.size(); ++i) {
    const double single = model.potential(molecule, points[i]);
    EXPECT_TRUE(std::isfinite(batch[i]));
    EXPECT_DOUBLE_EQ(batch[i], single);
  }
}

TEST(ChargeModelTest, PotentialsEmptyPointListReturnsEmpty)
{
  Molecule molecule = waterMolecule();
  FixedRowsChargeModel model(3);

  Array<Vector3> points;
  const Array<double> batch = model.potentials(molecule, points);
  EXPECT_TRUE(batch.empty());
}

TEST(ChargeModelTest, DielectricScalesPotential)
{
  Molecule molecule = waterMolecule();
  FixedRowsChargeModel model(3);

  const Vector3 probe(2.0, 0.0, 0.0);
  EXPECT_FLOAT_EQ(model.dielectric(), 1.0f);
  const double unscaled = model.potential(molecule, probe);

  model.setDielectric(2.0f);
  EXPECT_FLOAT_EQ(model.dielectric(), 2.0f);
  const double scaled = model.potential(molecule, probe);

  EXPECT_NEAR(scaled, unscaled / 2.0, 1e-9);
}

TEST(ChargeModelTest, PotentialDropsVeryCloseDistancesToAvoidOverflow)
{
  // potential() skips contributions closer than 0.01 A to avoid a near-
  // singular 1/distance term; probing exactly at an atom position must stay
  // finite rather than blow up.
  Molecule molecule = waterMolecule();
  FixedRowsChargeModel model(3);

  const double potential = model.potential(molecule, Vector3(0.0, 0.0, 0.0));
  EXPECT_TRUE(std::isfinite(potential));
}

TEST(ChargeModelTest, NoChargeColumnYieldsZeroResults)
{
  class NoColumnModel : public ChargeModel
  {
  public:
    ChargeModel* newInstance() const override { return new NoColumnModel; }
    std::string identifier() const override { return "no_column"; }
    std::string name() const override { return "No Column"; }
    Molecule::ElementMask elements() const override
    {
      Molecule::ElementMask mask;
      mask.set();
      return mask;
    }
    MatrixX partialCharges(Molecule& mol) const override
    {
      return MatrixX(static_cast<Eigen::Index>(mol.atomCount()), 0);
    }
    MatrixX partialCharges(const Molecule& mol) const override
    {
      return MatrixX(static_cast<Eigen::Index>(mol.atomCount()), 0);
    }
  };

  Molecule molecule = waterMolecule();
  NoColumnModel model;

  const Vector3 dipole = model.dipoleMoment(molecule);
  EXPECT_EQ(dipole, Vector3(0.0, 0.0, 0.0));

  const double potential = model.potential(molecule, Vector3(2.0, 0.0, 0.0));
  EXPECT_DOUBLE_EQ(potential, 0.0);
}
