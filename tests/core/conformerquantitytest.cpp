/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/conformerquantity.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <algorithm>

using Avogadro::Index;
using Avogadro::MaxIndex;
using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::Core::ConformerQuantity;
using Avogadro::Core::Constraint;
using Avogadro::Core::Molecule;
using Type = ConformerQuantity::Type;

namespace {

// Three atoms so that a distance, an angle and a temperature all have
// something to measure, spread over @p sets geometries a fixed step apart.
Molecule trajectory(size_t sets)
{
  Molecule molecule;
  molecule.addAtom(8);
  molecule.addAtom(1);
  molecule.addAtom(1);

  for (size_t i = 0; i < sets; ++i) {
    Array<Vector3> coords;
    coords.push_back(Vector3(0.0, 0.0, 0.0));
    // The O-H distance grows by 0.1 Angstrom per set, so a coordinate column
    // has something that actually changes.
    coords.push_back(Vector3(1.0 + 0.1 * i, 0.0, 0.0));
    coords.push_back(Vector3(0.0, 1.0, 0.0));
    molecule.setCoordinate3d(coords, i);
  }

  return molecule;
}

bool offers(const std::vector<ConformerQuantity>& quantities, Type type)
{
  return std::any_of(quantities.begin(), quantities.end(),
                     [type](const ConformerQuantity& quantity) {
                       return quantity.type() == type;
                     });
}

const ConformerQuantity& find(const std::vector<ConformerQuantity>& quantities,
                              Type type)
{
  auto it = std::find_if(quantities.begin(), quantities.end(),
                         [type](const ConformerQuantity& quantity) {
                           return quantity.type() == type;
                         });
  EXPECT_NE(it, quantities.end());
  return *it;
}

} // namespace

// A single geometry is not a trajectory: nothing that needs two coordinate
// sets to difference should be on offer for it.
TEST(ConformerQuantityTest, singleGeometryOffersNoDynamics)
{
  Molecule molecule = trajectory(1);

  const auto quantities = Avogadro::Core::conformerQuantities(molecule);
  EXPECT_TRUE(offers(quantities, Type::Frame));
  EXPECT_TRUE(offers(quantities, Type::Rmsd));
  EXPECT_FALSE(offers(quantities, Type::Time));
  EXPECT_FALSE(offers(quantities, Type::MeanSpeed));
  EXPECT_FALSE(offers(quantities, Type::Temperature));
  EXPECT_FALSE(offers(quantities, Type::Energy));
}

TEST(ConformerQuantityTest, trajectoryOffersDynamics)
{
  Molecule molecule = trajectory(4);

  const auto quantities = Avogadro::Core::conformerQuantities(molecule);
  EXPECT_TRUE(offers(quantities, Type::Time));
  EXPECT_TRUE(offers(quantities, Type::MeanSpeed));
  EXPECT_TRUE(offers(quantities, Type::Temperature));
  // Nothing supplied energies or gradients, so they are not on offer.
  EXPECT_FALSE(offers(quantities, Type::Energy));
  EXPECT_FALSE(offers(quantities, Type::Forces));

  molecule.setData("energies", std::vector<double>{ -1.0, -2.0, -1.5, -1.0 });
  EXPECT_TRUE(
    offers(Avogadro::Core::conformerQuantities(molecule), Type::Energy));
}

// Every series has to be one value per coordinate set, in order from the
// first: a plot marker and a table row both find a conformer by its position
// in the series, so a series that skipped one would point at the wrong
// geometry.
TEST(ConformerQuantityTest, everySeriesIsOneValuePerSet)
{
  Molecule molecule = trajectory(5);
  molecule.setData("energies",
                   std::vector<double>{ -1.0, -2.0, -1.5, -1.0, -1.2 });
  Avogadro::Core::ensureConformerVelocities(molecule);

  for (const auto& quantity : Avogadro::Core::conformerQuantities(molecule)) {
    const auto values =
      Avogadro::Core::evaluateConformerQuantity(molecule, quantity);
    EXPECT_EQ(values.size(), static_cast<size_t>(5))
      << "quantity " << quantity.identifier();
  }
}

TEST(ConformerQuantityTest, energiesAreRelativeToTheLowest)
{
  Molecule molecule = trajectory(3);
  molecule.setData("energies", std::vector<double>{ -75.5, -76.0, -75.75 });

  const auto quantities = Avogadro::Core::conformerQuantities(molecule);
  const auto values = Avogadro::Core::evaluateConformerQuantity(
    molecule, find(quantities, Type::Energy));

  ASSERT_EQ(values.size(), static_cast<size_t>(3));
  EXPECT_NEAR(values[0], 0.5, 1e-9);
  EXPECT_NEAR(values[1], 0.0, 1e-9);
  EXPECT_NEAR(values[2], 0.25, 1e-9);
}

// The time axis and the velocities have to be differenced with the same
// interval, or a speed read off the plot would not match its own time axis.
TEST(ConformerQuantityTest, frameIntervalDrivesTimeAndSpeed)
{
  Molecule molecule = trajectory(3);

  // Nothing set and no timesteps stored, so one picosecond stands in.
  EXPECT_NEAR(Avogadro::Core::frameInterval(molecule), 1.0, 1e-12);

  Avogadro::Core::setFrameInterval(molecule, 0.5);
  EXPECT_NEAR(Avogadro::Core::frameInterval(molecule), 0.5, 1e-12);

  const auto quantities = Avogadro::Core::conformerQuantities(molecule);
  const auto times = Avogadro::Core::evaluateConformerQuantity(
    molecule, find(quantities, Type::Time));
  ASSERT_EQ(times.size(), static_cast<size_t>(3));
  EXPECT_NEAR(times[0], 0.0, 1e-12);
  EXPECT_NEAR(times[1], 0.5, 1e-12);
  EXPECT_NEAR(times[2], 1.0, 1e-12);

  // One atom moves 0.1 Angstrom per set and the other two do not, so the mean
  // speed over three atoms is (0.1 / 0.5) / 3.
  Avogadro::Core::ensureConformerVelocities(molecule);
  const auto speeds = Avogadro::Core::evaluateConformerQuantity(
    molecule, find(quantities, Type::MeanSpeed));
  ASSERT_EQ(speeds.size(), static_cast<size_t>(3));
  EXPECT_NEAR(speeds[1], 0.2 / 3.0, 1e-9);
}

// Halving the interval doubles the speeds, and the change has to be noticed
// without anyone saying so.
TEST(ConformerQuantityTest, changedIntervalRedoesTheVelocities)
{
  Molecule molecule = trajectory(3);
  Avogadro::Core::setFrameInterval(molecule, 1.0);
  ASSERT_TRUE(Avogadro::Core::ensureConformerVelocities(molecule));

  const auto quantities = Avogadro::Core::conformerQuantities(molecule);
  const ConformerQuantity& speed = find(quantities, Type::MeanSpeed);
  const double before =
    Avogadro::Core::evaluateConformerQuantity(molecule, speed)[1];

  Avogadro::Core::setFrameInterval(molecule, 0.5);
  ASSERT_TRUE(Avogadro::Core::ensureConformerVelocities(molecule));
  const double after =
    Avogadro::Core::evaluateConformerQuantity(molecule, speed)[1];

  EXPECT_NEAR(after, 2.0 * before, 1e-9);
}

// A stored timestep is believed over the 1 ps default -- DCD records a real
// interval, and the reader converts it to picoseconds.
TEST(ConformerQuantityTest, storedTimestepsSetTheInterval)
{
  Molecule molecule = trajectory(4);
  for (int i = 0; i < 4; ++i)
    molecule.setTimeStep(2.0 * i, i);

  EXPECT_NEAR(Avogadro::Core::frameInterval(molecule), 2.0, 1e-12);

  // An interval the user set wins over the file's: a LAMMPS dump stores step
  // numbers rather than times, and correcting that is the whole point.
  Avogadro::Core::setFrameInterval(molecule, 0.25);
  EXPECT_NEAR(Avogadro::Core::frameInterval(molecule), 0.25, 1e-12);
}

TEST(ConformerQuantityTest, scanCoordinatesBecomeQuantities)
{
  Molecule molecule = trajectory(3);
  molecule.addScanCoordinate(Constraint(0, 1));

  const auto quantities = Avogadro::Core::conformerQuantities(molecule);
  ASSERT_TRUE(offers(quantities, Type::Coordinate));

  const ConformerQuantity& coordinate = find(quantities, Type::Coordinate);
  EXPECT_EQ(coordinate.unit(), "Å");
  EXPECT_EQ(coordinate.identifier(),
            "coordinate:0:1:" + std::to_string(MaxIndex) + ":" +
              std::to_string(MaxIndex));

  // The O-H distance grows by 0.1 Angstrom per set, which is what a relaxed
  // scan plotted against this column should show.
  const auto values =
    Avogadro::Core::evaluateConformerQuantity(molecule, coordinate);
  ASSERT_EQ(values.size(), static_cast<size_t>(3));
  EXPECT_NEAR(values[0], 1.0, 1e-9);
  EXPECT_NEAR(values[1], 1.1, 1e-9);
  EXPECT_NEAR(values[2], 1.2, 1e-9);
}

// A constraint and a scan coordinate over the same atoms are the same thing to
// measure, and must not turn into two columns saying the same number.
TEST(ConformerQuantityTest, duplicateCoordinatesAreListedOnce)
{
  Molecule molecule = trajectory(3);
  Constraint held(0, 1);
  molecule.addConstraint(held);
  molecule.addScanCoordinate(Constraint(0, 1));

  const auto quantities = Avogadro::Core::conformerQuantities(molecule);
  const auto coordinates =
    std::count_if(quantities.begin(), quantities.end(),
                  [](const ConformerQuantity& quantity) {
                    return quantity.type() == Type::Coordinate;
                  });
  EXPECT_EQ(coordinates, 1);
}

// Identifiers are how a plot remembers which axis the user chose across a
// rebuild of the list, so they have to be distinct and stable.
TEST(ConformerQuantityTest, identifiersAreUnique)
{
  Molecule molecule = trajectory(3);
  molecule.setData("energies", std::vector<double>{ -1.0, -2.0, -1.5 });
  molecule.addScanCoordinate(Constraint(0, 1));
  molecule.addScanCoordinate(Constraint(0, 1, 2));

  const auto quantities = Avogadro::Core::conformerQuantities(molecule);
  std::vector<std::string> identifiers;
  for (const auto& quantity : quantities)
    identifiers.push_back(quantity.identifier());

  std::sort(identifiers.begin(), identifiers.end());
  EXPECT_EQ(std::adjacent_find(identifiers.begin(), identifiers.end()),
            identifiers.end());
  EXPECT_EQ(identifiers.size(), quantities.size());
}
