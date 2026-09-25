/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "conformerquantity.h"

#include "molecule.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace Avogadro::Core {

namespace {

// Trajectories rarely say how far apart their frames are, and everything
// measured against time needs an answer, so one picosecond stands in.
constexpr double DefaultFrameInterval = 1.0;
const char* const FrameIntervalKey = "frameInterval";
const char* const EnergyUnitKey = "energyUnit";
// What the stored velocities were last differenced at, so that a changed
// frame interval is noticed without re-deriving the whole trajectory to find
// out that nothing moved.
const char* const VelocityIntervalKey = "velocityInterval";
// Stamped instead of an interval when the velocities were differenced across
// the times the file recorded rather than at one fixed spacing. No real
// interval is ever zero, so the two cannot be confused.
constexpr double RecordedTimesUsed = 0.0;

// Read a per-coordinate-set list out of the property map. Empty when the
// molecule does not carry that key, which is how an unavailable quantity is
// reported all the way up.
std::vector<double> storedList(const Molecule& molecule, const char* key)
{
  if (!molecule.hasData(key))
    return {};
  return molecule.data(key).toList();
}

std::vector<double> frameSeries(const Molecule& molecule)
{
  std::vector<double> values(molecule.coordinate3dCount());
  for (size_t i = 0; i < values.size(); ++i)
    values[i] = static_cast<double>(i);
  return values;
}

// True when the user has named the interval themselves. That answer is about
// this trajectory and overrides whatever the file recorded -- which is the
// whole point for a LAMMPS dump, whose "times" are step numbers.
bool hasFrameIntervalOverride(const Molecule& molecule)
{
  return molecule.hasData(FrameIntervalKey) &&
         molecule.data(FrameIntervalKey).toDouble() > 0.0;
}

// The time recorded for each coordinate set, when the file recorded one for
// every one of them; empty otherwise. These need not be evenly spaced: a
// trajectory written every n steps of a variable-timestep integrator is not.
std::vector<double> recordedTimes(const Molecule& molecule)
{
  const size_t count = molecule.coordinate3dCount();
  std::vector<double> times;
  times.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    bool recorded = false;
    const double time = molecule.timeStep(static_cast<int>(i), recorded);
    if (!recorded)
      return {};
    times.push_back(time);
  }
  return times;
}

std::vector<double> timeSeries(const Molecule& molecule)
{
  // What the file recorded beats a spacing worked out from its ends: those
  // are the times the frames were actually written at, and flattening them to
  // an average would put every point in the middle of a gap on the wrong side
  // of it.
  if (!hasFrameIntervalOverride(molecule)) {
    std::vector<double> recorded = recordedTimes(molecule);
    if (!recorded.empty())
      return recorded;
  }

  const size_t count = molecule.coordinate3dCount();
  const double interval = frameInterval(molecule);

  std::vector<double> values(count);
  for (size_t i = 0; i < count; ++i)
    values[i] = static_cast<double>(i) * interval;
  return values;
}

std::vector<double> rmsdSeries(const Molecule& molecule)
{
  const size_t count = molecule.coordinate3dCount();
  if (count == 0)
    return {};

  const Array<Vector3>& reference = molecule.coordinate3dRef(0);
  if (reference.empty())
    return {};

  std::vector<double> values(count, 0.0);
  for (size_t i = 0; i < count; ++i) {
    const Array<Vector3>& positions = molecule.coordinate3dRef(i);
    // The sets should all describe the same atoms, but compare only as far as
    // both of them go rather than reading off the end of the reference.
    const size_t atoms = std::min(positions.size(), reference.size());
    if (atoms == 0)
      continue;

    double sum = 0.0;
    for (size_t j = 0; j < atoms; ++j)
      sum += (positions[j] - reference[j]).squaredNorm();

    // The mean is over the atoms compared, not over the coordinate sets.
    values[i] = std::sqrt(sum / atoms);
  }

  return values;
}

std::vector<double> energySeries(const Molecule& molecule)
{
  std::vector<double> energies = storedList(molecule, "energies");
  if (energies.empty())
    return {};

  // Relative to the lowest set: the absolute value of a total energy says
  // nothing a reader wants, and differs by hundreds of Hartree between methods.
  const double minimum = *std::min_element(energies.begin(), energies.end());
  for (double& energy : energies)
    energy -= minimum;

  return energies;
}

std::vector<double> coordinateSeries(const Molecule& molecule,
                                     const Constraint& coordinate)
{
  const size_t count = molecule.coordinate3dCount();
  std::vector<double> values;
  values.reserve(count);

  // coordinate3dRef() hands back the stored set rather than a copy of it, so
  // reading four atoms out of every frame does not copy the whole molecule
  // once per frame. It does not change the displayed set either, so this reads
  // the trajectory without disturbing the active conformer.
  for (size_t i = 0; i < count; ++i) {
    Real value = 0.0;
    if (!coordinate.evaluate(molecule.coordinate3dRef(i), value))
      return {};
    values.push_back(static_cast<double>(value));
  }

  return values;
}

} // namespace

std::string ConformerQuantity::identifier() const
{
  switch (m_type) {
    case Type::Frame:
      return "frame";
    case Type::Time:
      return "time";
    case Type::Rmsd:
      return "rmsd";
    case Type::Energy:
      return "energy";
    case Type::Forces:
      return "forces";
    case Type::MeanSpeed:
      return "meanSpeed";
    case Type::Temperature:
      return "temperature";
    case Type::Coordinate:
      return "coordinate:" + std::to_string(m_coordinate.aIndex()) + ":" +
             std::to_string(m_coordinate.bIndex()) + ":" +
             std::to_string(m_coordinate.cIndex()) + ":" +
             std::to_string(m_coordinate.dIndex());
  }
  return "frame";
}

std::string ConformerQuantity::unit() const
{
  switch (m_type) {
    case Type::Time:
      return "ps";
    case Type::Rmsd:
      return "Å";
    case Type::MeanSpeed:
      return "Å/ps";
    case Type::Temperature:
      return "K";
    case Type::Coordinate:
      switch (m_coordinate.type()) {
        case Constraint::DistanceConstraint:
          return "Å";
        case Constraint::AngleConstraint:
        case Constraint::TorsionConstraint:
          return "°";
        default:
          return std::string();
      }
    // Frame counts rather than measures. Energies and gradients arrive in
    // whatever unit the file used, which only the reader knows.
    case Type::Frame:
    case Type::Energy:
    case Type::Forces:
      break;
  }
  return std::string();
}

std::vector<ConformerQuantity> conformerQuantities(const Molecule& molecule)
{
  using Type = ConformerQuantity::Type;

  std::vector<ConformerQuantity> quantities;

  // Velocities are differenced between neighbouring sets, so a single
  // geometry has none -- and the frame interval supplies what the file leaves
  // out, which puts these on offer for any trajectory rather than only one
  // that stored velocities.
  const bool isTrajectory = molecule.coordinate3dCount() > 1;

  quantities.emplace_back(Type::Frame);
  if (isTrajectory)
    quantities.emplace_back(Type::Time);
  quantities.emplace_back(Type::Rmsd);
  if (molecule.hasData("energies"))
    quantities.emplace_back(Type::Energy);
  if (molecule.hasData("forces"))
    quantities.emplace_back(Type::Forces);
  if (isTrajectory)
    quantities.emplace_back(Type::MeanSpeed);
  // Temperature comes out of the kinetic energy once the drift of the whole
  // molecule is removed, and a single atom has nothing left after that.
  if (isTrajectory && molecule.atomCount() > 1)
    quantities.emplace_back(Type::Temperature);

  const Index atoms = molecule.atomCount();

  // Constraints first: they are what an optimizer was told to hold, so they
  // are the likeliest thing a relaxed scan stepped through.
  for (const auto& constraint : molecule.constraints()) {
    // An out-of-plane constraint has no single value, and one left over from
    // deleted atoms would measure to the origin.
    if (constraint.isValid(atoms))
      quantities.emplace_back(constraint);
  }

  // Then coordinates the user asked to follow, which a file may also carry.
  for (const auto& coordinate : molecule.scanCoordinates()) {
    if (!coordinate.isValid(atoms))
      continue;

    const ConformerQuantity candidate(coordinate);
    const bool duplicate =
      std::any_of(quantities.begin(), quantities.end(),
                  [&candidate](const ConformerQuantity& existing) {
                    return existing == candidate;
                  });
    if (!duplicate)
      quantities.push_back(candidate);
  }

  return quantities;
}

std::vector<double> evaluateConformerQuantity(const Molecule& molecule,
                                              const ConformerQuantity& quantity)
{
  using Type = ConformerQuantity::Type;

  if (molecule.coordinate3dCount() == 0)
    return {};

  switch (quantity.type()) {
    case Type::Frame:
      return frameSeries(molecule);
    case Type::Time:
      return timeSeries(molecule);
    case Type::Rmsd:
      return rmsdSeries(molecule);
    case Type::Energy:
      return energySeries(molecule);
    case Type::Forces:
      return storedList(molecule, "forces");
    case Type::MeanSpeed:
      return storedList(molecule, "velocities");
    case Type::Temperature:
      return storedList(molecule, "temperatures");
    case Type::Coordinate:
      return coordinateSeries(molecule, quantity.coordinate());
  }

  return {};
}

std::vector<double> conformerQuantitySpread(const Molecule& molecule,
                                            const ConformerQuantity& quantity)
{
  if (quantity.type() != ConformerQuantity::Type::MeanSpeed)
    return {};

  return storedList(molecule, "velocityDeviations");
}

std::string energyUnit(const Molecule& molecule)
{
  if (!molecule.hasData(EnergyUnitKey))
    return std::string();
  return molecule.data(EnergyUnitKey).toString();
}

void setEnergyUnit(Molecule& molecule, const std::string& unit)
{
  molecule.setData(EnergyUnitKey, unit);
}

double frameInterval(const Molecule& molecule)
{
  if (molecule.hasData(FrameIntervalKey)) {
    const double stored = molecule.data(FrameIntervalKey).toDouble();
    if (stored > 0.0)
      return stored;
  }

  // Nothing set, so fall back to what the file recorded. DCD gives a real
  // interval in picoseconds; a LAMMPS dump records the step number instead and
  // carries no timestep anywhere to turn that into a time, so what comes back
  // there is a step count for the user to correct.
  const size_t count = molecule.coordinate3dCount();
  if (count > 1) {
    bool haveFirst = false;
    bool haveLast = false;
    const double first = molecule.timeStep(0, haveFirst);
    const double last =
      molecule.timeStep(static_cast<int>(count) - 1, haveLast);
    if (haveFirst && haveLast) {
      const double spacing = (last - first) / static_cast<double>(count - 1);
      if (spacing > 0.0)
        return spacing;
    }
  }

  return DefaultFrameInterval;
}

void setFrameInterval(Molecule& molecule, double interval)
{
  if (interval > 0.0)
    molecule.setData(FrameIntervalKey, interval);
}

bool ensureConformerVelocities(Molecule& molecule, bool force)
{
  const size_t count = molecule.coordinate3dCount();
  if (count < 2)
    return false;

  const std::vector<double> speeds = storedList(molecule, "velocities");

  // Velocities that arrived with the file are the real thing, and must not be
  // differenced over. The stamp is what tells them apart: it is written only
  // where these velocities were worked out here, so velocities of our own
  // that have gone stale are not mistaken for a reader's and patched up from
  // where the atoms used to be.
  const bool ours = molecule.hasData(VelocityIntervalKey);
  if (!ours && !molecule.velocities(0).empty()) {
    // They may have come in without the derived properties, if whoever called
    // setVelocities() did not ask for them.
    if (speeds.size() != count)
      molecule.updateVelocityProperties();
    return !storedList(molecule, "velocities").empty();
  }

  // Difference across the times the file recorded where it recorded them, and
  // at one fixed spacing otherwise -- the same rule the time axis follows, so
  // a speed read off the plot matches its own x coordinate.
  const bool useRecordedTimes =
    !hasFrameIntervalOverride(molecule) && !recordedTimes(molecule).empty();
  const double interval = frameInterval(molecule);
  const double stamp = useRecordedTimes ? RecordedTimesUsed : interval;

  // Still current: one value per coordinate set, worked out on the time base
  // still in force. Re-differencing a long trajectory for nothing is the
  // thing worth avoiding here -- both axes of a plot ask for this.
  const bool sameTimeBase =
    ours &&
    std::abs(molecule.data(VelocityIntervalKey).toDouble() - stamp) < 1e-12;
  if (!force && speeds.size() == count && sameTimeBase)
    return true;

  if (useRecordedTimes)
    molecule.estimateVelocities();
  else
    molecule.estimateVelocities(interval);
  molecule.setData(VelocityIntervalKey, stamp);

  return !storedList(molecule, "velocities").empty();
}

} // namespace Avogadro::Core
