/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_TESTS_SHADOWMOLECULE_H
#define AVOGADRO_TESTS_SHADOWMOLECULE_H

// A deliberately dumb "shadow" of a Core::Molecule, for tests that need to
// know that every value is still attached to the right atom or bond after
// add / swap / remove / copy / move / undo / redo.
//
// The shadow keeps one plain record per atom and per bond, tagged with an
// identity that never changes. It never looks at the molecule's own arrays:
// each mutation is applied to the shadow by the documented rules (swap-and-pop
// removal, swapAtom() exchanging two slots, addAtom()/addBond()/removeBond()
// discarding calculated results) and verify() then compares what the molecule
// reports, atom by atom and bond by bond, through its public getters.
//
// "Unset" is modelled by the getters' own defaults. Optional per-atom arrays
// may legally be shorter than atomCount() (an atom added after the array was
// last set has no entry), so a record that has never been given a value and a
// record holding the default are indistinguishable to the outside world; the
// tests make the arrays ragged on purpose by setting a property and then
// adding atoms without setting it.
//
// Constraints, scan coordinates and residues name atoms by index without being
// atom-indexed themselves, so they are modelled by atom identity as well (see
// Reference and ResidueRecord). Constraints and scan coordinates follow the
// rules in remapAtomReferences(): swapAtom() relabels them, removeAtom() drops
// any that names the removed atom and moves the former last atom's references
// into the hole, clearAtoms() drops them all. Residues repoint on swapAtom(),
// copy and move. removeAtom() removes every residue that names the removed
// atom, whole and with its label and custom property, keeping the order of
// the others (plans/molecule-refactor-plan.md, section 4.6); the atoms it
// named stay in the molecule, in no residue.
//
// Not modelled, on purpose (see the report accompanying this test):
//   basis sets (atom centres), unit cells, meshes, cubes, spectra, layer ids
//   as such (only each atom's layer), conformer properties, the custom
//   element map, per-residue colors and residue properties other than one
//   double column.

#include <avogadro/core/atom.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/propertymap.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/vector.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

// Tests that exercise the deprecated Residue accessors on purpose wrap the
// calls in these, so that the rest of the build can stay warning-free.
#if defined(_MSC_VER)
#define SHADOW_BEGIN_DEPRECATED                                                \
  __pragma(warning(push)) __pragma(warning(disable : 4996))
#define SHADOW_END_DEPRECATED __pragma(warning(pop))
#elif defined(__GNUC__) || defined(__clang__)
#define SHADOW_BEGIN_DEPRECATED                                                \
  _Pragma("GCC diagnostic push")                                               \
    _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#define SHADOW_END_DEPRECATED _Pragma("GCC diagnostic pop")
#else
#define SHADOW_BEGIN_DEPRECATED
#define SHADOW_END_DEPRECATED
#endif

namespace ShadowModel {

using Avogadro::Index;
using Avogadro::MatrixX;
using Avogadro::Vector2;
using Avogadro::Vector3;
using Avogadro::Vector3ub;

inline const char* kAtomDoubleProperty = "shadow-d";
inline const char* kAtomStringProperty = "shadow-s";
inline const char* kAtomMatrixProperty = "shadow-m";
inline const char* kBondDoubleProperty = "shadow-bd";
inline const char* kBondIntProperty = "shadow-bi";
inline const char* kResidueDoubleProperty = "shadow-rd";

struct Atom
{
  Index id = 0; // identity: never changes for the life of the atom
  unsigned char atomicNumber = 0;
  Vector3 position3d = Vector3::Zero();
  Vector2 position2d = Vector2::Zero();
  std::string label;
  signed char formalCharge = 0;
  Avogadro::Core::AtomHybridization hybridization =
    Avogadro::Core::HybridizationUnknown;
  unsigned short isotope = 0;
  double occupancy = 1.0;         // unset: a full site
  std::string disorderAssembly;   // unset: the implicit assembly
  std::string disorderGroup;      // unset: not disordered
  std::optional<Vector3ub> color; // unset: the element's colour
  bool selected = false;
  bool frozen[3] = { false, false, false };
  size_t layer = 0;

  // Calculated results: dropped by any atom or bond being added or removed.
  Vector3 force = Vector3::Zero();
  std::map<std::string, double> partialCharges;
  std::vector<Vector3> velocities; // one per velocity set
  std::vector<Vector3> modes;      // one per vibrational mode

  std::vector<Vector3> frames; // one per coordinate set

  std::optional<double> doubleProperty;
  std::optional<std::string> stringProperty;
  std::optional<double> matrixProperty; // the sole entry of a 1x1 matrix
};

struct Bond
{
  Index id = 0;
  Index atomA = 0; // atom identities, not indices
  Index atomB = 0;
  unsigned char order = 1;
  std::string label;
  std::optional<double> doubleProperty;
  std::optional<int> intProperty;
};

// A constraint or scan coordinate: up to four atom identities, the unused ones
// MaxIndex. Scan coordinates carry no value, so theirs stays zero.
struct Reference
{
  std::array<Index, 4> atoms = { Avogadro::MaxIndex, Avogadro::MaxIndex,
                                 Avogadro::MaxIndex, Avogadro::MaxIndex };
  double value = 0.0;

  bool names(Index atomId) const
  {
    return std::find(atoms.begin(), atoms.end(), atomId) != atoms.end();
  }
};

// A residue: its own fields and which atom each atom name refers to, by
// identity.
struct ResidueRecord
{
  std::string name;
  Index number = 0;
  char chain = 'A';
  bool heterogen = false;
  Avogadro::Core::Residue::SecondaryStructure secondary =
    Avogadro::Core::Residue::undefined;
  std::map<std::string, Index> members; // atom name -> atom identity
  std::string label;                    // empty: no custom label
  std::optional<double> doubleProperty;

  bool names(Index atomId) const
  {
    for (const auto& member : members)
      if (member.second == atomId)
        return true;
    return false;
  }
};

inline std::string str(const Vector3& v)
{
  std::ostringstream out;
  out << "(" << v.x() << ", " << v.y() << ", " << v.z() << ")";
  return out.str();
}

inline std::string str(const Vector2& v)
{
  std::ostringstream out;
  out << "(" << v.x() << ", " << v.y() << ")";
  return out.str();
}

inline std::string str(const Vector3ub& v)
{
  std::ostringstream out;
  out << "(" << int(v.x()) << ", " << int(v.y()) << ", " << int(v.z()) << ")";
  return out.str();
}

template <typename T>
std::string str(const std::optional<T>& v)
{
  if (!v)
    return "unset";
  std::ostringstream out;
  out << *v;
  return out.str();
}

// How many seeds a randomised shadow test runs: @p fallback unless the
// environment variable AVOGADRO_SHADOW_SEEDS names another number, which lets
// a soak run cover hundreds of seeds without touching the source.
inline unsigned seedCount(unsigned fallback)
{
  const char* text = std::getenv("AVOGADRO_SHADOW_SEEDS");
  if (text == nullptr)
    return fallback;
  const long value = std::strtol(text, nullptr, 10);
  return value > 0 ? static_cast<unsigned>(value) : fallback;
}

inline unsigned elementBit(unsigned char number)
{
  return number < Avogadro::Core::element_count
           ? number
           : static_cast<unsigned>(Avogadro::Core::element_count - 1);
}

class Model
{
public:
  std::vector<Atom> atoms; // in molecule index order
  std::vector<Bond> bonds; // in molecule index order (see syncBondOrder())
  size_t frameCount = 0;
  size_t velocitySetCount = 0;
  size_t modeCount = 0;
  std::set<std::string> chargeTypes;
  std::vector<Reference> constraints;
  std::vector<Reference> scanCoordinates;
  std::vector<ResidueRecord> residues;

  Index atomCount() const { return static_cast<Index>(atoms.size()); }
  Index bondCount() const { return static_cast<Index>(bonds.size()); }

  Index indexOf(Index atomId) const
  {
    for (size_t i = 0; i < atoms.size(); ++i)
      if (atoms[i].id == atomId)
        return static_cast<Index>(i);
    return Avogadro::MaxIndex;
  }

  // --- structure ---------------------------------------------------------

  // @p covered says whether the molecule's 3D position array already has an
  // entry for every atom: only then does addAtom(number, position) store the
  // position (see Molecule::addAtom). Pass false for the plain overload.
  // @p fullFrames says which coordinate sets had an entry for every atom
  // before the call; only those are extended, the rest are left as they were,
  // as Molecule::addAtom does. Empty means all of them. The entry is the
  // position when it was stored (@p covered), else the origin.
  Index addAtom(unsigned char number, const Vector3* position = nullptr,
                bool covered = false,
                const std::vector<bool>& fullFrames = std::vector<bool>())
  {
    clearCalculated();
    Atom a;
    a.id = m_nextAtomId++;
    a.atomicNumber = number;
    if (position != nullptr && covered)
      a.position3d = *position;
    a.frames.assign(frameCount, Vector3::Zero());
    for (size_t f = 0; f < frameCount; ++f) {
      if (position != nullptr && covered &&
          (fullFrames.empty() || fullFrames[f]))
        a.frames[f] = *position;
    }
    atoms.push_back(a);
    return a.id;
  }

  // Swap-and-pop, as documented; the bonds on the atom go with it.
  void removeAtom(Index index)
  {
    clearCalculated();
    const Index id = atoms[index].id;
    // An entry that loses an atom is dropped, not shortened.
    auto loses = [id](const Reference& r) { return r.names(id); };
    constraints.erase(
      std::remove_if(constraints.begin(), constraints.end(), loses),
      constraints.end());
    scanCoordinates.erase(
      std::remove_if(scanCoordinates.begin(), scanCoordinates.end(), loses),
      scanCoordinates.end());
    // Plan section 4.6: a residue that names the atom goes, whole, and the
    // others keep their order. The atom that moves into the hole is followed
    // by identity, so nothing else needs doing.
    residues.erase(
      std::remove_if(residues.begin(), residues.end(),
                     [id](const ResidueRecord& r) { return r.names(id); }),
      residues.end());
    bonds.erase(std::remove_if(bonds.begin(), bonds.end(),
                               [id](const Bond& b) {
                                 return b.atomA == id || b.atomB == id;
                               }),
                bonds.end());
    atoms[index] = atoms.back();
    atoms.pop_back();
    // The order the molecule leaves the surviving bonds in is its own
    // business (removeBonds() peels them off the atom one at a time);
    // syncBondOrder() adopts it after the removal.
  }

  void swapAtom(Index a, Index b)
  {
    if (a != b)
      std::swap(atoms[a], atoms[b]);
  }

  // Molecule::clearAtoms(): no atoms, bonds, coordinate sets, calculated
  // results, constraints, scan coordinates or residues are left.
  void clearAtoms()
  {
    clearCalculated();
    atoms.clear();
    bonds.clear();
    frameCount = 0;
    constraints.clear();
    scanCoordinates.clear();
    residues.clear();
  }

  // --- constraints, scan coordinates, residues (arguments are atom indices,
  // MaxIndex for "none") -------------------------------------------------

  Reference reference(const std::array<Index, 4>& indices,
                      double value = 0.0) const
  {
    Reference r;
    r.value = value;
    for (size_t k = 0; k < 4; ++k)
      r.atoms[k] = indices[k] == Avogadro::MaxIndex ? Avogadro::MaxIndex
                                                    : atoms[indices[k]].id;
    return r;
  }

  // The current indices of a reference's atoms.
  std::array<Index, 4> indicesOf(const Reference& r) const
  {
    std::array<Index, 4> out;
    for (size_t k = 0; k < 4; ++k)
      out[k] = indexOf(r.atoms[k]);
    return out;
  }

  void addConstraint(double value, const std::array<Index, 4>& indices)
  {
    constraints.push_back(reference(indices, value));
  }

  // Constraint::matches(): the same atoms in the same order, or in the
  // reverse order with the unused ones kept at the end. Only plain distance,
  // angle and torsion constraints are generated, so there is no out-of-plane
  // exception.
  void removeConstraint(const std::array<Index, 4>& indices)
  {
    const Reference wanted = reference(indices);
    Reference reversed;
    size_t used = 0;
    while (used < 4 && wanted.atoms[used] != Avogadro::MaxIndex)
      ++used;
    for (size_t k = 0; k < used; ++k)
      reversed.atoms[k] = wanted.atoms[used - 1 - k];
    constraints.erase(std::remove_if(constraints.begin(), constraints.end(),
                                     [&](const Reference& r) {
                                       return r.atoms == wanted.atoms ||
                                              r.atoms == reversed.atoms;
                                     }),
                      constraints.end());
  }

  void setScanCoordinates(const std::vector<std::array<Index, 4>>& coordinates)
  {
    scanCoordinates.clear();
    for (const auto& c : coordinates)
      scanCoordinates.push_back(reference(c));
  }

  // Molecule::addScanCoordinate() skips one that is already there.
  void addScanCoordinate(const std::array<Index, 4>& indices)
  {
    const Reference wanted = reference(indices);
    for (const auto& r : scanCoordinates)
      if (r.atoms == wanted.atoms)
        return;
    scanCoordinates.push_back(wanted);
  }

  void addResidue(const ResidueRecord& residue) { residues.push_back(residue); }

  // Molecule::removeResidue(): the later residues move down by one.
  void removeResidue(Index index)
  {
    if (index < residues.size())
      residues.erase(residues.begin() + static_cast<std::ptrdiff_t>(index));
  }

  void addBond(Index a, Index b, unsigned char order)
  {
    partialChargesGone();
    const Index ida = atoms[a].id;
    const Index idb = atoms[b].id;
    for (auto& bond : bonds) {
      if ((bond.atomA == ida && bond.atomB == idb) ||
          (bond.atomA == idb && bond.atomB == ida)) {
        bond.order = order;
        return;
      }
    }
    Bond bond;
    bond.id = m_nextBondId++;
    bond.atomA = ida;
    bond.atomB = idb;
    bond.order = order;
    bonds.push_back(bond);
  }

  void removeBond(Index index)
  {
    clearCalculated();
    bonds[index] = bonds.back();
    bonds.pop_back();
  }

  // Keeps vibrations and the like on purpose; only partial charges go.
  void clearBonds()
  {
    partialChargesGone();
    bonds.clear();
  }

  void swapBond(Index a, Index b)
  {
    if (a != b)
      std::swap(bonds[a], bonds[b]);
  }

  // --- state that is not part of the structure ---------------------------

  void setCoordinateSet(size_t index, const std::vector<Vector3>& coords)
  {
    if (index == frameCount) {
      ++frameCount;
      for (auto& a : atoms)
        a.frames.push_back(Vector3::Zero());
    }
    for (size_t i = 0; i < atoms.size(); ++i)
      atoms[i].frames[index] = i < coords.size() ? coords[i] : Vector3::Zero();
  }

  void activateCoordinateSet(size_t index)
  {
    for (auto& a : atoms)
      a.position3d = a.frames[index];
  }

  void setVelocitySet(size_t index, const std::vector<Vector3>& values)
  {
    if (index == velocitySetCount) {
      ++velocitySetCount;
      for (auto& a : atoms)
        a.velocities.push_back(Vector3::Zero());
    }
    for (size_t i = 0; i < atoms.size(); ++i)
      atoms[i].velocities[index] =
        i < values.size() ? values[i] : Vector3::Zero();
  }

  // @p modes[m][i] is the displacement of atom i in mode m; a mode may cover
  // fewer atoms than there are.
  void setVibrations(const std::vector<std::vector<Vector3>>& modes)
  {
    modeCount = modes.size();
    for (size_t i = 0; i < atoms.size(); ++i) {
      atoms[i].modes.clear();
      for (const auto& mode : modes)
        atoms[i].modes.push_back(i < mode.size() ? mode[i] : Vector3::Zero());
    }
  }

  void setPartialCharges(const std::string& type,
                         const std::vector<double>& values)
  {
    chargeTypes.insert(type);
    for (size_t i = 0; i < atoms.size(); ++i)
      atoms[i].partialCharges[type] = values[i];
  }

  // Adopt the order in which @p mol lists its bonds. Used after removeAtom(),
  // where that order is not specified. Every molecule bond must still match
  // exactly one shadow bond, by atom identities; returns an error otherwise.
  std::string syncBondOrder(const Avogadro::Core::Molecule& mol)
  {
    if (mol.bondCount() != bondCount() || mol.atomCount() != atomCount()) {
      std::ostringstream out;
      out << "counts differ after removal: molecule has " << mol.atomCount()
          << " atoms / " << mol.bondCount() << " bonds, shadow has "
          << atomCount() << " / " << bondCount();
      return out.str();
    }
    std::vector<Bond> ordered;
    std::vector<bool> used(bonds.size(), false);
    for (Index i = 0; i < mol.bondCount(); ++i) {
      const auto pair = mol.bondPair(i);
      if (pair.first >= atomCount() || pair.second >= atomCount())
        return "bond endpoint out of range after removal";
      const Index ida = atoms[pair.first].id;
      const Index idb = atoms[pair.second].id;
      bool found = false;
      for (size_t j = 0; j < bonds.size(); ++j) {
        if (used[j])
          continue;
        if ((bonds[j].atomA == ida && bonds[j].atomB == idb) ||
            (bonds[j].atomA == idb && bonds[j].atomB == ida)) {
          used[j] = true;
          ordered.push_back(bonds[j]);
          found = true;
          break;
        }
      }
      if (!found) {
        std::ostringstream out;
        out << "bond " << i << " joins atoms with ids " << ida << " and " << idb
            << ", which the shadow does not have a bond between";
        return out.str();
      }
    }
    bonds = ordered;
    return std::string();
  }

  // What removing something and restoring it from a snapshot leaves behind of
  // the calculated results: nothing. Call it on a copy of the model from
  // before the removal to get what the molecule should hold afterwards.
  void discardCalculated() { clearCalculated(); }

private:
  // What Molecule::clearCalculatedResults() drops.
  void partialChargesGone()
  {
    chargeTypes.clear();
    for (auto& a : atoms)
      a.partialCharges.clear();
  }

  void clearCalculated()
  {
    partialChargesGone();
    velocitySetCount = 0;
    modeCount = 0;
    for (auto& a : atoms) {
      a.force = Vector3::Zero();
      a.velocities.clear();
      a.modes.clear();
    }
  }

  Index m_nextAtomId = 1;
  Index m_nextBondId = 1;
};

// Compare @p mol with @p model through the public getters only. Returns an
// empty string when they agree, otherwise a description of the first
// difference, naming the atom or bond by index and identity.
//
// @p checkCalculated says whether to compare the calculated results (forces,
// partial charges, velocities, normal modes), which the library drops when
// the structure changes and which undo therefore cannot be expected to bring
// back. Constraints, scan coordinates and residues are always compared.
inline std::string verify(const Avogadro::Core::Molecule& mol,
                          const Model& model, bool checkCalculated = true)
{
  using Avogadro::Core::Elements;
  std::ostringstream out;

  const Index n = mol.atomCount();
  if (n != model.atomCount()) {
    out << "atomCount: expected " << model.atomCount() << " got " << n;
    return out.str();
  }
  if (mol.bondCount() != model.bondCount()) {
    out << "bondCount: expected " << model.bondCount() << " got "
        << mol.bondCount();
    return out.str();
  }

  // Containers that must never be longer than the molecule.
  if (mol.atomPositions3d().size() > n || mol.atomPositions2d().size() > n ||
      mol.atomLabels().size() > n || mol.colors().size() > n ||
      mol.forceVectors().size() > n) {
    out << "an optional per-atom array is longer than atomCount() == " << n;
    return out.str();
  }

  if (mol.coordinate3dCount() != model.frameCount) {
    out << "coordinate3dCount: expected " << model.frameCount << " got "
        << mol.coordinate3dCount();
    return out.str();
  }
  for (size_t f = 0; f < model.frameCount; ++f) {
    if (mol.coordinate3dRef(f).size() > n) {
      out << "coordinate set " << f << " is longer than atomCount() == " << n;
      return out.str();
    }
  }

  if (checkCalculated && mol.partialChargeTypes() != model.chargeTypes) {
    out << "partialChargeTypes differ (expected " << model.chargeTypes.size()
        << " types, got " << mol.partialChargeTypes().size() << ")";
    return out.str();
  }

  // The element mask is rebuilt from the atoms on removal.
  std::set<unsigned> bits;
  for (const auto& a : model.atoms)
    bits.insert(elementBit(a.atomicNumber));
  const auto mask = mol.elements();
  for (unsigned bit = 0; bit < Avogadro::Core::element_count; ++bit) {
    if (mask.test(bit) != (bits.count(bit) != 0)) {
      out << "elements().test(" << bit << "): expected "
          << (bits.count(bit) != 0) << " got " << mask.test(bit);
      return out.str();
    }
  }

  if (checkCalculated && model.modeCount == 0 &&
      mol.vibrationData(0) != nullptr) {
    out << "vibration data present, expected none";
    return out.str();
  }

  bool anySelected = false;
  for (Index i = 0; i < n; ++i) {
    const Atom& a = model.atoms[i];
    std::ostringstream where;
    where << "atom index " << i << " (id " << a.id << ") ";
    const std::string at = where.str();

#define SHADOW_EXPECT_EQ(field, expected, actual, show)                        \
  do {                                                                         \
    if (!((expected) == (actual))) {                                           \
      out << at << field << ": expected " << show(expected) << " got "         \
          << show(actual);                                                     \
      return out.str();                                                        \
    }                                                                          \
  } while (false)
#define SHADOW_NUM(x) (x)
#define SHADOW_INT(x) static_cast<long>(x)

    SHADOW_EXPECT_EQ("atomicNumber", a.atomicNumber, mol.atomicNumber(i),
                     SHADOW_INT);
    SHADOW_EXPECT_EQ("position3d", a.position3d, mol.atomPosition3d(i), str);
    SHADOW_EXPECT_EQ("position2d", a.position2d, mol.atomPosition2d(i), str);
    SHADOW_EXPECT_EQ("label", a.label, mol.atomLabel(i), SHADOW_NUM);
    SHADOW_EXPECT_EQ("formalCharge", a.formalCharge, mol.formalCharge(i),
                     SHADOW_INT);
    SHADOW_EXPECT_EQ("hybridization", a.hybridization, mol.hybridization(i),
                     SHADOW_INT);
    SHADOW_EXPECT_EQ("isotope", a.isotope, mol.isotope(i), SHADOW_INT);
    SHADOW_EXPECT_EQ("occupancy", a.occupancy, mol.occupancy(i), SHADOW_NUM);
    SHADOW_EXPECT_EQ("disorderAssembly", a.disorderAssembly,
                     mol.disorderAssembly(i), SHADOW_NUM);
    SHADOW_EXPECT_EQ("disorderGroup", a.disorderGroup, mol.disorderGroup(i),
                     SHADOW_NUM);

    const Vector3ub expectedColor =
      a.color ? *a.color : Vector3ub(Elements::color(a.atomicNumber));
    SHADOW_EXPECT_EQ("color", expectedColor, mol.color(i), str);

    SHADOW_EXPECT_EQ("selected", a.selected, mol.atomSelected(i), SHADOW_INT);
    anySelected = anySelected || a.selected;

    for (int axis = 0; axis < 3; ++axis) {
      if (a.frozen[axis] != mol.frozenAtomAxis(i, axis)) {
        out << at << "frozen axis " << axis << ": expected " << a.frozen[axis]
            << " got " << mol.frozenAtomAxis(i, axis);
        return out.str();
      }
    }
    SHADOW_EXPECT_EQ("frozenAtom", (a.frozen[0] && a.frozen[1] && a.frozen[2]),
                     mol.frozenAtom(i), SHADOW_INT);

    SHADOW_EXPECT_EQ("layer", a.layer, mol.layer(i), SHADOW_INT);
    if (checkCalculated)
      SHADOW_EXPECT_EQ("force", a.force, mol.forceVector(i), str);

    for (size_t f = 0; f < model.frameCount; ++f) {
      const auto& frame = mol.coordinate3dRef(f);
      const Vector3 got = i < frame.size() ? frame[i] : Vector3::Zero();
      if (!(a.frames[f] == got)) {
        out << at << "coordinate set " << f << ": expected " << str(a.frames[f])
            << " got " << str(got);
        return out.str();
      }
    }

    for (size_t v = 0; checkCalculated && v < model.velocitySetCount; ++v) {
      const auto velocities = mol.velocities(static_cast<int>(v));
      const Vector3 got =
        i < velocities.size() ? velocities[i] : Vector3::Zero();
      if (!(a.velocities[v] == got)) {
        out << at << "velocity set " << v << ": expected "
            << str(a.velocities[v]) << " got " << str(got);
        return out.str();
      }
    }

    if (checkCalculated && model.modeCount > 0) {
      const auto* vib = mol.vibrationData(0);
      if (vib == nullptr || vib->lx.size() != model.modeCount) {
        out << at << "vibration data missing or with the wrong mode count";
        return out.str();
      }
      for (size_t m = 0; m < model.modeCount; ++m) {
        const Vector3 got =
          i < vib->lx[m].size() ? vib->lx[m][i] : Vector3::Zero();
        if (!(a.modes[m] == got)) {
          out << at << "normal mode " << m << ": expected " << str(a.modes[m])
              << " got " << str(got);
          return out.str();
        }
      }
    }

    for (const auto& type : model.chargeTypes) {
      if (!checkCalculated)
        break;
      const MatrixX charges = mol.partialCharges(type);
      const auto it = a.partialCharges.find(type);
      const double expected = it == a.partialCharges.end() ? 0.0 : it->second;
      if (static_cast<Index>(charges.rows()) != n ||
          charges(static_cast<Eigen::Index>(i), 0) != expected) {
        out << at << "partial charge '" << type << "': expected " << expected
            << " got "
            << (static_cast<Index>(charges.rows()) != n
                  ? std::string("a matrix with the wrong row count")
                  : std::to_string(charges(static_cast<Eigen::Index>(i), 0)));
        return out.str();
      }
    }

    const auto& props = mol.atomProperties();
    SHADOW_EXPECT_EQ("double property", a.doubleProperty,
                     props.getDouble(kAtomDoubleProperty, i), str);
    SHADOW_EXPECT_EQ("string property", a.stringProperty,
                     props.getString(kAtomStringProperty, i), str);
    {
      const auto m = props.getMatrix(kAtomMatrixProperty, i);
      const std::optional<double> got =
        m ? std::optional<double>((*m)(0, 0)) : std::nullopt;
      SHADOW_EXPECT_EQ("matrix property", a.matrixProperty, got, str);
    }
  }
  if (mol.isSelectionEmpty() == anySelected) {
    out << "isSelectionEmpty(): expected " << !anySelected << " got "
        << mol.isSelectionEmpty();
    return out.str();
  }

  for (Index b = 0; b < model.bondCount(); ++b) {
    const Bond& bond = model.bonds[b];
    std::ostringstream where;
    where << "bond index " << b << " (id " << bond.id << ", atom ids "
          << bond.atomA << "-" << bond.atomB << ") ";
    const std::string at = where.str();

    const Index ia = model.indexOf(bond.atomA);
    const Index ib = model.indexOf(bond.atomB);
    const auto pair = mol.bondPair(b);
    const Index lo = std::min(pair.first, pair.second);
    const Index hi = std::max(pair.first, pair.second);
    if (lo != std::min(ia, ib) || hi != std::max(ia, ib)) {
      out << at << "endpoints: expected atom indices " << std::min(ia, ib)
          << "," << std::max(ia, ib) << " got " << lo << "," << hi;
      return out.str();
    }
    if (mol.bond(ia, ib).index() != b) {
      out << at << "bond(a, b) lookup resolves to bond "
          << mol.bond(ia, ib).index();
      return out.str();
    }
    SHADOW_EXPECT_EQ("order", bond.order, mol.bondOrder(b), SHADOW_INT);
    SHADOW_EXPECT_EQ("label", bond.label, mol.bondLabel(b), SHADOW_NUM);
    const auto& props = mol.bondProperties();
    SHADOW_EXPECT_EQ("double property", bond.doubleProperty,
                     props.getDouble(kBondDoubleProperty, b), str);
    SHADOW_EXPECT_EQ("int property", bond.intProperty,
                     props.getInt(kBondIntProperty, b), str);
  }

#undef SHADOW_EXPECT_EQ
#undef SHADOW_NUM
#undef SHADOW_INT

  auto compare = [&](const char* what, const std::vector<Reference>& expected,
                     const std::vector<Avogadro::Core::Constraint>& actual,
                     bool withValue) -> std::string {
    std::ostringstream err;
    if (expected.size() != actual.size()) {
      err << what << " count: expected " << expected.size() << " got "
          << actual.size();
      return err.str();
    }
    for (size_t i = 0; i < expected.size(); ++i) {
      const auto want = model.indicesOf(expected[i]);
      const std::array<Index, 4> got = { actual[i].aIndex(), actual[i].bIndex(),
                                         actual[i].cIndex(),
                                         actual[i].dIndex() };
      if (want != got) {
        err << what << " " << i << ": expected atom indices (" << want[0]
            << ", " << want[1] << ", " << want[2] << ", " << want[3]
            << ") got (" << got[0] << ", " << got[1] << ", " << got[2] << ", "
            << got[3] << ")";
        return err.str();
      }
      if (withValue && actual[i].value() != expected[i].value) {
        err << what << " " << i << " value: expected " << expected[i].value
            << " got " << actual[i].value();
        return err.str();
      }
    }
    return std::string();
  };
  std::string error =
    compare("constraint", model.constraints, mol.constraints(), true);
  if (error.empty())
    error = compare("scan coordinate", model.scanCoordinates,
                    mol.scanCoordinates(), false);
  if (!error.empty())
    return error;

  // Residues, in order: fields, which atom each name refers to, label and
  // custom property. Always compared; undo restores them.
  if (mol.residueCount() != model.residues.size()) {
    out << "residueCount: expected " << model.residues.size() << " got "
        << mol.residueCount();
    return out.str();
  }
  for (size_t r = 0; r < model.residues.size(); ++r) {
    const ResidueRecord& want = model.residues[r];
    const auto& residue = mol.residue(static_cast<Index>(r));
    std::ostringstream where;
    where << "residue " << r << " (" << want.name << ") ";
    const std::string at = where.str();
    if (residue.residueName() != want.name ||
        residue.residueId() != want.number || residue.chainId() != want.chain ||
        residue.isHeterogen() != want.heterogen ||
        residue.secondaryStructure() != want.secondary) {
      out << at << "fields differ";
      return out.str();
    }
    const std::vector<Index> gotIndices = residue.atomIndices();
    if (gotIndices.size() != want.members.size()) {
      out << at << "has " << gotIndices.size() << " atoms, expected "
          << want.members.size();
      return out.str();
    }
    std::vector<Index> wantIndices;
    for (const auto& member : want.members) {
      const Index index = model.indexOf(member.second);
      wantIndices.push_back(index);
      const Index got = residue.atomIndexByName(member.first);
      if (got != index) {
        out << at << "atom '" << member.first << "': expected index " << index
            << " got index " << got;
        return out.str();
      }
      if (residue.atomName(index) != member.first) {
        out << at << "atom " << index << " is named '"
            << residue.atomName(index) << "', expected '" << member.first
            << "'";
        return out.str();
      }
    }
    std::sort(wantIndices.begin(), wantIndices.end());
    if (gotIndices != wantIndices) {
      out << at << "atomIndices() differ";
      return out.str();
    }
    if (residue.atomIndexMap().size() != want.members.size()) {
      out << at << "atomIndexMap() has " << residue.atomIndexMap().size()
          << " entries, expected " << want.members.size();
      return out.str();
    }
    // The proxies behind the index API must still belong to this molecule.
    // That is only visible through the deprecated accessor.
    SHADOW_BEGIN_DEPRECATED
    for (const auto& proxy : residue.residueAtoms()) {
      if (proxy.molecule() != &mol) {
        out << at << "has an atom proxy in another molecule";
        return out.str();
      }
    }
    SHADOW_END_DEPRECATED
    if (mol.residueLabel(static_cast<Index>(r)) != want.label) {
      out << at << "label: expected '" << want.label << "' got '"
          << mol.residueLabel(static_cast<Index>(r)) << "'";
      return out.str();
    }
    const auto gotProperty = mol.residueProperties().getDouble(
      kResidueDoubleProperty, static_cast<Index>(r));
    if (!(gotProperty == want.doubleProperty)) {
      out << at << "double property: expected " << str(want.doubleProperty)
          << " got " << str(gotProperty);
      return out.str();
    }
  }
  return std::string();
}

} // namespace ShadowModel

#endif // AVOGADRO_TESTS_SHADOWMOLECULE_H
