/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "uff.h"
#include "uffdata.h"
#include "gradients.h"

#include <Eigen/src/Core/util/Meta.h>
#include <avogadro/core/angleiterator.h>
#include <avogadro/core/angletools.h>
#include <avogadro/core/aromaticity.h>
#include <avogadro/core/array.h>
#include <avogadro/core/dihedraliterator.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace Avogadro::Calc {

using namespace Core;
using Eigen::Vector3d;

enum Coordination
{
  Resonant = 0,             // conjugated / aromatic
  Linear = 1,               // sp linear
  Trigonal = 2,             // sp2 planar
  Tetrahedral = 3,          // sp3 tetrahedral
  SquarePlanar = 4,         // square planar
  TrigonalBipyramidal = 5,  // trigonal bipyramidal
  Octahedral = 6,           // octahedral
  TrigonalBipentagonal = 7, // trigonal bipentagonal
  Other = 8                 // including higher coordination
};

class UFFBond // track the bond parameters
{
public:
  Index _atom1;
  Index _atom2;
  Real _r0;
  Real _kb;
};

class UFFAngle
{
public:
  Index _atom1;
  Index _atom2;
  Index _atom3;
  Real _theta0;
  Real _kijk;
  Real _c0;
  Real _c1;
  Real _c2;
  Coordination coordination;
};

class UFFTorsion
{
public:
  Index _atom1;
  Index _atom2;
  Index _atom3;
  Index _atom4;
  Real _cos_phi0;
  Real _ijkl;
  short _n; // periodicity
};

class UFFOOP
{
public:
  Index _atom1; // central atom
  Index _atom2;
  Index _atom3;
  Index _atom4;
  Real _c0;
  Real _c1;
  Real _c2;
  Real _koop;
};

class UFFVdW
{
public:
  Index _atom1;
  Index _atom2;
  Real _depth;
  Real _x;
  Real _x6;  // precomputed x^6
  Real _x12; // precomputed x^12
};

// Torsions fade out as a bond angle goes from this angle (degrees) to 180
static constexpr Real TORSION_SWITCH_ONSET_DEGREES = 170.0;

// The van der Waals energy is switched smoothly to zero between VDW_R_ON and
// VDW_R_OFF (the CHARMM / Brooks switch, continuous in value and first
// derivative). UFF equilibrium VdW distances are 2.5-4.5 Angstroms, so at
// 2.5x the largest the LJ energy is already negligible.
static constexpr Real VDW_R_ON = 8.0;
static constexpr Real VDW_R_OFF = 10.0;
static constexpr Real VDW_R_ON_SQ = VDW_R_ON * VDW_R_ON;
static constexpr Real VDW_R_OFF_SQ = VDW_R_OFF * VDW_R_OFF;
// Denominator (r_off^2 - r_on^2)^3 of the switching function
static constexpr Real VDW_SWITCH_DENOM = (VDW_R_OFF_SQ - VDW_R_ON_SQ) *
                                         (VDW_R_OFF_SQ - VDW_R_ON_SQ) *
                                         (VDW_R_OFF_SQ - VDW_R_ON_SQ);
static constexpr Real VDW_SWITCH_INV = 1.0 / VDW_SWITCH_DENOM;
// Verlet pair list: every pair closer than r_off + skin is listed, and the
// list is rebuilt as soon as any atom has moved more than skin / 2 since it
// was built. Two atoms can then close by at most skin, so every pair inside
// r_off is always in the list and the energy does not depend on when the list
// was last built.
static constexpr Real VDW_SKIN = 2.5;
static constexpr Real VDW_LIST_CUTOFF_SQ =
  (VDW_R_OFF + VDW_SKIN) * (VDW_R_OFF + VDW_SKIN);
static constexpr Real VDW_REBUILD_THRESHOLD_SQ =
  (0.5 * VDW_SKIN) * (0.5 * VDW_SKIN);
// Soft core: inside r_c = VDW_CORE_FRACTION * x_ij the 12-6 energy is replaced
// by its tangent line at r_c, so the energy and gradient agree and stay finite
// for overlapping atoms. At r_c the 12-6 repulsion is already about 4000 D.
static constexpr Real VDW_CORE_FRACTION = 0.5;

// Helpers to look up rows of uffparams. Rows for an element are contiguous,
// and the third character of a label is the coordination (e.g., "C_3", "C_R",
// "Ti6+4"). Every search is limited to the one element's rows so that a
// missing coordination can never return another element's type.
// Returns the first row of this element accepted by the predicate, or -1.
template <class Pred>
static int findUffRow(int atomicNumber, Pred accept)
{
  for (size_t j = 0; j < std::size(uffparams); ++j) {
    if (uffparams[j].element == atomicNumber && accept(uffparams[j]))
      return static_cast<int>(j);
  }
  return -1;
}

// the first (generic) type of this element, or -1 if unsupported
static int findFirstUffType(int atomicNumber)
{
  return findUffRow(atomicNumber, [](const auto&) { return true; });
}

// the first type of this element with the given coordination character,
// or -1 if the element has none
static int findUffType(int atomicNumber, char coordination)
{
  return findUffRow(atomicNumber, [coordination](const auto& row) {
    return row.label.size() > 2 && row.label[2] == coordination;
  });
}

// the type of this element with the exact label (e.g., "S_3+6"), or -1
static int findUffTypeByLabel(int atomicNumber, const char* label)
{
  return findUffRow(atomicNumber,
                    [label](const auto& row) { return row.label == label; });
}

// UFF types for hypervalent sulfur and phosphorus, or -1 when the atom is not
// hypervalent (use the ordinary coordination types).
//   S_3+6 (109.47) : sulfate, sulfone, SO3, H2SO4, SF6; a bond order sum >= 6
//                    or five or more neighbors
//   S_3+4 (103.2)  : SO2, sulfoxides (DMSO), sulfite (bond order sum 4-5)
//   P_3+5 (109.47) : phosphates, phosphine oxides, PF5; four or more
//                    neighbors or a bond order sum >= 5
//   P_3+q (109.47) : the same for a positively charged P with only single
//                    bonds (phosphonium, charge-separated phosphate)
// These follow the oxidation-state comments in Open Babel's UFF.prm
// (S+4: SO2; S+6: SO3, H2SO4). Open Babel itself only applies them when the
// atom has that formal charge, so it types neutral SO2 / H2SO4 as S_3+2.
// The types follow the bond order sum, so four single bonds to S (SF4, but
// also sulfate or H2SO4 whose S=O bonds were never perceived) give S_3+4.
// That is a bond perception problem, not a typing one.
static int hypervalentTypeFor(int atomicNumber, int neighborCount,
                              int bondOrderSum, int formalCharge)
{
  if (atomicNumber == 16) {
    if (neighborCount >= 5 || bondOrderSum >= 6)
      return findUffTypeByLabel(16, "S_3+6");
    if (bondOrderSum >= 4)
      return findUffTypeByLabel(16, "S_3+4");
  } else if (atomicNumber == 15) {
    if (neighborCount >= 4 || bondOrderSum >= 5) {
      if (formalCharge > 0 && bondOrderSum == neighborCount)
        return findUffTypeByLabel(15, "P_3+q");
      return findUffTypeByLabel(15, "P_3+5");
    }
  }
  return -1;
}

class UFFPrivate // track the particular calculations for a molecule
{
public:
  std::vector<int> m_atomTypes; // entry row in uffparams
  std::vector<UFFBond> m_bonds;
  std::vector<UFFAngle> m_angles;
  std::vector<UFFOOP> m_oops;
  std::vector<UFFTorsion> m_torsions;
  std::vector<UFFVdW> m_vdws;
  std::vector<bool> m_aromaticBonds; // per bond, from AromaticityPerceiver
  std::unordered_set<uint64_t> m_excludedPairs; // 1-2 and 1-3 pairs
  Eigen::VectorXd m_lastVdWPositions; // positions when VdW list was last built
  Core::Molecule* m_molecule;
  Core::UnitCell* m_cell;

  static uint64_t pairKey(Index i, Index j)
  {
    return i < j ? (uint64_t(i) << 32 | uint64_t(j))
                 : (uint64_t(j) << 32 | uint64_t(i));
  }

  UFFPrivate(Core::Molecule* mol = nullptr) : m_molecule(mol), m_cell(nullptr)
  {
    if (mol == nullptr || mol->atomCount() < 2) {
      return; // nothing to do
    }

    m_cell = mol->unitCell(); // could be nullptr

    setAtomTypes();
    // An element with no UFF type (> 103) leaves -1 in m_atomTypes, which
    // would index uffparams[-1] below. Leave the molecule with no terms.
    for (int type : m_atomTypes) {
      if (type < 0) {
        m_atomTypes.clear();
        return;
      }
    }
    // perceive aromatic bonds once; they set the effective bond order
    {
      AromaticityPerceiver perceiver(m_molecule);
      m_aromaticBonds = perceiver.aromaticBonds();
    }
    setBonds();
    setAngles();
    setOOPs();
    setTorsions();
    buildExclusionSet();

    // Extract initial positions for VdW cutoff. Positions may be missing or
    // short; rebuildVdWsIfNeeded() builds the list on the first evaluate().
    Core::Array<Vector3> pos = mol->atomPositions3d();
    if (pos.size() == static_cast<size_t>(mol->atomCount())) {
      Eigen::Map<Eigen::VectorXd> posMap(pos[0].data(), 3 * mol->atomCount());
      setVdWs(posMap);
    }
  }

  void setAtomTypes()
  {
    // set up the calculations including atom types and parameters
    // loop through atoms to get the atom types
    m_atomTypes.reserve(m_molecule->atomCount());
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      const Core::Atom& atom = m_molecule->atom(i);
      const int atomicNumber = atom.atomicNumber();

      // the first (generic) type for this element, or -1 if unsupported
      const int firstType = findFirstUffType(atomicNumber);
      if (firstType < 0) {
        m_atomTypes.push_back(-1);
        continue;
      }

      // most elements only have one type
      const size_t next = static_cast<size_t>(firstType) + 1;
      if (next >= std::size(uffparams) ||
          uffparams[next].element != atomicNumber) {
        m_atomTypes.push_back(firstType);
        continue;
      }

      // there are multiple types for this element
      const Array<Bond> bonds = m_molecule->bonds(i);
      if (atomicNumber == 1) {
        // hydrogen has two types, so count the bonds (H_ with none or one
        // bond, otherwise the bridging type H_b, e.g., B-H-B in diborane)
        m_atomTypes.push_back(bonds.size() <= 1 ? firstType : firstType + 1);
        continue;
      }

      // remaining elements, we want the coordination number
      // count double and triple bonds
      int doubleBonds = 0;
      int tripleBonds = 0;
      int bondOrderSum = 0;
      for (const Bond bond : bonds) {
        unsigned char order = bond.order();
        if (order == 2)
          ++doubleBonds;
        else if (order == 3)
          ++tripleBonds;
        bondOrderSum += (order > 0 ? order : 1);
      }

      // Rappe et al. (1992) / UFF.prm: B_2 is trigonal planar, B_3 is
      // tetrahedral. Three-coordinate boron (BF3, BH3, boronic esters) is
      // trigonal; four-coordinate (BH4-, BF4-, amine-boranes) is tetrahedral.
      if (atomicNumber == 5 && bonds.size() >= 3) {
        m_atomTypes.push_back(
          findUffTypeByLabel(5, bonds.size() == 3 ? "B_2" : "B_3"));
        continue;
      }

      // sulfur and phosphorus can be hypervalent: SO2, DMSO, sulfate,
      // phosphate, ..., and the UFF types depend on the oxidation state
      const int hypervalentType =
        hypervalentTypeFor(atomicNumber, static_cast<int>(bonds.size()),
                           bondOrderSum, m_molecule->formalCharge(i));
      if (hypervalentType >= 0) {
        m_atomTypes.push_back(hypervalentType);
        continue;
      }

      int atomType = -1;
      if (bonds.size() > 4) {
        // UFF fortunately only has square planar as special cases
        // so if it's more than 4 bonds, we just use that type
        // (the digit in the label is the coordination number)
        const char coord =
          bonds.size() <= 9 ? static_cast<char>('0' + bonds.size()) : '6';
        atomType = findUffType(atomicNumber, coord);
        // e.g., five-coordinate Ti: octahedral is the closest type
        if (atomType < 0)
          atomType = findUffType(atomicNumber, '6');
      } else {
        char coord = '3'; // sp3 tetrahedral
        if (tripleBonds > 0 || doubleBonds > 1)
          coord = '1'; // sp linear
        else if (doubleBonds == 1)
          coord = '2'; // sp2 trigonal

        atomType = findUffType(atomicNumber, coord);
        // Not every element has every coordination (e.g., boron, phosphorus
        // and sulfur have no sp type). Fall back to the next less
        // unsaturated type of the same element, never to another element.
        if (atomType < 0 && coord == '1')
          atomType = findUffType(atomicNumber, '2');
        if (atomType < 0 && (coord == '1' || coord == '2'))
          atomType = findUffType(atomicNumber, '3');
      }
      // last resort: the generic type for this element
      if (atomType < 0)
        atomType = firstType;
      m_atomTypes.push_back(atomType);
    }

    // we need to do one more pass to set aromatic / resonance types
    // i.e., if an sp2 atom has neighbors, mark them as resonant
    // Read every label from a snapshot so the result does not depend on the
    // order of the atoms.
    const std::vector<int> baseTypes = m_atomTypes;
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      const Core::Atom& atom = m_molecule->atom(i);
      int atomicNumber = atom.atomicNumber();
      // carbon, nitrogen, oxygen and sulfur sp2 atoms
      if (atomicNumber == 6 || atomicNumber == 7 || atomicNumber == 8 ||
          atomicNumber == 16) {
        if (baseTypes[i] < 0)
          continue;

        const std::string& label = uffparams[baseTypes[i]].label;
        const char symbolChar = label.size() > 2 ? label[2] : '\0';

        // sp atoms (C_1, N_1, O_1) are linear and not conjugated in the UFF
        // sense; benzonitrile, ketene and allene keep their sp types
        if (symbolChar == '1')
          continue;

        // we might have an aromatic / resonant N, O, or S
        // e.g., furan, thiophene .. we also mark amide N
        // if it's an sp3 carbon, skip it
        if (atomicNumber == 6 && symbolChar == '3')
          continue;

        // hypervalent sulfur (sulfoxide, sulfone, sulfate) is not aromatic
        if (atomicNumber == 16 && label != "S_3+2" && label != "S_2")
          continue;

        // check the neighbors
        const std::vector<Index>& neighbors = m_molecule->graph().neighbors(i);

        // we can skip carbonyl oxygen (i.e., only one neighbor)
        if ((atomicNumber == 8 || atomicNumber == 16) && neighbors.size() == 1)
          continue;

        bool resonant = false;
        for (Index j : neighbors) {
          // untyped neighbor (unsupported element)
          if (baseTypes[j] < 0)
            continue;
          const auto& symbolLabel = uffparams[baseTypes[j]].label;
          if (symbolLabel.size() < 3)
            continue; // not a resonant type

          if (symbolLabel[2] == '2' || symbolLabel[2] == 'R') {
            resonant = true;
            break;
          }
        }
        if (resonant) {
          // set the resonant type (C_R, N_R, O_R, S_R) for this element
          const int resonantType = findUffType(atomicNumber, 'R');
          if (resonantType >= 0)
            m_atomTypes[i] = resonantType;
        }
      }
    }
  }

  // The bond order used for the bond length and the sp2-sp2 torsion barrier.
  // An aromatic bond (AromaticityPerceiver) is 1.5 whatever the Kekule form.
  // A single bond between two resonant atoms is conjugated: 1.5, or 1.41 for
  // a C-N pair (amide). Any other bond keeps its explicit order (at least 1),
  // so a non-aromatic C=C between two C_R atoms stays 2.
  Real effectiveBondOrder(const Core::Bond& bond, Index atom1, Index atom2)
  {
    // order 0 would give log(0) = -inf in the bond-order correction
    const Real order =
      bond.isValid() ? std::max(1.0, static_cast<Real>(bond.order())) : 1.0;

    if (bond.isValid() && bond.index() < m_aromaticBonds.size() &&
        m_aromaticBonds[bond.index()])
      return 1.5;

    if (order == 1.0) {
      const auto& symbol1 = uffparams[m_atomTypes[atom1]].label;
      const auto& symbol2 = uffparams[m_atomTypes[atom2]].label;
      if (symbol1.size() > 2 && symbol1[2] == 'R' && symbol2.size() > 2 &&
          symbol2[2] == 'R') {
        if ((symbol1[0] == 'N' && symbol2[0] == 'C') ||
            (symbol1[0] == 'C' && symbol2[0] == 'N'))
          return 1.41;
        return 1.5;
      }
    }
    return order;
  }

  // calculate the ideal bond distance between two atoms
  // used in a few places
  Real calculateRij(Index atom1, Index atom2)
  {
    Real ri = uffparams[m_atomTypes[atom1]].r1;
    Real rj = uffparams[m_atomTypes[atom2]].r1;
    Real r0 = ri + rj;
    // bond order correction
    const Real order =
      effectiveBondOrder(m_molecule->bond(atom1, atom2), atom1, atom2);
    Real rbo = -0.1332 * r0 * log(order);

    // electronegativity correction
    Real chi1 = uffparams[m_atomTypes[atom1]].Xi;
    Real chi2 = uffparams[m_atomTypes[atom2]].Xi;
    Real ren =
      ri * rj * pow((sqrt(chi1) - sqrt(chi2)), 2) / (chi1 * ri + chi2 * rj);

    // UFF publication has an error (electronegativity correction):
    // https://towhee.sourceforge.net/forcefields/uff.html
    return r0 + rbo - ren;
  }

  void setBonds()
  {
    // loop through the bonds
    for (Index i = 0; i < m_molecule->bondCount(); ++i) {
      const Core::Bond& bond = m_molecule->bond(i);
      Index atom1 = bond.atom1().index();
      Index atom2 = bond.atom2().index();
      UFFBond b;
      b._atom1 = atom1;
      b._atom2 = atom2;

      b._r0 = calculateRij(atom1, atom2);
      Real z1 = uffparams[m_atomTypes[atom1]].Z1;
      Real z2 = uffparams[m_atomTypes[atom2]].Z1;
      b._kb = 664.12 * z1 * z2 / pow((b._r0), 3);
      m_bonds.push_back(b);

      /*
      std::cout << " bond " << atom1 << " "
                << uffparams[m_atomTypes[atom1]].label << " " << atom2 << " "
                << uffparams[m_atomTypes[atom2]].label << " " << b._r0 << " "
                << b._kb << std::endl;
                */
    }
  }

  void setAngles()
  {
    AngleIterator ai(m_molecule);
    auto angle = ai.begin();
    while (angle != ai.end()) {
      Index i = std::get<0>(angle);
      Index j = std::get<1>(angle);
      Index k = std::get<2>(angle);
      UFFAngle a;
      a._atom1 = i;
      a._atom2 = j;
      a._atom3 = k;

      Real theta0 = uffparams[m_atomTypes[j]].theta0 * DEG_TO_RAD;
      a._theta0 = theta0 * RAD_TO_DEG; // store in degrees for consistency

      // calculate the kijk
      Real rij = calculateRij(i, j);
      Real rjk = calculateRij(j, k);

      /*
      std::cout << " Angle " << i << " " << j << " " << k << " " << rij << " "
                << rjk << " " << theta0 << std::endl;
                */

      Real rik = sqrt(rij * rij + rjk * rjk - 2 * rij * rjk * cos(theta0));
      Real Zi = uffparams[m_atomTypes[i]].Z1;
      Real Zk = uffparams[m_atomTypes[k]].Z1;
      Real cosTheta0 = cos(theta0);
      Real cosTheta0Sq = cosTheta0 * cosTheta0;
      // see https://towhee.sourceforge.net/forcefields/uff.html
      // e.g., original paper had some typos
      a._kijk = 664.12 / (rij * rjk) * (Zi * Zk) / (pow(rik, 5)) * rij * rjk;
      a._kijk *= (3 * rij * rjk * (1 - cosTheta0Sq) - rik * rik * cosTheta0);

      // calculate the c0, c1, c2 terms
      // based on coordination of the central atom
      const std::string& label = uffparams[m_atomTypes[j]].label;
      auto neighbors = m_molecule->graph().neighbors(j);
      a._c0 = 0.0;
      a._c1 = 0.0;
      a._c2 = 0.0;

      if (label.size() < 3 || neighbors.size() == 1 || label[2] == '1') {
        // linear
        a.coordination = Linear;
        a._c0 = 1.0;
      } else if ((label[2] == '2' || label[2] == 'R') &&
                 neighbors.size() == 3) {
        a.coordination = Trigonal;
        a._kijk = a._kijk / 9.0; // divide by n**2
        a._c0 = 3.0;
      } else if (label[2] == '4') {
        a.coordination = SquarePlanar;
        a._kijk = a._kijk / 16.0;
        a._c0 = 4.0;
      } else if (label[2] == '5') {
        // TODO
        a.coordination = TrigonalBipyramidal;
      } else if (label[2] == '6') {
        a.coordination = Octahedral;
        a._kijk = a._kijk / 16.0;
        a._c0 = 4.0;
      } else if (neighbors.size() > 6) {
        // TODO - trigonal bipentagonal and higher coordination
        // (e.g., as a repulsion between the other atoms)
        a.coordination = Other;
      } else {
        a.coordination = Tetrahedral;
        Real sinTheta0 = sin(theta0);
        a._c2 = 1.0 / (4.0 * sinTheta0 * sinTheta0);
        a._c1 = -4.0 * a._c2 * cosTheta0;
        a._c0 = a._c2 * (2.0 * cosTheta0 * cosTheta0 + 1.0);
      }

      m_angles.push_back(a);
      angle = ++ai;
    }
  }

  void setOOPs()
  {
    // loop through atoms checking for cases with 3 neighbors
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      auto neighbors = m_molecule->graph().neighbors(i);
      if (neighbors.size() != 3)
        continue;

      // also only for certain elements
      const Core::Atom& atom = m_molecule->atom(i);
      int atomicNumber = atom.atomicNumber();
      switch (atomicNumber) {
        case 6:  // carbon
        case 7:  // nitrogen
        case 8:  // oxygen
        case 15: // phos.
        case 33: // as
        case 51: // sb
        case 83: // bi
          break;
        default: // no inversion term for this element
          continue;
      }

      UFFOOP oop;
      oop._atom1 = i;

      const std::string& symbol = uffparams[m_atomTypes[i]].label;
      if (symbol == "N_R" || symbol == "N_2" || symbol == "O_R" ||
          symbol == "O_2") {
        oop._c0 = 1.0;
        oop._c1 = -1.0;
        oop._c2 = 0.0;
        oop._koop = 6.0;
      } else if (symbol == "P_3+3" || symbol == "As3+3" || symbol == "Sb3+3" ||
                 symbol == "Bi3+3") {

        Real phi;
        switch (atomicNumber) {
          case 15: // P
            phi = 84.4339 * DEG_TO_RAD;
            break;
          case 33: // As
            phi = 86.9735 * DEG_TO_RAD;
            break;
          case 51: // Sb
            phi = 87.7047 * DEG_TO_RAD;
            break;
          case 83: // Bi
          default:
            phi = 90.0 * DEG_TO_RAD;
        }
        // E = K (C0 + C1 cos(w) + C2 cos(2w)), Rappe et al. (1992):
        // C1 = -4 C2 cos(w0) puts the minimum at w0, and
        // C0 = -C1 cos(w0) - C2 cos(2 w0) makes E(w0) = 0, and
        // K = 22 / (C0 + C1 + C2) makes the planar (w = 0) energy 22 kcal/mol
        oop._c1 = -4.0 * cos(phi);
        oop._c2 = 1.0;
        oop._c0 = -1.0 * oop._c1 * cos(phi) - oop._c2 * cos(2.0 * phi);
        const Real planar = oop._c0 + oop._c1 + oop._c2;
        if (!(planar > 1.0e-8))
          continue;
        oop._koop = 22.0 / planar;
      } else if (symbol == "C_2" || symbol == "C_R") {
        oop._c0 = 1.0;
        oop._c1 = -1.0;
        oop._c2 = 0.0;
        oop._koop = 6.0;
        // check if one of the other atoms is "O_2"
        if (uffparams[m_atomTypes[neighbors[0]]].label == "O_2" ||
            uffparams[m_atomTypes[neighbors[1]]].label == "O_2" ||
            uffparams[m_atomTypes[neighbors[2]]].label == "O_2") {
          oop._koop = 50.0;
        }
      } else {
        continue;
      }

      // Rappe et al. average the inversion over the three axes (each
      // neighbor in turn is the out-of-plane atom, the other two define the
      // plane), as Open Babel does: three terms with a third of K each.
      oop._koop /= 3.0;
      for (size_t axis = 0; axis < 3; ++axis) {
        oop._atom2 = neighbors[axis];
        oop._atom3 = neighbors[(axis + 1) % 3];
        oop._atom4 = neighbors[(axis + 2) % 3];
        m_oops.push_back(oop);
      }
    }
  }

  void setTorsions()
  {
    // The third character of a UFF label is the hybridization or geometry:
    // '3' sp3, '2' sp2, 'R' resonant (treated as sp2), '1' linear. Labels
    // of one or two characters (H_, F_, Cl, Na) have none and can't be
    // torsion centers; the old code treated them as sp3 with Vi = 0.
    auto hybridization = [](const std::string& label) -> char {
      return label.size() < 3 ? '\0' : label[2];
    };
    auto isSp2 = [](char h) { return h == '2' || h == 'R'; };
    // group 16: O, S, Se, Te, Po
    auto isGroup16 = [](unsigned char atomicNumber) {
      return atomicNumber == 8 || atomicNumber == 16 || atomicNumber == 34 ||
             atomicNumber == 52 || atomicNumber == 84;
    };

    DihedralIterator di(m_molecule);
    auto dihedral = di.begin();
    for (; dihedral != di.end(); dihedral = ++di) {
      Index i = std::get<0>(dihedral);
      Index j = std::get<1>(dihedral);
      Index k = std::get<2>(dihedral);
      Index l = std::get<3>(dihedral);

      Bond bond = m_molecule->bond(j, k);
      if (!bond.isValid())
        continue;
      // no torsion about a triple bond (the centers are linear anyway)
      if (bond.order() >= 3)
        continue;

      const auto& paramJ = uffparams[m_atomTypes[j]];
      const auto& paramK = uffparams[m_atomTypes[k]];
      const char hybridJ = hybridization(paramJ.label);
      const char hybridK = hybridization(paramK.label);
      const unsigned char zJ = m_molecule->atom(j).atomicNumber();
      const unsigned char zK = m_molecule->atom(k).atomicNumber();

      UFFTorsion t;
      t._atom1 = i;
      t._atom2 = j;
      t._atom3 = k;
      t._atom4 = l;

      // _ijkl holds V / 2 (kcal/mol), _cos_phi0 holds cos(n * phi0):
      // E = V/2 * [1 - cos(n * phi0) * cos(n * phi)]  (Rappe 1992, eq. 16-18)
      if (hybridJ == '3' && hybridK == '3') {
        // sp3-sp3: n = 3, phi0 = 60, V = sqrt(Vj * Vk)
        t._n = 3;
        Real Vi_j = paramJ.Vi;
        Real Vi_k = paramK.Vi;
        Real phi0 = 60.0;

        // Pair of group 16 centers (e.g. H-O-O-H): n = 2, phi0 = 90,
        // V_O = 2.0, V_S/Se/Te/Po = 6.8. This applies only when BOTH centers
        // are group 16. (Open Babel applies it when either one is, so it
        // gives H-C-O-H a 2-fold term; that is not what the paper says.)
        if (isGroup16(zJ) && isGroup16(zK)) {
          t._n = 2;
          phi0 = 90.0;
          Vi_j = (zJ == 8) ? 2.0 : 6.8;
          Vi_k = (zK == 8) ? 2.0 : 6.8;
        }

        t._cos_phi0 = cos(t._n * phi0 * DEG_TO_RAD);
        t._ijkl = 0.5 * sqrt(Vi_j * Vi_k);
      } else if (isSp2(hybridJ) && isSp2(hybridK)) {
        // sp2-sp2: n = 2, phi0 = 180, V = 5 sqrt(Uj Uk) (1 + 4.18 ln BO)
        const Real order = effectiveBondOrder(bond, j, k);
        t._n = 2;
        t._cos_phi0 = 1.0; // cos(2 * 180 degrees)
        t._ijkl =
          0.5 * 5.0 * sqrt(paramJ.Uj * paramK.Uj) * (1.0 + 4.18 * log(order));
      } else if ((isSp2(hybridJ) && hybridK == '3') ||
                 (hybridJ == '3' && isSp2(hybridK))) {
        // sp2-sp3: n = 6, phi0 = 0, V = 1.0 kcal/mol
        // TODO: propene-like case (sp2 atom bonded to another sp2 atom):
        // n = 3, phi0 = 180, V = 2.0. Open Babel doesn't do it either.
        t._n = 6;
        t._cos_phi0 = 1.0; // cos(6 * 0 degrees)
        t._ijkl = 0.5;     // V / 2 with V = 1.0

        // exception when the sp3 center is group 16 (e.g. C=C-O-C):
        // n = 2, phi0 = 90. V stays 1.0 kcal/mol: Rappe 1992 and Open Babel
        // agree
        const unsigned char zSp3 = (hybridJ == '3') ? zJ : zK;
        if (isGroup16(zSp3)) {
          t._n = 2;
          t._cos_phi0 = cos(t._n * 90.0 * DEG_TO_RAD);
        }
      } else {
        // linear (sp1) or higher coordination: no torsion term
        continue;
      }

      if (std::fabs(t._ijkl) < 1.0e-6)
        continue;

      m_torsions.push_back(t);
    }

    // Rappe's V is the barrier about the j-k bond, but every i-j-k-l dihedral
    // was given all of it (ethane would get 9 times the barrier). Divide it
    // among the torsions about each central bond, as RDKit's UFF does. (Open
    // Babel applies the full V to every torsion.)
    std::unordered_map<uint64_t, int> torsionCounts;
    for (const UFFTorsion& t : m_torsions)
      ++torsionCounts[pairKey(t._atom2, t._atom3)];
    for (UFFTorsion& t : m_torsions) {
      const int count = torsionCounts[pairKey(t._atom2, t._atom3)];
      if (count > 1)
        t._ijkl /= static_cast<Real>(count);
    }
  }

  // Build a hash set of all 1-2 and 1-3 atom pairs for O(1) exclusion lookup
  void buildExclusionSet()
  {
    const auto& graph = m_molecule->graph();
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      const std::vector<Index>& neighbors = graph.neighbors(i);
      for (Index j : neighbors) {
        // 1-2 pair
        m_excludedPairs.insert(pairKey(i, j));
        // 1-3 pairs: neighbors of j that aren't i
        const std::vector<Index>& neighbors2 = graph.neighbors(j);
        for (Index k : neighbors2) {
          if (k != i)
            m_excludedPairs.insert(pairKey(i, k));
        }
      }
    }
  }

  // Check if atoms i and j are 1-2 or 1-3 connected (O(1) lookup)
  bool areExcluded(Index i, Index j) const
  {
    return m_excludedPairs.count(pairKey(i, j)) > 0;
  }

  // Build or rebuild the VdW pair list with distance cutoff.
  // With a unit cell each pair is listed once and seen through its nearest
  // periodic image only (UnitCell::minimumImage). That is exact while the
  // list cutoff (r_off + skin = 12.5 A) is shorter than half the narrowest
  // cell width; in a smaller cell the farther images of a pair, and the
  // interaction of an atom with its own images, are not counted.
  void setVdWs(const Eigen::VectorXd& x)
  {
    m_vdws.clear();
    m_lastVdWPositions = x;

    // m_atomTypes is empty for a molecule with unsupported elements
    if (m_atomTypes.empty())
      return;

    const Index n = m_molecule->atomCount();
    // clear() keeps the capacity, so this only matters for the first build:
    // a few dozen listed neighbors per atom, never more than all pairs
    const size_t pairCount = static_cast<size_t>(n) * (n - 1) / 2;
    m_vdws.reserve(std::min(pairCount, static_cast<size_t>(n) * 64));
    for (Index i = 0; i < n; ++i) {
      for (Index j = i + 1; j < n; ++j) {
        // Apply distance cutoff
        Real r2;
        if (m_cell == nullptr) {
          const Vector3d diff = x.segment<3>(3 * i) - x.segment<3>(3 * j);
          r2 = diff.squaredNorm();
        } else {
          r2 = m_cell->distanceSquared(Vector3(x.segment<3>(3 * i)),
                                       Vector3(x.segment<3>(3 * j)));
        }
        if (r2 > VDW_LIST_CUTOFF_SQ || areExcluded(i, j))
          continue;

        UFFVdW v;
        v._atom1 = i;
        v._atom2 = j;
        v._depth =
          sqrt(uffparams[m_atomTypes[i]].D1 * uffparams[m_atomTypes[j]].D1);
        v._x =
          sqrt(uffparams[m_atomTypes[i]].x1 * uffparams[m_atomTypes[j]].x1);
        Real x3 = v._x * v._x * v._x;
        v._x6 = x3 * x3;
        v._x12 = v._x6 * v._x6;
        m_vdws.push_back(v);
      }
    }
  }

  // Rebuild the VdW pair list if any atom has moved more than half the skin
  // since it was built. This is checked on every evaluation (O(N)); see
  // VDW_SKIN for why that keeps every pair inside the switching distance
  // listed.
  void rebuildVdWsIfNeeded(const Eigen::VectorXd& x)
  {
    if (m_lastVdWPositions.size() != x.size()) {
      setVdWs(x);
      return;
    }

    const Index n = m_molecule->atomCount();
    for (Index i = 0; i < n; ++i) {
      const Vector3d disp =
        x.segment<3>(3 * i) - m_lastVdWPositions.segment<3>(3 * i);
      if (disp.squaredNorm() > VDW_REBUILD_THRESHOLD_SQ) {
        setVdWs(x);
        return;
      }
    }
  }

  // True if bonded terms should use the minimum image convention: there is a
  // unit cell and it can be inverted (a singular cell would give NaN).
  bool usesMinimumImage() const
  {
    return m_cell != nullptr && m_cell->isRegular();
  }

  // The vector from atom a to atom b. Bonded atoms in a periodic cell may sit
  // on opposite sides of the boundary, so take the shortest periodic image.
  // The angle, inversion and torsion terms chain these vectors to place their
  // atoms as one connected fragment. The gradient with respect to each atom
  // is unchanged by the (constant) lattice shifts, so those terms can use the
  // shifted points for both the energy and the gradient.
  Vector3d bondedVector(const Eigen::VectorXd& x, Index a, Index b,
                        bool periodic) const
  {
    const Vector3d v = x.segment<3>(3 * b) - x.segment<3>(3 * a);
    return periodic ? Vector3d(m_cell->minimumImage(v)) : v;
  }

  void bondEvaluate(const Eigen::VectorXd& x, Real* energy,
                    Eigen::VectorXd* grad)
  {
    const bool periodic = usesMinimumImage();
    for (const UFFBond& bond : m_bonds) {
      const Index i = bond._atom1;
      const Index j = bond._atom2;
      const Vector3d diff = -bondedVector(x, i, j, periodic);
      const Real r = diff.norm();
      const Real dr = r - bond._r0;

      if (energy != nullptr) {
        // the 0.5 * kb is already in kb to save a multiplication
        *energy += bond._kb * dr * dr;
      }

      if (grad == nullptr || r < 1e-3)
        continue;

      const Real dEdr = 2.0 * bond._kb * dr;
      const Vector3d direction = diff / r;
      grad->segment<3>(3 * i) += dEdr * direction;
      grad->segment<3>(3 * j) -= dEdr * direction;
    }
  }

  void angleEvaluate(const Eigen::VectorXd& x, Real* energy,
                     Eigen::VectorXd* grad)
  {
    const bool needsGradient = grad != nullptr;
    const bool needsEnergy = energy != nullptr;
    const bool periodic = usesMinimumImage();

    for (const UFFAngle& angle : m_angles) {
      const Index i = angle._atom1;
      const Index j = angle._atom2;
      const Index k = angle._atom3;
      const Real theta0 = angle._theta0 * DEG_TO_RAD;
      const Real kijk = angle._kijk;
      const Real c0 = angle._c0;
      const Real c1 = angle._c1;
      const Real c2 = angle._c2;

      // the vertex j, with i and k at their shortest images from it
      const Vector3d vj = x.segment<3>(3 * j);
      const Vector3d vi = vj + bondedVector(x, j, i, periodic);
      const Vector3d vk = vj + bondedVector(x, j, k, periodic);

      Real thetaGradient = 0.0;
      Vector3d grad_i = Vector3d::Zero();
      Vector3d grad_j = Vector3d::Zero();
      Vector3d grad_k = Vector3d::Zero();
      if (needsGradient) {
        // d(theta)/dx ~ 1/sin(theta) is large for nearly linear angles, but
        // the periodic forms (Linear, Trigonal, SquarePlanar, Octahedral,
        // Tetrahedral) have dE/dtheta ~ sin(theta), so the product stays
        // finite and must not be dropped (e.g., trans F-Xe-F in XeF4 is
        // within 1e-7 radians of 180 degrees). The harmonic fallback has no
        // such cancellation, so it keeps the default cutoff.
        const bool harmonic = angle.coordination == TrigonalBipyramidal ||
                              angle.coordination == TrigonalBipentagonal ||
                              angle.coordination == Other;
        thetaGradient = ::Avogadro::Calc::angleGradient(
          vi, vj, vk, grad_i, grad_j, grad_k, harmonic ? 1.e-6 : 1.e-14);
      }

      if (needsEnergy) {
        // Match the legacy value() path: use acos-based angle in [0, pi].
        const Vector3d ij = vi - vj;
        const Vector3d kj = vk - vj;
        const Real r1 = ij.norm();
        const Real r2 = kj.norm();
        // coincident atoms give 0/0, and std::clamp passes NaN through
        const Real thetaEnergy =
          (r1 > 1e-6 && r2 > 1e-6)
            ? acos(std::clamp(ij.dot(kj) / (r1 * r2), -1.0, 1.0))
            : 0.0;
        switch (angle.coordination) {
          case Linear:
            // fixed typo in UFF paper (it's 1+cos(theta), not 1-cos(theta))
            *energy += kijk * (1 + cos(c0 * thetaEnergy));
            break;
          case Trigonal:
          case Resonant:
          case SquarePlanar:
          case Octahedral:
            // The exp() term is not in Rappe 1992. It removes the spurious
            // minimum of 1 - cos(n theta) at theta = 0, which would otherwise
            // pull two atoms on top of each other in distorted geometries
            // (same term as Open Babel's UFF).
            *energy += kijk * (1 - cos(c0 * thetaEnergy)) +
                       exp(-20.0 * (thetaEnergy - theta0 + 0.25));
            break;
          case Tetrahedral: {
            const Real cosTheta = cos(thetaEnergy);
            // use cos(2t) = 2cos^2(t) - 1
            *energy +=
              kijk * (c0 + c1 * cosTheta + c2 * (2 * cosTheta * cosTheta - 1));
            break;
          }
          case TrigonalBipyramidal:
          case TrigonalBipentagonal:
          case Other:
          default:
            // fallback to harmonic potential for unsupported coordinations
            *energy += kijk * (thetaEnergy - theta0) * (thetaEnergy - theta0);
            break;
        }
      }

      if (!needsGradient || thetaGradient <= 0.1)
        continue;

      Real dEdTheta = 0.0;
      switch (angle.coordination) {
        case Linear:
          dEdTheta = -kijk * c0 * sin(c0 * thetaGradient);
          break;
        case Trigonal:
        case Resonant:
        case SquarePlanar:
        case Octahedral:
          dEdTheta = kijk * c0 * sin(c0 * thetaGradient) -
                     20.0 * exp(-20.0 * (thetaGradient - theta0 + 0.25));
          break;
        case Tetrahedral: {
          const Real cosTheta = cos(thetaGradient);
          const Real sinTheta = sin(thetaGradient);
          dEdTheta =
            -kijk * (c1 * sinTheta + c2 * 2 * (2 * cosTheta * sinTheta));
          break;
        }
        case TrigonalBipyramidal:
        case TrigonalBipentagonal:
        case Other:
        default:
          // E = k (theta - theta0)^2 and angleGradient() gives d(theta)/dx,
          // so dE/dtheta has no sin(theta) factor
          dEdTheta = 2.0 * kijk * (thetaGradient - theta0);
          break;
      }

      if (std::isnan(dEdTheta))
        continue;

      grad->segment<3>(3 * i) += dEdTheta * grad_i;
      grad->segment<3>(3 * j) += dEdTheta * grad_j;
      grad->segment<3>(3 * k) += dEdTheta * grad_k;
    }
  }

  void oopEvaluate(const Eigen::VectorXd& x, Real* energy,
                   Eigen::VectorXd* grad)
  {
    const bool needsGradient = grad != nullptr;
    const bool periodic = usesMinimumImage();

    for (const UFFOOP& oop : m_oops) {
      // for UFF, i is the central atom
      const Index i = oop._atom1;
      const Index j = oop._atom2;
      const Index k = oop._atom3;
      const Index l = oop._atom4;

      const Real koop = oop._koop;
      const Real c0 = oop._c0;
      const Real c1 = oop._c1;
      const Real c2 = oop._c2;

      // all three neighbors at their shortest images from the central atom
      const Vector3d vi = x.segment<3>(3 * i);
      const Vector3d vj = vi + bondedVector(x, i, j, periodic);
      const Vector3d vk = vi + bondedVector(x, i, k, periodic);
      const Vector3d vl = vi + bondedVector(x, i, l, periodic);

      Real angleGradient = 0.0;
      Vector3d grad_i = Vector3d::Zero();
      Vector3d grad_j = Vector3d::Zero();
      Vector3d grad_k = Vector3d::Zero();
      Vector3d grad_l = Vector3d::Zero();
      if (needsGradient) {
        angleGradient = ::Avogadro::Calc::outOfPlaneGradient(
          vi, vj, vk, vl, grad_i, grad_j, grad_k, grad_l);
      }

      if (energy != nullptr) {
        // Match the legacy value() path.
        const Real angleEnergy = outOfPlaneAngle(vi, vj, vk, vl) * DEG_TO_RAD;
        *energy +=
          koop * (c0 + c1 * cos(angleEnergy) + c2 * cos(2 * angleEnergy));
      }

      if (!needsGradient)
        continue;

      const Real dE =
        koop * (-c1 * sin(angleGradient) - 2.0 * c2 * sin(2.0 * angleGradient));
      if (std::isnan(dE))
        continue;

      grad->segment<3>(3 * i) += dE * grad_i;
      grad->segment<3>(3 * j) += dE * grad_j;
      grad->segment<3>(3 * k) += dE * grad_k;
      grad->segment<3>(3 * l) += dE * grad_l;
    }
  }

  // Smooth switch that turns a torsion off as one of its bond angles nears
  // 180 degrees, as a function of c = cos(theta). It is 1 for theta <= 170
  // degrees and falls to 0 at 180 degrees (C2 smoothstep in c). At a linear
  // angle the dihedral is undefined, so without it the torsion energy jumps
  // and its gradient diverges. This deliberately deviates from Rappe 1992
  // (like the extra exp() term in the angle energy). dS receives dS/dc.
  static Real torsionSwitch(Real cosTheta, Real& dS)
  {
    static const Real onset =
      1.0 + std::cos(TORSION_SWITCH_ONSET_DEGREES * DEG_TO_RAD);
    static const Real onsetInv = 1.0 / onset;
    Real u = (cosTheta + 1.0) * onsetInv;
    u = std::clamp(u, 0.0, 1.0);
    dS = (u > 0.0 && u < 1.0) ? 30.0 * u * u * (1.0 - u) * (1.0 - u) * onsetInv
                              : 0.0;
    return u * u * u * (10.0 - 15.0 * u + 6.0 * u * u);
  }

  // cos(angle a-b-c) and its gradient with respect to a, b and c. Returns
  // false if either bond has zero length.
  static bool cosineAndGradient(const Vector3d& a, const Vector3d& b,
                                const Vector3d& c, Real& cosine, Vector3d& ga,
                                Vector3d& gb, Vector3d& gc)
  {
    const Vector3d u = a - b;
    const Vector3d v = c - b;
    const Real lu = u.norm();
    const Real lv = v.norm();
    if (lu < 1e-6 || lv < 1e-6)
      return false;
    const Vector3d uh = u / lu;
    const Vector3d vh = v / lv;
    cosine = std::clamp(uh.dot(vh), -1.0, 1.0);
    ga = (vh - cosine * uh) / lu;
    gc = (uh - cosine * vh) / lv;
    gb = -(ga + gc);
    return true;
  }

  void torsionEvaluate(const Eigen::VectorXd& x, Real* energy,
                       Eigen::VectorXd* grad)
  {
    const bool needsGradient = grad != nullptr;
    const bool periodic = usesMinimumImage();

    for (const UFFTorsion& torsion : m_torsions) {
      const Index i = torsion._atom1;
      const Index j = torsion._atom2;
      const Index k = torsion._atom3;
      const Index l = torsion._atom4;

      // follow the chain i-j-k-l so it stays contiguous across the boundary
      const Vector3d vi = x.segment<3>(3 * i);
      const Vector3d vj = vi + bondedVector(x, i, j, periodic);
      const Vector3d vk = vj + bondedVector(x, j, k, periodic);
      const Vector3d vl = vk + bondedVector(x, k, l, periodic);

      // switch off the torsion near linear bond angles (zero-length bonds
      // have no angle or dihedral, so the term is skipped for them too)
      Vector3d a1, b1, c1, a2, b2, c2;
      Real cos1 = 0.0;
      Real cos2 = 0.0;
      if (!cosineAndGradient(vi, vj, vk, cos1, a1, b1, c1) ||
          !cosineAndGradient(vj, vk, vl, cos2, a2, b2, c2))
        continue;
      Real dS1 = 0.0;
      Real dS2 = 0.0;
      const Real s1 = torsionSwitch(cos1, dS1);
      const Real s2 = torsionSwitch(cos2, dS2);
      if (s1 * s2 == 0.0)
        continue;

      const Real cosPhi0 = torsion._cos_phi0;
      const Real kijkl = torsion._ijkl;
      if (energy != nullptr) {
        const Real phiEnergy = calculateDihedral(vi, vj, vk, vl) * DEG_TO_RAD;
        const Real e0 = kijkl * (1.0 - cosPhi0 * cos(torsion._n * phiEnergy));
        if (std::isfinite(e0))
          *energy += s1 * s2 * e0;
      }

      if (!needsGradient)
        continue;

      Real phiGradient = 0.0;
      Vector3d grad_i = Vector3d::Zero();
      Vector3d grad_j = Vector3d::Zero();
      Vector3d grad_k = Vector3d::Zero();
      Vector3d grad_l = Vector3d::Zero();
      phiGradient =
        dihedralGradient(vi, vj, vk, vl, grad_i, grad_j, grad_k, grad_l);

      const Real e0 = kijkl * (1.0 - cosPhi0 * cos(torsion._n * phiGradient));
      const Real dE =
        kijkl * torsion._n * sin(torsion._n * phiGradient) * cosPhi0;
      if (!std::isfinite(dE) || !std::isfinite(e0))
        continue;

      // product rule: S1 S2 dE0 + E0 (S2 dS1 dcos1 + S1 dS2 dcos2)
      const Real w = s1 * s2;
      const Real w1 = e0 * s2 * dS1;
      const Real w2 = e0 * s1 * dS2;
      grad->segment<3>(3 * i) += w * dE * grad_i + w1 * a1;
      grad->segment<3>(3 * j) += w * dE * grad_j + w1 * b1 + w2 * a2;
      grad->segment<3>(3 * k) += w * dE * grad_k + w1 * c1 + w2 * b2;
      grad->segment<3>(3 * l) += w * dE * grad_l + w2 * c2;
    }
  }

  // Energy (kcal/mol) and dE/dr of one pair at squared distance r2 > 0,
  // including the soft core and the switch. dEdr is only set when requested.
  // r receives the pair distance sqrt(r2).
  static Real vdwPair(const UFFVdW& vdw, Real r2, Real& r, Real* dEdr)
  {
    r = sqrt(r2);
    const bool needsGradient = dEdr != nullptr;
    const Real rc = VDW_CORE_FRACTION * vdw._x; // soft-core radius
    Real e = 0.0;
    Real de = 0.0;
    if (r < rc) {
      // tangent line of the 12-6 curve at r_c (r < r_c implies r_c > 0)
      const Real rc2 = rc * rc;
      const Real rc6 = rc2 * rc2 * rc2;
      const Real ec = vdw._depth * (vdw._x12 / (rc6 * rc6) - 2 * vdw._x6 / rc6);
      de = 12 * vdw._depth * vdw._x6 / (rc6 * rc) * (1 - vdw._x6 / rc6);
      e = ec + de * (r - rc);
    } else {
      const Real r6 = r2 * r2 * r2;
      e = vdw._depth * (vdw._x12 / (r6 * r6) - 2 * vdw._x6 / r6);
      if (needsGradient)
        de = 12 * vdw._depth * vdw._x6 / (r6 * r) * (1 - vdw._x6 / r6);
    }

    if (r2 > VDW_R_ON_SQ) {
      // S(r) = (roff^2 - r^2)^2 (roff^2 + 2r^2 - 3ron^2) / (roff^2 - ron^2)^3
      const Real a = VDW_R_OFF_SQ - r2;
      const Real s =
        a * a * (VDW_R_OFF_SQ + 2 * r2 - 3 * VDW_R_ON_SQ) * VDW_SWITCH_INV;
      if (needsGradient) {
        const Real ds = 12 * r * a * (VDW_R_ON_SQ - r2) * VDW_SWITCH_INV;
        de = s * de + e * ds;
      }
      e *= s;
    }

    if (needsGradient)
      *dEdr = de;
    return e;
  }

  void vdwEvaluate(const Eigen::VectorXd& x, Real* energy,
                   Eigen::VectorXd* grad)
  {
    rebuildVdWsIfNeeded(x);

    const bool needsGradient = grad != nullptr;

    for (const UFFVdW& vdw : m_vdws) {
      const Index i = vdw._atom1;
      const Index j = vdw._atom2;
      const Vector3d vi = x.segment<3>(3 * i);
      const Vector3d vj = x.segment<3>(3 * j);

      Vector3d diff = Vector3d::Zero();
      Real r2 = 0.0;
      if (m_cell == nullptr) {
        diff = vi - vj;
        r2 = diff.squaredNorm();
      } else if (needsGradient) {
        diff = m_cell->minimumImage(vi - vj);
        r2 = diff.squaredNorm();
      } else {
        r2 = m_cell->distanceSquared(vi, vj);
      }

      // The energy is exactly zero beyond the switching distance
      if (r2 >= VDW_R_OFF_SQ)
        continue;

      Real r = 0.0;
      Real dEdr = 0.0;
      const Real e = vdwPair(vdw, r2, r, needsGradient ? &dEdr : nullptr);
      if (energy != nullptr)
        *energy += e;

      if (!needsGradient)
        continue;

      // Coincident atoms have no direction; the soft core still has a finite
      // force, so push them apart along a fixed axis instead of dropping it.
      Vector3d direction = Vector3d::UnitX();
      if (r2 > 1e-24)
        direction = diff / r;
      grad->segment<3>(3 * i) += dEdr * direction;
      grad->segment<3>(3 * j) -= dEdr * direction;
    }
  }

  void evaluate(const Eigen::VectorXd& x, Real* energy, Eigen::VectorXd* grad)
  {
    bondEvaluate(x, energy, grad);
    angleEvaluate(x, energy, grad);
    torsionEvaluate(x, energy, grad);
    oopEvaluate(x, energy, grad);
    vdwEvaluate(x, energy, grad);
  }

  Real bondEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    bondEvaluate(x, &energy, nullptr);
    return energy;
  }

  Real angleEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    angleEvaluate(x, &energy, nullptr);
    return energy;
  }

  Real oopEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    oopEvaluate(x, &energy, nullptr);
    return energy;
  }

  Real torsionEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    torsionEvaluate(x, &energy, nullptr);
    return energy;
  }

  Real vdwEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    vdwEvaluate(x, &energy, nullptr);
    return energy;
  }

  void bondGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    bondEvaluate(x, nullptr, &grad);
  }

  void angleGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    angleEvaluate(x, nullptr, &grad);
  }

  void oopGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    oopEvaluate(x, nullptr, &grad);
  }

  void torsionGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    torsionEvaluate(x, nullptr, &grad);
  }

  void vdwGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    vdwEvaluate(x, nullptr, &grad);
  }
};

UFF::UFF() : d(nullptr)
{
  // defined for every element in the parameter table (1-103, plus the
  // dummy atom at 0)
  for (const parameter& row : uffparams) {
    m_elements.set(static_cast<size_t>(row.element));
  }
}

UFF::~UFF()
{
  delete d;
  d = nullptr;
}

void UFF::setMolecule(Core::Molecule* mol)
{
  if (d != nullptr) {
    delete d;
    d = nullptr;
  }

  m_molecule = mol;

  if (mol == nullptr) {
    return; // nothing to do
  }

  setMaskFromMolecule(*mol);

  int numAtoms = mol->atomCount();
  if (numAtoms < 2)
    return; // nothing to do for single atoms

  // start with assigning atom types
  d = new UFFPrivate(mol);
}

std::string UFF::atomTypeLabel(Index atomIndex) const
{
  if (d == nullptr || atomIndex >= d->m_atomTypes.size())
    return std::string();
  const int type = d->m_atomTypes[atomIndex];
  if (type < 0 || static_cast<size_t>(type) >= std::size(uffparams))
    return std::string();
  return uffparams[type].label;
}

Real UFF::value(const Eigen::VectorXd& x)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return 0.0;
  if (m_molecule->atomCount() < 2)
    return 0.0; // no bonds

  Real energy = 0.0;
  d->evaluate(x, &energy, nullptr);
  // UFF terms are in kcal/mol; restraints are already in kJ/mol
  return energy * KCAL_TO_KJ + constraintEnergies(x);
}

Real UFF::evaluate(const Eigen::VectorXd& x, Eigen::VectorXd* grad)
{
  if (grad != nullptr) {
    if (grad->rows() != x.rows())
      grad->resize(x.rows());
    grad->setZero();
  }

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return 0.0;
  if (m_molecule->atomCount() < 2)
    return 0.0; // no bonds

  Real energy = 0.0;
  d->evaluate(x, &energy, grad);

  // Convert the UFF terms from kcal/mol to kJ/mol before adding restraints,
  // which are already in kJ/mol (see core/constraint.h)
  energy = energy * KCAL_TO_KJ + constraintEnergies(x);

  if (grad != nullptr) {
    *grad *= KCAL_TO_KJ;
    cleanGradients(*grad);
    constraintGradients(x, *grad);
  }

  return energy;
}

Real UFF::bondEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 2)
    return energy; // no bonds

  energy = d->bondEnergies(x);
  return energy;
}

Real UFF::angleEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 3)
    return energy; // no angle

  energy = d->angleEnergies(x);
  return energy;
}

Real UFF::oopEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 4)
    return energy; // no oop

  energy = d->oopEnergies(x);
  return energy;
}

Real UFF::torsionEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 4)
    return energy; // no torsion

  energy = d->torsionEnergies(x);
  return energy;
}

Real UFF::vdwEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 2)
    return energy; // nothing to do

  energy = d->vdwEnergies(x);
  return energy;
}

void UFF::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  evaluate(x, &grad);
}

void UFF::bondGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 2)
    return; // no bonds

  d->bondGradient(x, grad);
}

void UFF::angleGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 3)
    return; // no bonds

  d->angleGradient(x, grad);
}

void UFF::oopGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 4)
    return; // no bonds

  d->oopGradient(x, grad);
}

void UFF::torsionGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 4)
    return; // no bonds

  d->torsionGradient(x, grad);
}

void UFF::vdwGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 2)
    return; // no bonds

  d->vdwGradient(x, grad);
}

} // namespace Avogadro::Calc
