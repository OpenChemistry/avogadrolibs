/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "atomutilities.h"

#include <avogadro/core/elements.h>

#include <algorithm>
#include <cmath>
#include <vector>

constexpr double M_TETRAHED = 109.47122063449069389;

namespace Avogadro::Core {

using NeighborListType = Array<Bond>;

inline unsigned int countExistingBonds(const NeighborListType& bonds)
{
  unsigned int result(0);
  for (auto bond : bonds) {
    result += static_cast<unsigned int>(bond.order());
  }
  return result;
}

AtomHybridization AtomUtilities::perceiveHybridization(const Atom& atom)
{
  const NeighborListType bonds(atom.molecule()->bonds(atom));
  const unsigned int numberOfBonds(countExistingBonds(bonds)); // bond order sum

  AtomHybridization hybridization = SP3; // default to sp3

  // TODO: Handle hypervalent species, SO3, SO4, lone pairs, etc.

  if (numberOfBonds > 4) {
    //      hybridization = numberOfBonds; // e.g., octahedral, trig. bipyr.,
    //      etc.
  } else {
    // Count multiple bonds
    unsigned int numTripleBonds = 0;
    unsigned int numDoubleBonds = 0;

    for (auto bond : bonds) {
      if (bond.order() == 2)
        numDoubleBonds++;
      else if (bond.order() == 3)
        numTripleBonds++;
    }

    if (numTripleBonds > 0 || numDoubleBonds > 1)
      hybridization = SP; // sp
    else if (numDoubleBonds > 0)
      hybridization = SP2; // sp2

    // special case for nitrogen in an amide
    if (atom.atomicNumber() == 7 && hybridization == SP3) {
      // look through the neighbors for a C=O
      for (auto bond : bonds) {
        Atom a1 = bond.getOtherAtom(atom);
        if (a1.atomicNumber() == 6 && bond.order() == 1) {
          const NeighborListType nbrBonds(atom.molecule()->bonds(a1));
          for (auto nbrBond : nbrBonds) {
            Atom a2 = nbrBond.getOtherAtom(a1);
            if (a2.index() == atom.index())
              continue; // we want a *new* atom, not the nitrogen

            if (a2.atomicNumber() == 8 && nbrBond.order() == 2) {
              hybridization = SP2;
              break;
            }
          }
        }
      }
    }
  }
  return hybridization;
}

// Generate bond geometries
// First, the default fallback (random vectors)
// Also applies when you have a linear geometry and just need one new vector
// (it doesn't matter where it goes).
Vector3 AtomUtilities::generateNewBondVector(
  const Atom& atom, const std::vector<Vector3>& allVectors,
  AtomHybridization hybridization)
{
  Vector3 newPos;
  bool success = false;
  int currentValence = static_cast<int>(allVectors.size());

  // No bonded atoms, just pick a random vector
  if (currentValence == 0) {
    newPos = Vector3::Random().normalized();
    return newPos;
  } else if (currentValence == 1) {
    // One bonded atom
    const Vector3& bond1 = allVectors[0];

    // Check what's attached to our neighbor -- we want to set trans to the
    // neighbor
    Vector3 bond2(0.0, 0.0, 0.0);

    const NeighborListType bonds(atom.molecule()->bonds(atom));
    for (auto bond : bonds) {
      Atom a1 = bond.getOtherAtom(atom);
      const NeighborListType nbrBonds(atom.molecule()->bonds(a1));
      for (auto nbrBond : nbrBonds) {
        Atom a2 = nbrBond.getOtherAtom(a1);
        if (a2.index() == atom.index())
          continue; // we want a *new* atom

        Vector3 delta = a2.position3d() - a1.position3d();
        if (!delta.isZero(1e-5))
          bond2 = delta.normalized();

        // Check for carboxylate (CO2)
        if ((atom.atomicNumber() == 8)  // atom for H is O
            && (a1.atomicNumber() == 6) // central atom is C
            && (nbrBond.order() == 2) && (a2.atomicNumber() == 8))
          break; // make sure the H will be trans to the C=O
      }
    }

    Vector3 v1, v2;
    v1 = bond1.cross(bond2);

    if (bond2.norm() < 1.0e-5 || v1.norm() < 1.0e-5) {
      //        std::cout << " creating a random paired atom " << std::endl;

      v2 = Vector3::Random().normalized();

      double angle = fabs(acos(bond1.dot(v2)));
      while (angle < 45.0 * DEG_TO_RAD || angle > 135.0 * DEG_TO_RAD) {
        v2 = Vector3::Random().normalized();
        angle = fabs(acos(bond1.dot(v2)));
        //          std::cout << "angle = " << angle*RAD_TO_DEG << std::endl;
      }
      v1 = bond1.cross(v2); // so find a perpendicular, given the random vector
      v2 = bond1.cross(v1);
    } else {
      //        std::cout << " found a neighbor for trans " << std::endl;
      v1 = bond1.cross(bond2);
      v2 = -1.0 * bond1.cross(v1);
    }
    v2.normalize();

    switch (hybridization) {
      case SP:
      case SquarePlanar:
      case TrigonalBipyramidal:
        newPos = bond1; // 180 degrees away from the current neighbor
        break;
      case SP2: // sp2
        newPos = bond1 - v2 * tan(DEG_TO_RAD * 120.0);
        break;
      case Octahedral: // octahedral
        newPos = bond1 - v2 * tan(DEG_TO_RAD * 90.0);
        break;
      case SP3:
      default:
        newPos = (bond1 - v2 * tan(DEG_TO_RAD * M_TETRAHED));
        break;
    }

    //      std::cout << " one bond " << newPos.normalized() << std::endl;
    return -1.0 * newPos.normalized();
  } // end one bond
  else if (currentValence == 2) {
    const Vector3& bond1 = allVectors[0];
    const Vector3& bond2 = allVectors[1];

    Vector3 v1 = bond1 + bond2;
    v1.normalize();

    switch (hybridization) {
      case SP: // shouldn't happen, but maybe with metal atoms?
      case SP2:
        newPos = v1; // point away from the two existing bonds
        break;
      case SP3:
      default:
        Vector3 v2 = bond1.cross(bond2); // find the perpendicular
        v2.normalize();
        // newPos = bond1 - v2 * tan(DEG_TO_RAD * (M_TETRAHED));
        newPos = v2 + v1 * (sqrt(2.0) / 2.0);
    }

    //      std::cout << " two bonds " << newPos.normalized() << std::endl;
    return -1.0 * newPos.normalized();
  } // end two bonds
  else if (currentValence == 3) {
    const Vector3& bond1 = allVectors[0];
    const Vector3& bond2 = allVectors[1];
    const Vector3& bond3 = allVectors[2];

    // need to handle different hybridizations here

    // since the base of the tetrahedron should be symmetric
    // the sum of the three bond vectors should cancel the angular parts
    // and point in the new direction.. just need to normalize and rescale
    newPos = -1.0 * (bond1 + bond2 + bond3);

    //      std::cout << " three bonds " << newPos.normalized() << std::endl;
    return newPos.normalized();
  }

  // Fallback:
  // Try 10 times to generate a random vector that doesn't overlap with
  // an existing bond. If we can't, just give up and let the overlap occur.

  // Tolerance for two vectors being "too close" in radians (pi/8).
  const Avogadro::Real cosRadTol =
    cos(static_cast<Avogadro::Real>(M_PI) / static_cast<Avogadro::Real>(8.));

  for (int attempt = 0; !success && attempt < 10; ++attempt) {
    newPos = Vector3::Random().normalized();
    success = true;
    for (auto it = allVectors.begin(), itEnd = allVectors.end();
         success && it != itEnd; ++it) {
      success = newPos.dot(*it) < cosRadTol;
    }
  }
  return newPos;
}

namespace {

/**
 * A measured length for one element pair and bond order, used where the sum of
 * covalent radii is a poor estimate.
 */
struct IdealBondLength
{
  unsigned char atomicNumber1; //!< always <= atomicNumber2
  unsigned char atomicNumber2;
  unsigned char order;
  double length; //!< in Angstroms
};

/** Pack a bond into a sortable key. Atomic numbers need 8 bits, order 4. */
constexpr unsigned int bondKey(unsigned char atomicNumber1,
                               unsigned char atomicNumber2, unsigned char order)
{
  return (static_cast<unsigned int>(atomicNumber1) << 12) |
         (static_cast<unsigned int>(atomicNumber2) << 4) |
         static_cast<unsigned int>(order);
}

/**
 * Bonds whose measured length differs from the covalent radii estimate by more
 * than ~1.5%, plus the common organic bonds, which are pinned so that editing
 * a hydrocarbon reproduces textbook geometry exactly.
 *
 * Single and multiple bond references are averages over the Cambridge
 * Structural Database (Allen et al., J. Chem. Soc. Perkin Trans. II, 1987,
 * S1-S19) where one exists, otherwise gas phase microwave or electron
 * diffraction values for the parent molecule (CRC Handbook, 97th ed.).
 *
 * Sorted by (atomicNumber1, atomicNumber2, order); keep it that way.
 */
const IdealBondLength ideal_bond_lengths[] = {
  { 1, 1, 1, 0.741 },  // H-H   H2 (radii: 0.640)
  { 1, 5, 1, 1.190 },  // H-B   B2H6 terminal (radii: 1.170)
  { 1, 6, 1, 1.090 },  // H-C   CH4 / CSD sp3 (radii: 1.070)
  { 1, 7, 1, 1.012 },  // H-N   NH3 (radii: 1.030)
  { 1, 8, 1, 0.958 },  // H-O   H2O (radii: 0.950)
  { 1, 9, 1, 0.917 },  // H-F   HF (radii: 0.960)
  { 1, 16, 1, 1.341 }, // H-S   H2S (radii: 1.350)
  { 1, 17, 1, 1.275 }, // H-Cl  HCl (radii: 1.310)
  { 1, 35, 1, 1.414 }, // H-Br  HBr (radii: 1.460)
  { 1, 53, 1, 1.609 }, // H-I   HI (radii: 1.650)

  { 5, 5, 1, 1.750 },  // B-B   B2Cl4 (radii: 1.700)
  { 5, 8, 1, 1.370 },  // B-O   borates (radii: 1.480)
  { 5, 9, 1, 1.307 },  // B-F   BF3 (radii: 1.490)
  { 5, 17, 1, 1.742 }, // B-Cl  BCl3 (radii: 1.840)

  { 6, 6, 1, 1.540 },  // C-C   ethane 1.535 / diamond 1.544 (radii: 1.500)
  { 6, 6, 2, 1.331 },  // C=C   CSD alkene (radii: 1.312)
  { 6, 6, 3, 1.200 },  // C#C   acetylene 1.203 / CSD 1.181 (radii: 1.185)
  { 6, 7, 1, 1.469 },  // C-N   CSD sp3 (radii: 1.460)
  { 6, 7, 2, 1.279 },  // C=N   CSD imine (radii: 1.277)
  { 6, 7, 3, 1.140 },  // C#N   nitrile (radii: 1.153)
  { 6, 8, 1, 1.426 },  // C-O   CSD sp3 (radii: 1.380)
  { 6, 8, 2, 1.220 },  // C=O   CSD ketone (radii: 1.208)
  { 6, 8, 3, 1.128 },  // C#O   CO (radii: 1.090)
  { 6, 14, 1, 1.863 }, // C-Si  CSD (radii: 1.910)
  { 6, 16, 1, 1.819 }, // C-S   CSD sp3 (radii: 1.780)
  { 6, 16, 2, 1.650 }, // C=S   CSD thioketone (radii: 1.594)
  { 6, 17, 1, 1.790 }, // C-Cl  CSD sp3 (radii: 1.740)
  { 6, 34, 1, 1.970 }, // C-Se  CSD (radii: 1.910)
  { 6, 34, 2, 1.770 }, // C=Se  selenoketone (radii: 1.735)
  { 6, 35, 1, 1.966 }, // C-Br  CSD sp3 (radii: 1.890)
  { 6, 53, 1, 2.162 }, // C-I   CSD sp3 (radii: 2.080)

  { 7, 7, 1, 1.449 },  // N-N   hydrazine (radii: 1.420)
  { 7, 7, 2, 1.240 },  // N=N   CSD azo (radii: 1.242)
  { 7, 7, 3, 1.098 },  // N#N   N2 (radii: 1.122)
  { 7, 8, 1, 1.440 },  // N-O   hydroxylamine/CSD (radii: 1.340)
  { 7, 8, 2, 1.220 },  // N=O   CSD nitro/nitroso (radii: 1.172)
  { 7, 14, 1, 1.720 }, // N-Si  CSD (radii: 1.870)
  { 7, 15, 1, 1.650 }, // N-P   CSD (radii: 1.820)
  { 7, 15, 2, 1.580 }, // N=P   phosphazene (radii: 1.631)
  { 7, 16, 1, 1.700 }, // N-S   CSD (radii: 1.740)
  { 7, 17, 1, 1.750 }, // N-Cl  NCl3 (radii: 1.700)

  { 8, 8, 1, 1.475 },  // O-O   H2O2 (radii: 1.260)
  { 8, 8, 2, 1.208 },  // O=O   O2 (radii: 1.103)
  { 8, 9, 1, 1.420 },  // O-F   OF2 1.405 (radii: 1.270)
  { 8, 14, 1, 1.630 }, // O-Si  silicates (radii: 1.790)
  { 8, 15, 1, 1.600 }, // O-P   P-OH (radii: 1.740)
  { 8, 15, 2, 1.480 }, // O=P   phosphine oxide (radii: 1.561)
  { 8, 16, 1, 1.570 }, // O-S   S-OH (radii: 1.660)
  { 8, 16, 2, 1.440 }, // O=S   sulfone (radii: 1.489)
  { 8, 17, 1, 1.690 }, // O-Cl  HOCl (radii: 1.620)
  { 8, 17, 2, 1.430 }, // O=Cl  perchlorate 1.44 (radii: 1.452)

  { 9, 9, 1, 1.412 },  // F-F   F2 (radii: 1.280)
  { 9, 14, 1, 1.570 }, // F-Si  SiF4 1.554 (radii: 1.800)
  { 9, 15, 1, 1.570 }, // F-P   PF3 (radii: 1.750)
  { 9, 16, 1, 1.564 }, // F-S   SF6 (radii: 1.670)

  { 14, 14, 2, 2.160 }, // Si=Si disilene (radii: 2.111)
  { 14, 17, 1, 2.019 }, // Si-Cl SiCl4 (radii: 2.150)

  { 15, 17, 1, 2.043 }, // P-Cl  PCl3 (radii: 2.100)
};

/** @return the period (row) of the periodic table @a atomicNumber sits in. */
unsigned char elementPeriod(unsigned char atomicNumber)
{
  if (atomicNumber <= 2)
    return 1;
  if (atomicNumber <= 10)
    return 2;
  if (atomicNumber <= 18)
    return 3;
  if (atomicNumber <= 36)
    return 4;
  if (atomicNumber <= 54)
    return 5;
  if (atomicNumber <= 86)
    return 6;
  return 7;
}

/**
 * @return the fraction of its single bond covalent radius that @a atomicNumber
 * contributes to a bond of order @a order.
 *
 * Multiple bond contraction weakens going down a group, so no single factor
 * fits both rows: C=C needs 0.89 while Si=Si needs 0.93. These are a
 * least-squares fit, per period, to the measured lengths above.
 */
double multipleBondScale(unsigned char atomicNumber, unsigned char order)
{
  if (order < 2)
    return 1.0;

  const unsigned char period = elementPeriod(atomicNumber);
  if (order == 2) {
    if (period <= 2)
      return 0.875;
    return (period == 3) ? 0.910 : 0.930;
  }
  if (period <= 2)
    return 0.790;
  return (period == 3) ? 0.845 : 0.870;
}

} // namespace

Real AtomUtilities::idealBondLength(unsigned char atomicNumber1,
                                    unsigned char atomicNumber2,
                                    unsigned char bondOrder)
{
  // Aromatic, dative and other orders outside 1-3 have no contraction to
  // apply, so fall back to the single bond length.
  if (bondOrder < 1 || bondOrder > 3)
    bondOrder = 1;

  // The table only stores each pair once, in ascending atomic number. Order
  // the pair once here so the result cannot depend on which way round the
  // caller passed the two atoms.
  const unsigned char lighter = std::min(atomicNumber1, atomicNumber2);
  const unsigned char heavier = std::max(atomicNumber1, atomicNumber2);

  const unsigned int key = bondKey(lighter, heavier, bondOrder);

  const IdealBondLength* begin = std::begin(ideal_bond_lengths);
  const IdealBondLength* end = std::end(ideal_bond_lengths);
  const IdealBondLength* match = std::lower_bound(
    begin, end, key, [](const IdealBondLength& bond, unsigned int value) {
      return bondKey(bond.atomicNumber1, bond.atomicNumber2, bond.order) <
             value;
    });

  if (match != end &&
      bondKey(match->atomicNumber1, match->atomicNumber2, match->order) == key)
    return match->length;

  // Otherwise sum the covalent radii, contracted for double and triple bonds.
  return Elements::radiusCovalent(lighter) *
           multipleBondScale(lighter, bondOrder) +
         Elements::radiusCovalent(heavier) *
           multipleBondScale(heavier, bondOrder);
}

} // namespace Avogadro::Core
