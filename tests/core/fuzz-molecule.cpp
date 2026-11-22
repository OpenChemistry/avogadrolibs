/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>

#include <string>

#include "fuzzhelpers.h"

using namespace Avogadro;
using namespace Avogadro::Core;
using Avogadro::FuzzHelpers::consumeAtomicNumber;
using Avogadro::FuzzHelpers::consumeVector3;

// Fuzz Core::Molecule mutation operations and common queries.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Molecule mol = FuzzHelpers::buildMolecule(fdp);

  // A snapshot held across later edits. Restoring it is usually a misuse
  // (the molecule is no longer as the removal left it), which must be
  // refused or survived, never crash.
  Index heldAtomId = MaxIndex;
  AtomSnapshot heldAtom;
  Index heldBondId = MaxIndex;
  BondSnapshot heldBond;

  size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, 128);
  for (size_t i = 0; i < steps; ++i) {
    switch (fdp.ConsumeIntegral<uint8_t>() % 22) {
      case 0: { // add atom
        unsigned char z = consumeAtomicNumber(fdp);
        mol.addAtom(z);
        break;
      }
      case 1: { // remove atom
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        mol.removeAtom(atomId);
        break;
      }
      case 2: { // add bond
        if (mol.atomCount() < 2)
          break;
        Index a = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        Index b = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        if (a == b)
          break;
        unsigned char order =
          static_cast<unsigned char>(1 + (fdp.ConsumeIntegral<uint8_t>() % 3));
        mol.addBond(a, b, order);
        break;
      }
      case 3: { // remove bond
        if (mol.bondCount() == 0)
          break;
        Index bondId = fdp.ConsumeIntegral<uint8_t>() % mol.bondCount();
        mol.removeBond(bondId);
        break;
      }
      case 4: { // set atom position
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        mol.setAtomPosition3d(atomId, consumeVector3(fdp));
        break;
      }
      case 5: { // set atomic number
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        mol.setAtomicNumber(atomId, consumeAtomicNumber(fdp));
        break;
      }
      case 6: { // set formal charge
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        signed char charge =
          static_cast<signed char>(fdp.ConsumeIntegralInRange<int>(-3, 3));
        mol.setFormalCharge(atomId, charge);
        break;
      }
      case 7: { // set isotope
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        unsigned short isotope =
          static_cast<unsigned short>(fdp.ConsumeIntegral<uint16_t>());
        mol.setIsotope(atomId, isotope);
        break;
      }
      case 8: { // set atom label
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        mol.setAtomLabel(atomId, FuzzHelpers::consumeString(fdp, 64));
        break;
      }
      case 9: { // set bond order
        if (mol.bondCount() == 0)
          break;
        Index bondId = fdp.ConsumeIntegral<uint8_t>() % mol.bondCount();
        unsigned char order =
          static_cast<unsigned char>(1 + (fdp.ConsumeIntegral<uint8_t>() % 3));
        mol.setBondOrder(bondId, order);
        break;
      }
      case 10: { // set bond label
        if (mol.bondCount() == 0)
          break;
        Index bondId = fdp.ConsumeIntegral<uint8_t>() % mol.bondCount();
        mol.setBondLabel(bondId, FuzzHelpers::consumeString(fdp, 64));
        break;
      }
      case 11: { // set force vector
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        mol.setForceVector(atomId, consumeVector3(fdp));
        break;
      }
      case 12: { // remove an atom and restore it at once: must round-trip
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        const Index atoms = mol.atomCount();
        const Index bonds = mol.bondCount();
        const unsigned char number = mol.atomicNumber(atomId);
        const AtomSnapshot snapshot = mol.atomSnapshot(atomId);
        if (!mol.removeAtom(atomId))
          break;
        if (!mol.restoreAtomSnapshot(atomId, snapshot) ||
            mol.atomCount() != atoms || mol.bondCount() != bonds ||
            mol.atomicNumber(atomId) != number)
          __builtin_trap();
        // A second restoration is stale and must be refused.
        if (mol.restoreAtomSnapshot(atomId, snapshot))
          __builtin_trap();
        break;
      }
      case 13: { // remove an atom, holding its snapshot
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        heldAtom = mol.atomSnapshot(atomId);
        heldAtomId = atomId;
        mol.removeAtom(atomId);
        break;
      }
      case 14: { // restore the held atom, whatever happened since
        if (heldAtomId == MaxIndex)
          break;
        if (mol.restoreAtomSnapshot(heldAtomId, heldAtom))
          heldAtomId = MaxIndex;
        break;
      }
      case 15: { // remove a bond and restore it at once: must round-trip
        if (mol.bondCount() == 0)
          break;
        Index bondId = fdp.ConsumeIntegral<uint8_t>() % mol.bondCount();
        const Index bonds = mol.bondCount();
        const unsigned char order = mol.bondOrder(bondId);
        const BondSnapshot snapshot = mol.bondSnapshot(bondId);
        if (!mol.removeBond(bondId))
          break;
        if (!mol.restoreBondSnapshot(bondId, snapshot) ||
            mol.bondCount() != bonds || mol.bondOrder(bondId) != order)
          __builtin_trap();
        if (mol.restoreBondSnapshot(bondId, snapshot))
          __builtin_trap();
        break;
      }
      case 16: { // remove a bond, holding its snapshot
        if (mol.bondCount() == 0)
          break;
        Index bondId = fdp.ConsumeIntegral<uint8_t>() % mol.bondCount();
        heldBond = mol.bondSnapshot(bondId);
        heldBondId = bondId;
        mol.removeBond(bondId);
        break;
      }
      case 17: { // restore the held bond, whatever happened since
        if (heldBondId == MaxIndex)
          break;
        if (mol.restoreBondSnapshot(heldBondId, heldBond))
          heldBondId = MaxIndex;
        break;
      }
      case 18: { // add a coordinate set, possibly shorter than atomCount()
        Array<Vector3> frame(
          fdp.ConsumeIntegralInRange<size_t>(0, mol.atomCount() + 1));
        for (auto& position : frame)
          position = consumeVector3(fdp);
        mol.setCoordinate3d(frame, mol.coordinate3dCount());
        break;
      }
      case 19: { // add a constraint between two to four atoms
        if (mol.atomCount() < 2)
          break;
        auto pick = [&]() {
          return static_cast<Index>(fdp.ConsumeIntegral<uint8_t>() %
                                    mol.atomCount());
        };
        const Index a = pick();
        const Index b = pick();
        const Index c = fdp.ConsumeBool() ? pick() : MaxIndex;
        mol.addConstraint(1.0, a, b, c);
        break;
      }
      case 20: { // put an atom into a new residue
        if (mol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
        std::string name = "RES";
        Index number = mol.residueCount() + 1;
        char chain = 'A';
        Residue& residue = mol.addResidue(name, number, chain);
        residue.addResidueAtom("X" + std::to_string(atomId), mol.atom(atomId));
        break;
      }
      case 21: { // set a custom atom or bond property
        if (fdp.ConsumeBool()) {
          if (mol.atomCount() == 0)
            break;
          Index atomId = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
          mol.atomProperties().setDouble("p", atomId,
                                         fdp.ConsumeFloatingPoint<double>());
        } else {
          if (mol.bondCount() == 0)
            break;
          Index bondId = fdp.ConsumeIntegral<uint8_t>() % mol.bondCount();
          mol.bondProperties().setInt("q", bondId, fdp.ConsumeIntegral<int>());
        }
        break;
      }
      default:
        break;
    }
  }

  if (mol.atomCount() > 0) {
    mol.centerOfGeometry();
    mol.centerOfMass();
    mol.radius();
    mol.formula();
  }

  Vector3 minPos = Vector3::Zero();
  Vector3 maxPos = Vector3::Zero();
  mol.boundingBox(minPos, maxPos);

  if (mol.bondCount() > 0)
    mol.perceiveBondOrders();

  return 0;
}
