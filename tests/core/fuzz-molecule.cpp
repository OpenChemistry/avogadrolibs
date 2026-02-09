/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>

#include "fuzzhelpers.h"

using namespace Avogadro;
using namespace Avogadro::Core;

namespace {
unsigned char consumeAtomicNumber(FuzzedDataProvider& fdp)
{
  uint8_t z = fdp.ConsumeIntegral<uint8_t>();
  return static_cast<unsigned char>(1 + (z % (Core::element_count - 1)));
}

Vector3 consumeVector3(FuzzedDataProvider& fdp)
{
  float x = fdp.ConsumeFloatingPointInRange<float>(-FuzzHelpers::kCoordRange,
                                                   FuzzHelpers::kCoordRange);
  float y = fdp.ConsumeFloatingPointInRange<float>(-FuzzHelpers::kCoordRange,
                                                   FuzzHelpers::kCoordRange);
  float z = fdp.ConsumeFloatingPointInRange<float>(-FuzzHelpers::kCoordRange,
                                                   FuzzHelpers::kCoordRange);
  return Vector3(x, y, z);
}
} // namespace

// Fuzz Core::Molecule mutation operations and common queries.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Molecule mol = FuzzHelpers::buildMolecule(fdp);

  size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, 128);
  for (size_t i = 0; i < steps; ++i) {
    switch (fdp.ConsumeIntegral<uint8_t>() % 12) {
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
