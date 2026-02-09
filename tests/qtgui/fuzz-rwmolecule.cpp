/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <QtCore/QCoreApplication>

#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include "fuzzhelpers.h"

using namespace Avogadro;
using namespace Avogadro::Core;
using namespace Avogadro::QtGui;

namespace {
QCoreApplication* ensureApp()
{
  static int argc = 1;
  static char arg0[] = "fuzz";
  static char* argv[] = { arg0, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

} // namespace

// Fuzz QtGui::RWMolecule mutation operations and undo stack.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  ensureApp();

  FuzzedDataProvider fdp(Data, Size);

  Molecule mol = FuzzHelpers::buildMolecule(fdp);
  RWMolecule rwmol(mol);

  size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, 128);
  for (size_t i = 0; i < steps; ++i) {
    switch (fdp.ConsumeIntegral<uint8_t>() % 14) {
      case 0: { // add atom
        unsigned char z = consumeAtomicNumber(fdp);
        if (fdp.ConsumeBool())
          rwmol.addAtom(z, consumeVector3(fdp));
        else
          rwmol.addAtom(z, fdp.ConsumeBool());
        break;
      }
      case 1: { // remove atom
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        rwmol.removeAtom(atomId);
        break;
      }
      case 2: { // add bond
        if (rwmol.atomCount() < 2)
          break;
        Index a = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        Index b = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        if (a == b)
          break;
        unsigned char order =
          static_cast<unsigned char>(1 + (fdp.ConsumeIntegral<uint8_t>() % 3));
        rwmol.addBond(a, b, order);
        break;
      }
      case 3: { // remove bond
        if (rwmol.bondCount() == 0)
          break;
        Index bondId = fdp.ConsumeIntegral<uint8_t>() % rwmol.bondCount();
        rwmol.removeBond(bondId);
        break;
      }
      case 4: { // set atom position
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        rwmol.setAtomPosition3d(atomId, consumeVector3(fdp));
        break;
      }
      case 5: { // set atomic number
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        rwmol.setAtomicNumber(atomId, consumeAtomicNumber(fdp));
        break;
      }
      case 6: { // set atom label
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        rwmol.setAtomLabel(atomId, FuzzHelpers::consumeString(fdp, 64));
        break;
      }
      case 7: { // set bond label
        if (rwmol.bondCount() == 0)
          break;
        Index bondId = fdp.ConsumeIntegral<uint8_t>() % rwmol.bondCount();
        rwmol.setBondLabel(bondId, FuzzHelpers::consumeString(fdp, 64));
        break;
      }
      case 8: { // set formal charge
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        signed char charge =
          static_cast<signed char>(fdp.ConsumeIntegralInRange<int>(-3, 3));
        rwmol.setFormalCharge(atomId, charge);
        break;
      }
      case 9: { // set isotope
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        unsigned short isotope =
          static_cast<unsigned short>(fdp.ConsumeIntegral<uint16_t>());
        rwmol.setIsotope(atomId, isotope);
        break;
      }
      case 10: { // set color
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        Vector3ub color(fdp.ConsumeIntegral<uint8_t>(),
                        fdp.ConsumeIntegral<uint8_t>(),
                        fdp.ConsumeIntegral<uint8_t>());
        rwmol.setColor(atomId, color);
        break;
      }
      case 11: { // set layer
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        size_t layer = fdp.ConsumeIntegral<uint8_t>();
        rwmol.setLayer(atomId, layer);
        break;
      }
      case 12: { // selection
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        rwmol.setAtomSelected(atomId, fdp.ConsumeBool());
        rwmol.atomSelected(atomId);
        break;
      }
      case 13: { // undo/redo
        if (fdp.ConsumeBool())
          rwmol.undoStack().undo();
        else
          rwmol.undoStack().redo();
        break;
      }
      default:
        break;
    }
  }

  if (rwmol.atomCount() > 0) {
    rwmol.molecule().centerOfGeometry();
    rwmol.molecule().centerOfMass();
    rwmol.molecule().radius();
  }

  return 0;
}
