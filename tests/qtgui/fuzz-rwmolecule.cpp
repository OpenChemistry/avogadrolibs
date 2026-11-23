/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <QtCore/QCoreApplication>

#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/rwmolecule.h>

#include "fuzzhelpers.h"

#include <string>

using namespace Avogadro;
using namespace Avogadro::Core;
using namespace Avogadro::QtGui;

using Avogadro::FuzzHelpers::consumeAtomicNumber;
using Avogadro::FuzzHelpers::consumeVector3;

namespace {
QCoreApplication* ensureApp()
{
  static int argc = 1;
  static char arg0[] = "fuzz";
  static char* argv[] = { arg0, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

// Groups runs of atoms into residues, so that residue edits are reached and
// atom removal has residues to drop (and undo to restore). Each atom joins at
// most one residue. This is setup, not an undoable step.
void addResidues(FuzzedDataProvider& fdp, QtGui::Molecule& mol)
{
  const size_t numResidues = fdp.ConsumeIntegralInRange<size_t>(0, 4);
  Index next = 0;
  for (size_t r = 0; r < numResidues && next < mol.atomCount(); ++r) {
    std::string name = "R" + std::to_string(r);
    Index number = r + 1;
    char chain = 'A';
    Core::Residue& residue = mol.addResidue(name, number, chain);
    const size_t size = fdp.ConsumeIntegralInRange<size_t>(1, 8);
    for (size_t j = 0; j < size && next < mol.atomCount(); ++j, ++next)
      residue.addResidueAtom("X" + std::to_string(j), mol.atom(next));
  }
}

} // namespace

// Fuzz QtGui::RWMolecule mutation operations and undo stack.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  ensureApp();

  FuzzedDataProvider fdp(Data, Size);

  QtGui::Molecule mol = FuzzHelpers::buildMolecule(fdp);
  addResidues(fdp, mol);
  RWMolecule rwmol(mol);

  size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, 128);
  for (size_t i = 0; i < steps; ++i) {
    switch (fdp.ConsumeIntegral<uint8_t>() % 24) {
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
      case 14: // interactive mode, under which position edits merge
        rwmol.setInteractive(fdp.ConsumeBool());
        break;
      case 15: { // bond order (merges on the same bond)
        if (rwmol.bondCount() == 0)
          break;
        Index bondId = fdp.ConsumeIntegral<uint8_t>() % rwmol.bondCount();
        unsigned char order =
          static_cast<unsigned char>(1 + (fdp.ConsumeIntegral<uint8_t>() % 3));
        rwmol.setBondOrder(bondId, order);
        break;
      }
      case 16: { // bond pair
        if (rwmol.bondCount() == 0 || rwmol.atomCount() < 2)
          break;
        Index bondId = fdp.ConsumeIntegral<uint8_t>() % rwmol.bondCount();
        Index a = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        Index b = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        rwmol.setBondPair(bondId, std::make_pair(a, b));
        break;
      }
      case 17: { // hybridization
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        auto hyb = static_cast<AtomHybridization>(
          fdp.ConsumeIntegralInRange<int>(-6, 6));
        rwmol.setHybridization(atomId, hyb);
        break;
      }
      case 18: { // all 3D positions at once (merges when interactive)
        Array<Vector3> positions(rwmol.atomCount());
        for (Index j = 0; j < positions.size(); ++j)
          positions[j] = consumeVector3(fdp);
        rwmol.setAtomPositions3d(positions);
        break;
      }
      case 19: { // all atomic numbers at once
        Array<unsigned char> numbers(rwmol.atomCount());
        for (Index j = 0; j < numbers.size(); ++j)
          numbers[j] = consumeAtomicNumber(fdp);
        rwmol.setAtomicNumbers(numbers);
        break;
      }
      case 20: { // all bond orders at once
        Array<unsigned char> orders(rwmol.bondCount());
        for (Index j = 0; j < orders.size(); ++j)
          orders[j] = static_cast<unsigned char>(
            1 + (fdp.ConsumeIntegral<uint8_t>() % 3));
        rwmol.setBondOrders(orders);
        break;
      }
      case 21: { // all bond pairs at once; often refused (duplicates, a == b)
        if (rwmol.atomCount() == 0)
          break;
        Array<std::pair<Index, Index>> pairs(rwmol.bondCount());
        for (Index j = 0; j < pairs.size(); ++j)
          pairs[j] =
            std::make_pair(fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount(),
                           fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount());
        rwmol.setBondPairs(pairs);
        break;
      }
      case 22: { // 2D position
        if (rwmol.atomCount() == 0)
          break;
        Index atomId = fdp.ConsumeIntegral<uint8_t>() % rwmol.atomCount();
        const Vector3 v = consumeVector3(fdp);
        rwmol.setAtomPosition2d(atomId, Vector2(v.x(), v.y()));
        rwmol.atomPosition2d(atomId);
        break;
      }
      case 23: { // residue color
        if (rwmol.molecule().residueCount() == 0)
          break;
        Index residueId =
          fdp.ConsumeIntegral<uint8_t>() % rwmol.molecule().residueCount();
        Vector3ub color(fdp.ConsumeIntegral<uint8_t>(),
                        fdp.ConsumeIntegral<uint8_t>(),
                        fdp.ConsumeIntegral<uint8_t>());
        rwmol.setResidueColor(residueId, color);
        rwmol.molecule().residue(residueId).color();
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
