/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/core/stereo.h>

#include <avogadro/io/cmlformat.h>
#include <avogadro/io/mdlformat.h>
#include <avogadro/io/smilesformat.h>
#include <avogadro/io/smileswriter.h>

#include <cmath>
#include <map>
#include <set>
#include <string>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::Core::Molecule;
using Avogadro::Io::CmlFormat;
using Avogadro::Io::MdlFormat;
using Avogadro::Io::SmilesFormat;
using Avogadro::Io::SmilesWriter;

namespace {

/** Write in the only mode implemented so far: mapped, explicit hydrogens. */
std::string writeMapped(const Molecule& mol)
{
  SmilesWriter writer;
  writer.setAtomMaps(true);
  std::string smiles;
  EXPECT_TRUE(writer.write(mol, smiles)) << writer.error();
  return smiles;
}

/** Attach @a count hydrogens to @a heavy with single bonds. */
void addHydrogens(Molecule& mol, Index heavy, int count)
{
  for (int i = 0; i < count; ++i)
    mol.addBond(heavy, mol.addAtom(1).index(), 1);
}

/** Parentheses balance, and never close more than were opened. */
bool parenthesesBalanced(const std::string& smiles)
{
  int depth = 0;
  for (char c : smiles) {
    if (c == '(') {
      ++depth;
    } else if (c == ')') {
      if (--depth < 0)
        return false;
    }
  }
  return depth == 0;
}

/** Every ring bond number in the string occurs an even number of times. */
bool ringNumbersPaired(const std::string& smiles)
{
  std::map<int, int> counts;
  for (size_t i = 0; i < smiles.size(); ++i) {
    // Skip bracket contents, where digits are isotopes, charges and maps.
    if (smiles[i] == '[') {
      while (i < smiles.size() && smiles[i] != ']')
        ++i;
      continue;
    }
    if (smiles[i] == '%' && i + 2 < smiles.size()) {
      counts[(smiles[i + 1] - '0') * 10 + (smiles[i + 2] - '0')] += 1;
      i += 2;
    } else if (smiles[i] >= '0' && smiles[i] <= '9') {
      counts[smiles[i] - '0'] += 1;
    }
  }
  for (const auto& entry : counts) {
    if (entry.second % 2 != 0)
      return false;
  }
  return true;
}

/** Each atom map class 1..atomCount appears exactly once. */
bool everyAtomMapped(const std::string& smiles, Index atomCount)
{
  std::set<int> seen;
  for (size_t i = 0; i < smiles.size(); ++i) {
    if (smiles[i] != ':')
      continue;
    int value = 0;
    size_t j = i + 1;
    for (; j < smiles.size() && smiles[j] >= '0' && smiles[j] <= '9'; ++j)
      value = value * 10 + (smiles[j] - '0');
    if (j == i + 1)
      return false; // A colon with no digits after it.
    seen.insert(value);
    i = j - 1;
  }
  if (seen.size() != atomCount)
    return false;
  return *seen.begin() == 1 && *seen.rbegin() == static_cast<int>(atomCount);
}

} // namespace

TEST(SmilesTest, methane)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);

  EXPECT_EQ(writeMapped(mol), "[C:1]([H:2])([H:3])([H:4])[H:5]");
}

TEST(SmilesTest, methaneWithoutMaps)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);

  SmilesWriter writer;
  writer.setHydrogenMode(SmilesWriter::HydrogenMode::Explicit);
  std::string smiles;
  EXPECT_TRUE(writer.write(mol, smiles)) << writer.error();
  EXPECT_EQ(smiles, "[C]([H])([H])([H])[H]");
}

TEST(SmilesTest, water)
{
  Molecule mol;
  Index oxygen = mol.addAtom(8).index();
  addHydrogens(mol, oxygen, 2);

  EXPECT_EQ(writeMapped(mol), "[O:1]([H:2])[H:3]");
}

TEST(SmilesTest, formalCharge)
{
  Molecule mol;
  Index nitrogen = mol.addAtom(7).index();
  mol.setFormalCharge(nitrogen, 1);
  addHydrogens(mol, nitrogen, 4);

  EXPECT_EQ(writeMapped(mol), "[N+:1]([H:2])([H:3])([H:4])[H:5]");
}

TEST(SmilesTest, multipleCharge)
{
  Molecule mol;
  Index magnesium = mol.addAtom(12).index();
  mol.setFormalCharge(magnesium, 2);

  EXPECT_EQ(writeMapped(mol), "[Mg+2:1]");

  Molecule anion;
  Index sulfur = anion.addAtom(16).index();
  anion.setFormalCharge(sulfur, -2);

  EXPECT_EQ(writeMapped(anion), "[S-2:1]");
}

TEST(SmilesTest, isotope)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);
  mol.setIsotope(carbon, 13);
  mol.setIsotope(1, 2);

  EXPECT_EQ(writeMapped(mol), "[13C:1]([2H:2])([H:3])([H:4])[H:5]");
}

TEST(SmilesTest, bondOrders)
{
  Molecule mol;
  Index first = mol.addAtom(6).index();
  Index second = mol.addAtom(6).index();
  mol.addBond(first, second, 2);
  addHydrogens(mol, first, 2);
  addHydrogens(mol, second, 2);

  EXPECT_EQ(writeMapped(mol), "[C:1](=[C:2]([H:5])[H:6])([H:3])[H:4]");

  Molecule triple;
  Index a = triple.addAtom(6).index();
  Index b = triple.addAtom(6).index();
  triple.addBond(a, b, 3);

  EXPECT_EQ(writeMapped(triple), "[C:1]#[C:2]");
}

TEST(SmilesTest, ringClosure)
{
  Molecule mol;
  Index a = mol.addAtom(6).index();
  Index b = mol.addAtom(6).index();
  Index c = mol.addAtom(6).index();
  mol.addBond(a, b, 1);
  mol.addBond(b, c, 1);
  mol.addBond(c, a, 1);

  EXPECT_EQ(writeMapped(mol), "[C:1]1[C:2][C:3]1");
}

TEST(SmilesTest, ringClosureBondOrder)
{
  // The closing bond carries the double bond, so the symbol has to travel to
  // the ring number rather than sitting between two atoms.
  Molecule mol;
  Index a = mol.addAtom(6).index();
  Index b = mol.addAtom(6).index();
  Index c = mol.addAtom(6).index();
  Index d = mol.addAtom(6).index();
  mol.addBond(a, b, 1);
  mol.addBond(b, c, 1);
  mol.addBond(c, d, 1);
  mol.addBond(d, a, 2);

  EXPECT_EQ(writeMapped(mol), "[C:1]=1[C:2][C:3][C:4]1");
}

TEST(SmilesTest, ringNumbersAreReused)
{
  // Two rings that do not overlap in the traversal should both use number 1.
  Molecule mol;
  for (int ring = 0; ring < 2; ++ring) {
    Index base = mol.atomCount();
    mol.addAtom(6);
    mol.addAtom(6);
    mol.addAtom(6);
    mol.addBond(base, base + 1, 1);
    mol.addBond(base + 1, base + 2, 1);
    mol.addBond(base + 2, base, 1);
  }

  EXPECT_EQ(writeMapped(mol), "[C:1]1[C:2][C:3]1.[C:4]1[C:5][C:6]1");
}

TEST(SmilesTest, disconnectedComponents)
{
  Molecule mol;
  mol.addAtom(11);
  mol.addAtom(17);

  EXPECT_EQ(writeMapped(mol), "[Na:1].[Cl:2]");
}

TEST(SmilesTest, atomsWithoutAnElementSymbol)
{
  // Dummy atoms, custom elements and InvalidElement all have to become the
  // wildcard: Elements::symbol() answers "Xx" for them, which is not valid
  // SMILES, and dropping them would leave a gap in the atom mapping.
  Molecule mol;
  mol.addAtom(0);
  mol.addAtom(Avogadro::InvalidElement);
  mol.addAtom(Avogadro::CustomElementMin);

  EXPECT_EQ(writeMapped(mol), "[*:1].[*:2].[*:3]");
}

TEST(SmilesTest, emptyMolecule)
{
  Molecule mol;
  EXPECT_EQ(writeMapped(mol), "");
}

TEST(SmilesTest, atomMapsImplyExplicitHydrogens)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);

  SmilesWriter writer;
  writer.setHydrogenMode(SmilesWriter::HydrogenMode::Bracket);
  writer.setAtomMaps(true);

  EXPECT_EQ(writer.effectiveHydrogenMode(),
            SmilesWriter::HydrogenMode::Explicit);

  std::string smiles;
  EXPECT_TRUE(writer.write(mol, smiles)) << writer.error();
  EXPECT_EQ(smiles, "[C:1]([H:2])([H:3])([H:4])[H:5]");
}

/** Write in the default (implicit hydrogen) mode. */
std::string writeImplicit(const Molecule& mol)
{
  SmilesWriter writer;
  std::string smiles;
  EXPECT_TRUE(writer.write(mol, smiles)) << writer.error();
  return smiles;
}

std::string writeBracket(const Molecule& mol)
{
  SmilesWriter writer;
  writer.setHydrogenMode(SmilesWriter::HydrogenMode::Bracket);
  std::string smiles;
  EXPECT_TRUE(writer.write(mol, smiles)) << writer.error();
  return smiles;
}

/** Build a heavy atom carrying @a count hydrogens. */
Molecule hydride(unsigned char atomicNumber, int count)
{
  Molecule mol;
  addHydrogens(mol, mol.addAtom(atomicNumber).index(), count);
  return mol;
}

TEST(SmilesTest, implicitOrganicSubset)
{
  // One bare atom per organic subset element, at its lowest normal valence.
  EXPECT_EQ(writeImplicit(hydride(6, 4)), "C");   // methane
  EXPECT_EQ(writeImplicit(hydride(7, 3)), "N");   // ammonia
  EXPECT_EQ(writeImplicit(hydride(8, 2)), "O");   // water
  EXPECT_EQ(writeImplicit(hydride(5, 3)), "B");   // borane
  EXPECT_EQ(writeImplicit(hydride(15, 3)), "P");  // phosphine
  EXPECT_EQ(writeImplicit(hydride(16, 2)), "S");  // hydrogen sulfide
  EXPECT_EQ(writeImplicit(hydride(9, 1)), "F");   // hydrogen fluoride
  EXPECT_EQ(writeImplicit(hydride(17, 1)), "Cl"); // hydrogen chloride
}

TEST(SmilesTest, implicitHigherValences)
{
  // Nitrogen's second normal valence: a bond order sum of 4 implies one H.
  Molecule imine;
  Index nitrogen = imine.addAtom(7).index();
  Index first = imine.addAtom(6).index();
  Index second = imine.addAtom(6).index();
  imine.addBond(nitrogen, first, 2);
  imine.addBond(nitrogen, second, 2);
  addHydrogens(imine, nitrogen, 1);
  addHydrogens(imine, first, 2);
  addHydrogens(imine, second, 2);

  EXPECT_EQ(writeImplicit(imine), "N(=C)=C");

  // Dimethyl sulfone: sulfur reaches its third normal valence, so it needs no
  // hydrogens, while the methyl carbons reach their first and take three each.
  Molecule sulfone;
  Index sulfur = sulfone.addAtom(16).index();
  sulfone.addBond(sulfur, sulfone.addAtom(8).index(), 2);
  sulfone.addBond(sulfur, sulfone.addAtom(8).index(), 2);
  for (int i = 0; i < 2; ++i) {
    Index methyl = sulfone.addAtom(6).index();
    sulfone.addBond(sulfur, methyl, 1);
    addHydrogens(sulfone, methyl, 3);
  }

  EXPECT_EQ(writeImplicit(sulfone), "S(=O)(=O)(C)C");
}

TEST(SmilesTest, implicitFallsBackToBrackets)
{
  // A methyl radical has one hydrogen fewer than carbon's valence implies, so
  // writing it bare would silently turn it into methane.
  EXPECT_EQ(writeImplicit(hydride(6, 3)), "[CH3]");

  // Charge, isotope and non-subset elements each force a bracket.
  Molecule ammonium = hydride(7, 4);
  ammonium.setFormalCharge(0, 1);
  EXPECT_EQ(writeImplicit(ammonium), "[NH4+]");

  Molecule heavyWater = hydride(8, 2);
  heavyWater.setIsotope(1, 2);
  heavyWater.setIsotope(2, 2);
  EXPECT_EQ(writeImplicit(heavyWater), "O([2H])[2H]");

  Molecule iron;
  iron.addAtom(26);
  EXPECT_EQ(writeImplicit(iron), "[Fe]");

  // Wildcards are always bracketed: bare '*' has no implied hydrogen rule.
  Molecule dummy;
  dummy.addAtom(0);
  EXPECT_EQ(writeImplicit(dummy), "[*]");
}

TEST(SmilesTest, hydrogensThatCannotBeSuppressed)
{
  // Molecular hydrogen: neither atom has a heavy neighbour to fold into.
  Molecule h2;
  h2.addBond(h2.addAtom(1).index(), h2.addAtom(1).index(), 1);
  EXPECT_EQ(writeImplicit(h2), "[H][H]");

  // A lone hydrogen atom, and a hydride ion.
  Molecule atomic;
  atomic.addAtom(1);
  EXPECT_EQ(writeImplicit(atomic), "[H]");

  Molecule anion;
  anion.addAtom(1);
  anion.setFormalCharge(0, -1);
  EXPECT_EQ(writeImplicit(anion), "[H-]");

  // A bridging hydrogen has two bonds, so it stays an atom of its own while
  // the terminal hydrogens on the same borons are folded away.
  Molecule bridged;
  Index left = bridged.addAtom(5).index();
  Index right = bridged.addAtom(5).index();
  Index bridge = bridged.addAtom(1).index();
  bridged.addBond(left, bridge, 1);
  bridged.addBond(right, bridge, 1);
  addHydrogens(bridged, left, 2);
  addHydrogens(bridged, right, 2);
  EXPECT_EQ(writeImplicit(bridged), "B[H]B");
}

TEST(SmilesTest, bracketMode)
{
  EXPECT_EQ(writeBracket(hydride(6, 4)), "[CH4]");
  EXPECT_EQ(writeBracket(hydride(8, 2)), "[OH2]");

  // Bracket mode still folds hydrogens away; it just never goes bare.
  Molecule ethanol;
  Index c1 = ethanol.addAtom(6).index();
  Index c2 = ethanol.addAtom(6).index();
  Index oxygen = ethanol.addAtom(8).index();
  ethanol.addBond(c1, c2, 1);
  ethanol.addBond(c2, oxygen, 1);
  addHydrogens(ethanol, c1, 3);
  addHydrogens(ethanol, c2, 2);
  addHydrogens(ethanol, oxygen, 1);

  EXPECT_EQ(writeBracket(ethanol), "[CH3][CH2][OH]");
  EXPECT_EQ(writeImplicit(ethanol), "CCO");
}

namespace {

/**
 * A tetrahedral centre with four substituents at alternating cube corners.
 * Listing them in the order @a first .. @a fourth reproduces the neighbour
 * order the writer will use, since the centre is atom zero and the bonds are
 * added in that order.
 *
 * @param mirror Reflect the coordinates, giving the opposite enantiomer with
 * an otherwise identical molecule and an identical neighbour order.
 */
Molecule tetrahedralCenter(unsigned char first, unsigned char second,
                           unsigned char third, unsigned char fourth,
                           bool mirror = false)
{
  Molecule mol;
  Index center = mol.addAtom(6, Vector3(0.0, 0.0, 0.0)).index();
  const Vector3 corners[4] = { Vector3(1.0, 1.0, 1.0), Vector3(1.0, -1.0, -1.0),
                               Vector3(-1.0, 1.0, -1.0),
                               Vector3(-1.0, -1.0, 1.0) };
  const unsigned char elements[4] = { first, second, third, fourth };
  const double flip = mirror ? -1.0 : 1.0;
  for (int i = 0; i < 4; ++i) {
    const Vector3 corner(flip * corners[i].x(), corners[i].y(), corners[i].z());
    mol.addBond(center, mol.addAtom(elements[i], corner).index(), 1);
  }
  return mol;
}

} // namespace

TEST(SmilesTest, tetrahedralChirality)
{
  // F, Cl, Br, I at the four corners in written order.
  EXPECT_EQ(writeImplicit(tetrahedralCenter(9, 17, 35, 53)),
            "[C@](F)(Cl)(Br)I");

  // The mirror image is the same graph written the same way, so only the
  // chirality symbol may differ.
  EXPECT_EQ(writeImplicit(tetrahedralCenter(9, 17, 35, 53, true)),
            "[C@@](F)(Cl)(Br)I");
}

TEST(SmilesTest, chiralityWithASuppressedHydrogen)
{
  // A folded hydrogen still occupies a slot in the neighbour ordering -- here
  // the first, since the centre has no atom it was reached from.
  EXPECT_EQ(writeImplicit(tetrahedralCenter(1, 9, 17, 35)), "[C@H](F)(Cl)Br");
  EXPECT_EQ(writeImplicit(tetrahedralCenter(1, 9, 17, 35, true)),
            "[C@@H](F)(Cl)Br");
}

TEST(SmilesTest, noChiralityWithoutFourDistinctSubstituents)
{
  // Two identical substituents: nothing stereogenic, so no "@" at all.
  EXPECT_EQ(writeImplicit(tetrahedralCenter(9, 9, 17, 35)), "C(F)(F)(Cl)Br");

  // Two hydrogens fold away and are indistinguishable.
  EXPECT_EQ(writeImplicit(tetrahedralCenter(1, 1, 17, 35)), "C(Cl)Br");
}

namespace {

/**
 * A puckered six-membered carbon ring, with the substituent on @a first and
 * @a second placed above or below the mean plane according to @a firstUp and
 * @a secondUp. Every other ring position carries two hydrogens.
 */
Molecule substitutedCyclohexane(unsigned char firstElement, Index first,
                                bool firstUp, unsigned char secondElement,
                                Index second, bool secondUp)
{
  Molecule mol;
  Index ring[6];
  for (Index i = 0; i < 6; ++i) {
    const double angle = 2.0 * M_PI * static_cast<double>(i) / 6.0;
    // Alternating pucker, so the ring is not planar and the substituents have
    // a real side to be on.
    const double z = (i % 2 == 0) ? 0.25 : -0.25;
    ring[i] =
      mol.addAtom(6, Vector3(1.5 * cos(angle), 1.5 * sin(angle), z)).index();
  }
  for (Index i = 0; i < 6; ++i)
    mol.addBond(ring[i], ring[(i + 1) % 6], 1);

  for (Index i = 0; i < 6; ++i) {
    const double angle = 2.0 * M_PI * static_cast<double>(i) / 6.0;
    const bool substituted = (i == first) || (i == second);
    const unsigned char element =
      (i == first) ? firstElement : (i == second ? secondElement : 1);
    const bool up = (i == first) ? firstUp : secondUp;

    if (substituted) {
      mol.addBond(
        ring[i],
        mol
          .addAtom(element,
                   Vector3(2.4 * cos(angle), 2.4 * sin(angle), up ? 1.0 : -1.0))
          .index(),
        1);
      mol.addBond(ring[i],
                  mol
                    .addAtom(1, Vector3(1.7 * cos(angle), 1.7 * sin(angle),
                                        up ? -1.0 : 1.0))
                    .index(),
                  1);
    } else {
      mol.addBond(
        ring[i],
        mol.addAtom(1, Vector3(2.4 * cos(angle), 2.4 * sin(angle), 1.0))
          .index(),
        1);
      mol.addBond(
        ring[i],
        mol.addAtom(1, Vector3(1.7 * cos(angle), 1.7 * sin(angle), -1.0))
          .index(),
        1);
    }
  }
  return mol;
}

bool hasChirality(const std::string& smiles)
{
  return smiles.find('@') != std::string::npos;
}

} // namespace

TEST(SmilesTest, ringDependentStereocenters)
{
  // 4-methylcyclohexanol. Neither centre has four constitutionally different
  // substituents -- the two ways round the ring are equivalent -- but the two
  // together describe cis or trans, so both have to be written.
  const std::string cis =
    writeImplicit(substitutedCyclohexane(8, 0, true, 6, 3, true));
  const std::string trans =
    writeImplicit(substitutedCyclohexane(8, 0, true, 6, 3, false));

  EXPECT_TRUE(hasChirality(cis)) << cis;
  EXPECT_TRUE(hasChirality(trans)) << trans;
  EXPECT_NE(cis, trans);
}

TEST(SmilesTest, noRingStereocenterWithoutAPartner)
{
  // Cyclohexanol has one such centre and no partner, so there is nothing for
  // it to be cis or trans to and it is achiral.
  Molecule mol = substitutedCyclohexane(8, 0, true, 1, 3, true);
  const std::string smiles = writeImplicit(mol);
  EXPECT_FALSE(hasChirality(smiles)) << smiles;

  // Methylcyclohexane, likewise.
  Molecule methyl = substitutedCyclohexane(6, 0, true, 1, 3, true);
  const std::string methylSmiles = writeImplicit(methyl);
  EXPECT_FALSE(hasChirality(methylSmiles)) << methylSmiles;
}

TEST(SmilesTest, noChiralityWithoutCoordinates)
{
  // Built without positions, so there is no handedness to read.
  Molecule mol;
  Index center = mol.addAtom(6).index();
  for (unsigned char element : { 9, 17, 35, 53 })
    mol.addBond(center, mol.addAtom(element).index(), 1);

  EXPECT_EQ(writeImplicit(mol), "C(F)(Cl)(Br)I");
}

namespace {

/**
 * Planar 1,2-difluoroethene. @a trans puts the two fluorines on opposite sides
 * of the double bond; otherwise they sit on the same side.
 */
Molecule difluoroethene(bool trans)
{
  Molecule mol;
  const double side = trans ? -1.0 : 1.0;
  Index c1 = mol.addAtom(6, Vector3(0.0, 0.0, 0.0)).index();
  Index f1 = mol.addAtom(9, Vector3(-0.67, 1.03, 0.0)).index();
  Index h1 = mol.addAtom(1, Vector3(-0.67, -1.03, 0.0)).index();
  Index c2 = mol.addAtom(6, Vector3(1.33, 0.0, 0.0)).index();
  Index f2 = mol.addAtom(9, Vector3(2.0, side * 1.03, 0.0)).index();
  Index h2 = mol.addAtom(1, Vector3(2.0, side * -1.03, 0.0)).index();

  mol.addBond(c1, f1, 1);
  mol.addBond(c1, h1, 1);
  mol.addBond(c1, c2, 2);
  mol.addBond(c2, f2, 1);
  mol.addBond(c2, h2, 1);
  return mol;
}

} // namespace

TEST(SmilesTest, cisTransMarkers)
{
  // The markers sit on the single bonds either side of the double bond, and
  // opposite senses mean the substituents are on opposite sides.
  EXPECT_EQ(writeImplicit(difluoroethene(true)), "C(/F)=C\\F");
  EXPECT_EQ(writeImplicit(difluoroethene(false)), "C(/F)=C/F");
}

TEST(SmilesTest, noCisTransWithoutTwoDistinctEnds)
{
  // 1,1-difluoroethene: one end carries two fluorines, so there is no
  // cis/trans relationship to describe.
  Molecule mol;
  Index c1 = mol.addAtom(6, Vector3(0.0, 0.0, 0.0)).index();
  Index c2 = mol.addAtom(6, Vector3(1.33, 0.0, 0.0)).index();
  mol.addBond(c1, c2, 2);
  mol.addBond(c1, mol.addAtom(9, Vector3(-0.67, 1.03, 0.0)).index(), 1);
  mol.addBond(c1, mol.addAtom(9, Vector3(-0.67, -1.03, 0.0)).index(), 1);
  mol.addBond(c2, mol.addAtom(1, Vector3(2.0, 1.03, 0.0)).index(), 1);
  mol.addBond(c2, mol.addAtom(1, Vector3(2.0, -1.03, 0.0)).index(), 1);

  const std::string smiles = writeImplicit(mol);
  EXPECT_EQ(smiles.find('/'), std::string::npos) << smiles;
  EXPECT_EQ(smiles.find('\\'), std::string::npos) << smiles;
}

TEST(SmilesTest, noCisTransWithoutCoordinates)
{
  Molecule mol;
  Index c1 = mol.addAtom(6).index();
  Index c2 = mol.addAtom(6).index();
  mol.addBond(c1, mol.addAtom(9).index(), 1);
  mol.addBond(c1, mol.addAtom(1).index(), 1);
  mol.addBond(c1, c2, 2);
  mol.addBond(c2, mol.addAtom(9).index(), 1);
  mol.addBond(c2, mol.addAtom(1).index(), 1);

  EXPECT_EQ(writeImplicit(mol), "C(F)=CF");
}

namespace {

/** trans-2-butene in two dimensions, with the given MDL bond stereo flag. */
std::string buteneMol(const char* doubleBondStereo)
{
  return std::string("2-butene\n"
                     "  Avogadro\n"
                     "\n"
                     "  4  3  0  0  0  0  0  0  0  0999 V2000\n"
                     "    0.5000    0.8700    0.0000 C   0  0  0  0  0  0  0  "
                     "0  0  0  0  0\n"
                     "    1.0000    0.0000    0.0000 C   0  0  0  0  0  0  0  "
                     "0  0  0  0  0\n"
                     "    2.0000    0.0000    0.0000 C   0  0  0  0  0  0  0  "
                     "0  0  0  0  0\n"
                     "    2.5000   -0.8700    0.0000 C   0  0  0  0  0  0  0  "
                     "0  0  0  0  0\n"
                     "  1  2  1  0\n"
                     "  2  3  2  ") +
         doubleBondStereo + "\n  3  4  1  0\nM  END\n";
}

bool hasDirectionalBond(const std::string& smiles)
{
  return smiles.find('/') != std::string::npos ||
         smiles.find('\\') != std::string::npos;
}

} // namespace

TEST(SmilesTest, unspecifiedDoubleBondStereoIsNotInvented)
{
  // With the stereo column clear, the coordinates are the author's statement
  // about configuration and get written out.
  MdlFormat mdl;
  Molecule defined;
  ASSERT_TRUE(mdl.readString(buteneMol("0"), defined)) << mdl.error();
  EXPECT_FALSE(Avogadro::Core::bondStereoUnspecified(defined, 1));

  const std::string definedSmiles = writeImplicit(defined);
  EXPECT_TRUE(hasDirectionalBond(definedSmiles)) << definedSmiles;

  // Flag 3 is "cis or trans, either": the atoms still have coordinates, but
  // the author declined to claim a configuration, so none may be written.
  MdlFormat eitherMdl;
  Molecule either;
  ASSERT_TRUE(eitherMdl.readString(buteneMol("3"), either))
    << eitherMdl.error();
  EXPECT_TRUE(Avogadro::Core::bondStereoUnspecified(either, 1));

  const std::string eitherSmiles = writeImplicit(either);
  EXPECT_FALSE(hasDirectionalBond(eitherSmiles)) << eitherSmiles;
}

TEST(SmilesTest, unspecifiedMarkersFollowTheirBonds)
{
  // The markers live in the property map, so they have to survive editing.
  MdlFormat mdl;
  Molecule mol;
  ASSERT_TRUE(mdl.readString(buteneMol("3"), mol)) << mdl.error();
  ASSERT_TRUE(Avogadro::Core::bondStereoUnspecified(mol, 1));

  // Removing a bond renumbers the rest -- Graph and PropertyMap both swap the
  // last entry into the freed slot -- so the marker has to move with its bond
  // rather than stay at index 1.
  mol.removeBond(static_cast<Index>(0));

  bool markedDoubleBond = false;
  for (Index bond = 0; bond < mol.bondCount(); ++bond) {
    if (mol.bondOrders()[bond] == 2)
      markedDoubleBond = Avogadro::Core::bondStereoUnspecified(mol, bond);
  }
  EXPECT_TRUE(markedDoubleBond);
}

namespace {

/** A ring of @a elements, alternating double and single bonds, plus one
 *  hydrogen on every atom that is given one in @a hydrogens. */
Molecule aromaticRing(const std::vector<unsigned char>& elements,
                      const std::vector<bool>& hydrogens,
                      const std::vector<unsigned char>& orders)
{
  Molecule mol;
  for (unsigned char element : elements)
    mol.addAtom(element);
  for (Index i = 0; i < elements.size(); ++i)
    mol.addBond(i, (i + 1) % elements.size(), orders[i]);
  for (Index i = 0; i < elements.size(); ++i) {
    if (hydrogens[i])
      mol.addBond(i, mol.addAtom(1).index(), 1);
  }
  return mol;
}

} // namespace

TEST(SmilesTest, aromaticOutput)
{
  // Benzene, in the form everyone writes it.
  Molecule benzene =
    aromaticRing({ 6, 6, 6, 6, 6, 6 }, { true, true, true, true, true, true },
                 { 2, 1, 2, 1, 2, 1 });
  EXPECT_EQ(writeImplicit(benzene), "c1ccccc1");

  // Pyridine: the nitrogen needs no hydrogen and stays bare.
  Molecule pyridine =
    aromaticRing({ 7, 6, 6, 6, 6, 6 }, { false, true, true, true, true, true },
                 { 2, 1, 2, 1, 2, 1 });
  EXPECT_EQ(writeImplicit(pyridine), "n1ccccc1");
}

TEST(SmilesTest, aromaticHeteroatomsSpellOutTheirHydrogens)
{
  // Pyrrole. A reader cannot kekulize the ring without knowing whether the
  // nitrogen carries a hydrogen, so it has to be written explicitly.
  Molecule pyrrole = aromaticRing(
    { 7, 6, 6, 6, 6 }, { true, true, true, true, true }, { 1, 2, 1, 2, 1 });
  EXPECT_EQ(writeImplicit(pyrrole), "[nH]1cccc1");

  // Furan's oxygen has none, so it needs no bracket.
  Molecule furan = aromaticRing(
    { 8, 6, 6, 6, 6 }, { false, true, true, true, true }, { 1, 2, 1, 2, 1 });
  EXPECT_EQ(writeImplicit(furan), "o1cccc1");
}

TEST(SmilesTest, kekuleOutputOnRequest)
{
  Molecule benzene =
    aromaticRing({ 6, 6, 6, 6, 6, 6 }, { true, true, true, true, true, true },
                 { 2, 1, 2, 1, 2, 1 });

  SmilesWriter writer;
  writer.setAromatic(false);
  std::string smiles;
  EXPECT_TRUE(writer.write(benzene, smiles)) << writer.error();
  EXPECT_EQ(smiles, "C1=CC=CC=C1");
}

TEST(SmilesTest, nonAromaticRingsKeepTheirBondOrders)
{
  // Cyclohexane has no aromaticity to find, so nothing changes.
  Molecule mol = aromaticRing({ 6, 6, 6, 6, 6, 6 },
                              { false, false, false, false, false, false },
                              { 1, 1, 1, 1, 1, 1 });
  for (Index i = 0; i < 6; ++i) {
    mol.addBond(i, mol.addAtom(1).index(), 1);
    mol.addBond(i, mol.addAtom(1).index(), 1);
  }
  EXPECT_EQ(writeImplicit(mol), "C1CCCCC1");
}

TEST(SmilesTest, formatIsWriteOnly)
{
  SmilesFormat format;
  EXPECT_EQ(format.supportedOperations() & Avogadro::Io::FileFormat::Read, 0);
  EXPECT_NE(format.supportedOperations() & Avogadro::Io::FileFormat::Write, 0);
}

TEST(SmilesTest, formatOptions)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);

  SmilesFormat format;
  format.setOptions("{\"atomMaps\": true}");
  std::string smiles;
  EXPECT_TRUE(format.writeString(smiles, mol)) << format.error();
  EXPECT_EQ(smiles, "[C:1]([H:2])([H:3])([H:4])[H:5]\n");

  SmilesFormat defaults;
  std::string implicit;
  EXPECT_TRUE(defaults.writeString(implicit, mol)) << defaults.error();
  EXPECT_EQ(implicit, "C\n");
}

TEST(SmilesTest, structuralInvariantsOnRealMolecule)
{
  // Caffeine rather than something acyclic: its fused rings are what give the
  // ring closure invariant anything to check.
  CmlFormat cml;
  Molecule mol;
  ASSERT_TRUE(
    cml.readFile(std::string(AVOGADRO_DATA) + "/data/cml/caffeine.cml", mol));
  ASSERT_GT(mol.bondCount(), mol.atomCount() - 1); // i.e. it has rings

  const std::string smiles = writeMapped(mol);
  EXPECT_TRUE(parenthesesBalanced(smiles)) << smiles;
  EXPECT_TRUE(ringNumbersPaired(smiles)) << smiles;
  EXPECT_TRUE(everyAtomMapped(smiles, mol.atomCount())) << smiles;
}
