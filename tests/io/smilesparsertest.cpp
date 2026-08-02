/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>

#include <avogadro/io/smilesparser.h>
#include <avogadro/io/smileswriter.h>

#include <string>
#include <utility>
#include <vector>

using Avogadro::Index;
using Avogadro::Core::Molecule;
using Avogadro::Io::SmilesParser;
using Avogadro::Io::SmilesWriter;

namespace {

/** Attach @a count hydrogens to @a heavy with single bonds. */
void addHydrogens(Molecule& mol, Index heavy, int count)
{
  for (int i = 0; i < count; ++i)
    mol.addBond(heavy, mol.addAtom(1).index(), 1);
}

/** Parse @a smiles, asserting success, and return the resulting molecule. */
Molecule parseOk(const std::string& smiles)
{
  SmilesParser parser;
  Molecule mol;
  EXPECT_TRUE(parser.parse(smiles, mol))
    << smiles << ": " << parser.error() << " at " << parser.errorPosition();
  return mol;
}

/** Parse @a smiles, asserting it fails at @a expectedPosition. */
void expectError(const std::string& smiles, size_t expectedPosition)
{
  SmilesParser parser;
  Molecule mol;
  EXPECT_FALSE(parser.parse(smiles, mol)) << smiles;
  EXPECT_FALSE(parser.error().empty()) << smiles;
  EXPECT_EQ(parser.errorPosition(), expectedPosition)
    << smiles << ": " << parser.error();
  EXPECT_EQ(mol.atomCount(), 0u) << smiles;
}

int countElement(const Molecule& mol, unsigned char atomicNumber)
{
  int count = 0;
  for (Index i = 0; i < mol.atomCount(); ++i) {
    if (mol.atomicNumber(i) == atomicNumber)
      ++count;
  }
  return count;
}

int countBondOrder(const Molecule& mol, unsigned char order)
{
  int count = 0;
  for (Index i = 0; i < mol.bondCount(); ++i) {
    if (mol.bondOrders()[i] == order)
      ++count;
  }
  return count;
}

} // namespace

// ---------------------------------------------------------------------------
// Bare atoms and implied hydrogen counts.

TEST(SmilesParserTest, bareCarbon)
{
  Molecule mol = parseOk("C");
  EXPECT_EQ(mol.atomCount(), 5u);
  EXPECT_EQ(mol.bondCount(), 4u);
  EXPECT_EQ(countElement(mol, 6), 1);
  EXPECT_EQ(countElement(mol, 1), 4);
}

TEST(SmilesParserTest, bareEthane)
{
  Molecule mol = parseOk("CC");
  EXPECT_EQ(mol.atomCount(), 8u);
  EXPECT_EQ(mol.bondCount(), 7u);
  EXPECT_EQ(countElement(mol, 6), 2);
  EXPECT_EQ(countElement(mol, 1), 6);
}

TEST(SmilesParserTest, bareEthylene)
{
  Molecule mol = parseOk("C=C");
  EXPECT_EQ(mol.atomCount(), 6u);
  EXPECT_EQ(mol.bondCount(), 5u);
  EXPECT_EQ(countBondOrder(mol, 2), 1);
  EXPECT_EQ(countBondOrder(mol, 1), 4);
}

TEST(SmilesParserTest, bareHydrogenCyanide)
{
  Molecule mol = parseOk("C#N");
  EXPECT_EQ(mol.atomCount(), 3u);
  EXPECT_EQ(mol.bondCount(), 2u);
  EXPECT_EQ(countElement(mol, 6), 1);
  EXPECT_EQ(countElement(mol, 7), 1);
  EXPECT_EQ(countElement(mol, 1), 1);
  EXPECT_EQ(countBondOrder(mol, 3), 1);
  EXPECT_EQ(countBondOrder(mol, 1), 1);
}

TEST(SmilesParserTest, bareWater)
{
  Molecule mol = parseOk("O");
  EXPECT_EQ(mol.atomCount(), 3u);
  EXPECT_EQ(mol.bondCount(), 2u);
  EXPECT_EQ(countElement(mol, 8), 1);
  EXPECT_EQ(countElement(mol, 1), 2);
}

TEST(SmilesParserTest, bareAmmonia)
{
  Molecule mol = parseOk("N");
  EXPECT_EQ(mol.atomCount(), 4u);
  EXPECT_EQ(mol.bondCount(), 3u);
}

TEST(SmilesParserTest, bareHydrogenSulfide)
{
  Molecule mol = parseOk("S");
  EXPECT_EQ(mol.atomCount(), 3u);
  EXPECT_EQ(mol.bondCount(), 2u);
}

TEST(SmilesParserTest, bareHydrogenChloride)
{
  Molecule mol = parseOk("Cl");
  EXPECT_EQ(mol.atomCount(), 2u);
  EXPECT_EQ(mol.bondCount(), 1u);
  EXPECT_EQ(countElement(mol, 17), 1);
  EXPECT_EQ(countElement(mol, 1), 1);
}

TEST(SmilesParserTest, bracketHydrogenMolecule)
{
  Molecule mol = parseOk("[H][H]");
  EXPECT_EQ(mol.atomCount(), 2u);
  EXPECT_EQ(mol.bondCount(), 1u);
  EXPECT_EQ(countElement(mol, 1), 2);
  EXPECT_EQ(countBondOrder(mol, 1), 1);
}

// ---------------------------------------------------------------------------
// The valence model's multi-valence cases.

TEST(SmilesParserTest, nitrogenValences)
{
  Molecule ammonia = parseOk("N");
  EXPECT_EQ(ammonia.atomCount(), 4u); // NH3

  Molecule dioxide = parseOk("N(=O)=O");
  EXPECT_EQ(dioxide.atomCount(), 4u); // one N, two O, one H
  EXPECT_EQ(dioxide.bondCount(), 3u);
  EXPECT_EQ(countElement(dioxide, 7), 1);
  EXPECT_EQ(countElement(dioxide, 8), 2);
  EXPECT_EQ(countElement(dioxide, 1), 1);
  EXPECT_EQ(countBondOrder(dioxide, 2), 2);
  EXPECT_EQ(countBondOrder(dioxide, 1), 1);
}

TEST(SmilesParserTest, sulfurValences)
{
  Molecule sulfide = parseOk("S");
  EXPECT_EQ(sulfide.atomCount(), 3u); // H2S

  Molecule dioxide = parseOk("S(=O)(=O)");
  EXPECT_EQ(dioxide.atomCount(), 3u); // S reaches valence 4, no H
  EXPECT_EQ(dioxide.bondCount(), 2u);
  EXPECT_EQ(countBondOrder(dioxide, 2), 2);
  EXPECT_EQ(countBondOrder(dioxide, 1), 0);
}

TEST(SmilesParserTest, phosphorusValence)
{
  Molecule phosphine = parseOk("P");
  EXPECT_EQ(phosphine.atomCount(), 4u); // PH3
  EXPECT_EQ(phosphine.bondCount(), 3u);
}

// ---------------------------------------------------------------------------
// Bracket atoms.

TEST(SmilesParserTest, bracketMethane)
{
  Molecule mol = parseOk("[CH4]");
  EXPECT_EQ(mol.atomCount(), 5u);
  EXPECT_EQ(countElement(mol, 6), 1);
  EXPECT_EQ(countElement(mol, 1), 4);
}

TEST(SmilesParserTest, bracketAmmonium)
{
  Molecule mol = parseOk("[NH4+]");
  EXPECT_EQ(mol.atomCount(), 5u);
  EXPECT_EQ(mol.formalCharge(0), 1);
}

TEST(SmilesParserTest, bracketIronDigitCharge)
{
  Molecule mol = parseOk("[Fe+2]");
  EXPECT_EQ(mol.atomCount(), 1u);
  EXPECT_EQ(mol.atomicNumber(0), 26);
  EXPECT_EQ(mol.formalCharge(0), 2);
}

TEST(SmilesParserTest, bracketIronRepeatedSignCharge)
{
  Molecule mol = parseOk("[Fe++]");
  EXPECT_EQ(mol.atomCount(), 1u);
  EXPECT_EQ(mol.atomicNumber(0), 26);
  EXPECT_EQ(mol.formalCharge(0), 2);
}

TEST(SmilesParserTest, bracketOxideAnion)
{
  Molecule mol = parseOk("[O-]");
  EXPECT_EQ(mol.atomCount(), 1u);
  EXPECT_EQ(mol.formalCharge(0), -1);
}

TEST(SmilesParserTest, bracketIsotope)
{
  Molecule mol = parseOk("[13CH4]");
  EXPECT_EQ(mol.atomCount(), 5u);
  EXPECT_EQ(mol.atomicNumber(0), 6);
  EXPECT_EQ(mol.isotope(0), 13);
  EXPECT_EQ(countElement(mol, 1), 4);
}

TEST(SmilesParserTest, bracketChiralityDiscarded)
{
  SmilesParser parser;
  Molecule mol;
  ASSERT_TRUE(parser.parse("[C@H](N)(O)C", mol)) << parser.error();
  EXPECT_EQ(mol.atomCount(), 11u);
  EXPECT_EQ(mol.bondCount(), 10u);
  ASSERT_EQ(parser.warnings().size(), 1u);
}

TEST(SmilesParserTest, bracketWildcard)
{
  Molecule mol = parseOk("[*]");
  EXPECT_EQ(mol.atomCount(), 1u);
  EXPECT_EQ(mol.atomicNumber(0), 0);
  EXPECT_EQ(mol.bondCount(), 0u);
}

TEST(SmilesParserTest, atomMapClasses)
{
  SmilesParser single;
  Molecule mol;
  ASSERT_TRUE(single.parse("[C:5]", mol)) << single.error();
  EXPECT_EQ(mol.atomCount(), 1u);
  ASSERT_EQ(single.atomMaps().size(), 1u);
  EXPECT_EQ(single.atomMaps()[0], 5u);

  SmilesParser withHydrogens;
  Molecule methyl;
  ASSERT_TRUE(withHydrogens.parse("[CH3:12]", methyl)) << withHydrogens.error();
  EXPECT_EQ(methyl.atomCount(), 4u);
  ASSERT_EQ(withHydrogens.atomMaps().size(), 4u);
  EXPECT_EQ(withHydrogens.atomMaps()[0], 12u);
  EXPECT_EQ(withHydrogens.atomMaps()[1], 0u);
  EXPECT_EQ(withHydrogens.atomMaps()[2], 0u);
  EXPECT_EQ(withHydrogens.atomMaps()[3], 0u);
}

// ---------------------------------------------------------------------------
// Branches, including nested and consecutive.

TEST(SmilesParserTest, consecutiveBranches)
{
  // Isobutane.
  Molecule mol = parseOk("CC(C)C");
  EXPECT_EQ(mol.atomCount(), 14u);
  EXPECT_EQ(mol.bondCount(), 13u);
  EXPECT_EQ(countElement(mol, 6), 4);
  EXPECT_EQ(countElement(mol, 1), 10);
}

TEST(SmilesParserTest, doubleBranch)
{
  // Neopentane.
  Molecule mol = parseOk("CC(C)(C)C");
  EXPECT_EQ(mol.atomCount(), 17u);
  EXPECT_EQ(mol.bondCount(), 16u);
  EXPECT_EQ(countElement(mol, 6), 5);
  EXPECT_EQ(countElement(mol, 1), 12);
}

TEST(SmilesParserTest, nestedBranch)
{
  // n-Butane, written with a branch nested inside another.
  Molecule mol = parseOk("C(C(C))C");
  EXPECT_EQ(mol.atomCount(), 14u);
  EXPECT_EQ(mol.bondCount(), 13u);
  EXPECT_EQ(countElement(mol, 6), 4);
  EXPECT_EQ(countElement(mol, 1), 10);
}

// ---------------------------------------------------------------------------
// Ring closures.

TEST(SmilesParserTest, ringClosureDigit)
{
  // Cyclohexane.
  Molecule mol = parseOk("C1CCCCC1");
  EXPECT_EQ(mol.atomCount(), 18u);
  EXPECT_EQ(mol.bondCount(), 18u);
  EXPECT_EQ(countElement(mol, 6), 6);
  EXPECT_EQ(countElement(mol, 1), 12);
}

TEST(SmilesParserTest, ringClosurePercent)
{
  // The same cyclohexane, with a two digit ring number.
  Molecule mol = parseOk("C%10CCCCC%10");
  EXPECT_EQ(mol.atomCount(), 18u);
  EXPECT_EQ(mol.bondCount(), 18u);
}

TEST(SmilesParserTest, ringNumberReusedAfterClosing)
{
  // Bicyclopropyl: two cyclopropane rings, joined by a single bond, both
  // written with ring number 1.
  Molecule mol = parseOk("C1CC1C1CC1");
  EXPECT_EQ(mol.atomCount(), 16u);
  EXPECT_EQ(mol.bondCount(), 17u);
  EXPECT_EQ(countElement(mol, 6), 6);
  EXPECT_EQ(countElement(mol, 1), 10);
}

TEST(SmilesParserTest, ringClosureBondOrderOnOneEnd)
{
  // Cyclohexene.
  Molecule mol = parseOk("C=1CCCCC1");
  EXPECT_EQ(mol.atomCount(), 16u);
  EXPECT_EQ(mol.bondCount(), 16u);
  EXPECT_EQ(countBondOrder(mol, 2), 1);
}

TEST(SmilesParserTest, ringClosureBondOrderOnBothEnds)
{
  // The two ends agree, so this is the same cyclohexene as above.
  Molecule mol = parseOk("C=1CCCCC=1");
  EXPECT_EQ(mol.atomCount(), 16u);
  EXPECT_EQ(mol.bondCount(), 16u);
  EXPECT_EQ(countBondOrder(mol, 2), 1);
}

// ---------------------------------------------------------------------------
// Dot disconnection.

TEST(SmilesParserTest, dotDisconnection)
{
  Molecule mol = parseOk("[Na+].[Cl-]");
  EXPECT_EQ(mol.atomCount(), 2u);
  EXPECT_EQ(mol.bondCount(), 0u);
  EXPECT_EQ(mol.atomicNumber(0), 11);
  EXPECT_EQ(mol.formalCharge(0), 1);
  EXPECT_EQ(mol.atomicNumber(1), 17);
  EXPECT_EQ(mol.formalCharge(1), -1);
}

TEST(SmilesParserTest, dotInsideABranch)
{
  // The branch's tail ("N") is disconnected from what came before the dot,
  // but the branch still closes back onto the atom that opened it.
  Molecule mol = parseOk("C(CC.N)C");
  EXPECT_EQ(mol.atomCount(), 18u);
  EXPECT_EQ(mol.bondCount(), 16u);
  EXPECT_EQ(countElement(mol, 6), 4);
  EXPECT_EQ(countElement(mol, 7), 1);
}

// ---------------------------------------------------------------------------
// Title handling.

TEST(SmilesParserTest, title)
{
  SmilesParser parser;
  Molecule mol;
  ASSERT_TRUE(parser.parse("CC ethane", mol)) << parser.error();
  EXPECT_EQ(mol.atomCount(), 8u); // The title does not affect the graph.
  ASSERT_TRUE(mol.hasData("name"));
  EXPECT_EQ(mol.data("name").toString(), "ethane");
}

TEST(SmilesParserTest, noTitleMeansNoNameData)
{
  Molecule mol = parseOk("CC");
  EXPECT_FALSE(mol.hasData("name"));
}

// ---------------------------------------------------------------------------
// Empty input.

TEST(SmilesParserTest, emptyString)
{
  SmilesParser parser;
  Molecule mol;
  EXPECT_TRUE(parser.parse("", mol)) << parser.error();
  EXPECT_EQ(mol.atomCount(), 0u);
}

// ---------------------------------------------------------------------------
// Errors. Each of these picks an offset deliberately, so a bug that reports
// the wrong position -- as opposed to merely failing -- is still caught.

TEST(SmilesParserTest, errorUnexpectedCharacter)
{
  expectError("CX", 1);
}

TEST(SmilesParserTest, errorUnterminatedBracket)
{
  expectError("[C", 0);
}

TEST(SmilesParserTest, errorEmptyBracket)
{
  expectError("[]", 0);
}

TEST(SmilesParserTest, errorUnknownElementInBracket)
{
  expectError("[Zz]", 1);
}

TEST(SmilesParserTest, errorBondNotFollowedByAtom)
{
  expectError("C-", 1);
}

TEST(SmilesParserTest, errorUnmatchedCloseParen)
{
  expectError(")C", 0);
}

TEST(SmilesParserTest, errorUnclosedOpenParen)
{
  expectError("C(C", 1);
}

TEST(SmilesParserTest, errorBranchWithNoPrecedingAtom)
{
  expectError("(C)", 0);
}

TEST(SmilesParserTest, errorBondWithNoPrecedingAtom)
{
  expectError("-C", 0);
}

TEST(SmilesParserTest, errorPercentNotTwoDigits)
{
  expectError("C%1", 1);
}

TEST(SmilesParserTest, errorRingClosureConflictingBondOrder)
{
  expectError("C=1CCCCC#1", 8);
}

TEST(SmilesParserTest, errorRingClosureToItself)
{
  expectError("C11", 2);
}

TEST(SmilesParserTest, errorRingClosureDuplicatesExistingBond)
{
  // Ring 2 closes the atom0-atom2 bond; ring 1 then tries to close the same
  // pair again.
  expectError("C12CC21", 6);
}

TEST(SmilesParserTest, errorRingClosureStillOpenAtEndOfInput)
{
  expectError("C1CC", 1);
}

TEST(SmilesParserTest, errorIsotopeOverflow)
{
  expectError("[999999C]", 1);
}

TEST(SmilesParserTest, errorChargeOverflow)
{
  expectError("[Fe+999]", 3);
}

TEST(SmilesParserTest, errorAtomClassOverflow)
{
  expectError("[C:9999999999]", 2);
}

// ---------------------------------------------------------------------------
// Aromatic input: kekulized rather than rejected.

TEST(SmilesParserTest, aromaticBenzene)
{
  Molecule mol = parseOk("c1ccccc1");
  EXPECT_EQ(mol.atomCount(), 12u);
  EXPECT_EQ(countElement(mol, 6), 6);
  EXPECT_EQ(countElement(mol, 1), 6);
  EXPECT_EQ(countBondOrder(mol, 2), 3);
  EXPECT_EQ(countBondOrder(mol, 1), 9);
}

TEST(SmilesParserTest, aromaticPyridine)
{
  Molecule mol = parseOk("c1ccncc1");
  EXPECT_EQ(mol.atomCount(), 11u);
  EXPECT_EQ(countElement(mol, 6), 5);
  EXPECT_EQ(countElement(mol, 7), 1);
  EXPECT_EQ(countElement(mol, 1), 5);
  EXPECT_EQ(countBondOrder(mol, 2), 3);
  EXPECT_EQ(countBondOrder(mol, 1), 8);
}

TEST(SmilesParserTest, aromaticPyrroleBracketNitrogen)
{
  // The [nH] states its hydrogen explicitly, which is what lets kekulize()
  // classify the nitrogen correctly (it must not take a ring double bond).
  Molecule mol = parseOk("[nH]1cccc1");
  EXPECT_EQ(mol.atomCount(), 10u);
  EXPECT_EQ(countElement(mol, 6), 4);
  EXPECT_EQ(countElement(mol, 7), 1);
  EXPECT_EQ(countElement(mol, 1), 5); // Four ring CH, plus the N-H.
  EXPECT_EQ(countBondOrder(mol, 2), 2);
  EXPECT_EQ(countBondOrder(mol, 1), 8);
}

TEST(SmilesParserTest, aromaticFuran)
{
  Molecule mol = parseOk("c1ccoc1");
  EXPECT_EQ(mol.atomCount(), 9u);
  EXPECT_EQ(countElement(mol, 6), 4);
  EXPECT_EQ(countElement(mol, 8), 1);
  EXPECT_EQ(countElement(mol, 1), 4);
  EXPECT_EQ(countBondOrder(mol, 2), 2);
  EXPECT_EQ(countBondOrder(mol, 1), 7);
}

TEST(SmilesParserTest, aromaticThiophene)
{
  Molecule mol = parseOk("c1ccsc1");
  EXPECT_EQ(mol.atomCount(), 9u);
  EXPECT_EQ(countElement(mol, 6), 4);
  EXPECT_EQ(countElement(mol, 16), 1);
  EXPECT_EQ(countElement(mol, 1), 4);
  EXPECT_EQ(countBondOrder(mol, 2), 2);
  EXPECT_EQ(countBondOrder(mol, 1), 7);
}

TEST(SmilesParserTest, aromaticImidazole)
{
  Molecule mol = parseOk("c1c[nH]cn1");
  EXPECT_EQ(mol.atomCount(), 9u);
  EXPECT_EQ(countElement(mol, 6), 3);
  EXPECT_EQ(countElement(mol, 7), 2);
  EXPECT_EQ(countElement(mol, 1), 4); // Three ring CH, plus the N-H.
  EXPECT_EQ(countBondOrder(mol, 2), 2);
  EXPECT_EQ(countBondOrder(mol, 1), 7);
}

TEST(SmilesParserTest, aromaticNaphthaleneFusedRings)
{
  Molecule mol = parseOk("c1ccc2ccccc2c1");
  EXPECT_EQ(mol.atomCount(), 18u);
  EXPECT_EQ(countElement(mol, 6), 10);
  EXPECT_EQ(countElement(mol, 1), 8); // The two bridgeheads carry no H.
  EXPECT_EQ(countBondOrder(mol, 2), 5);
  EXPECT_EQ(countBondOrder(mol, 1), 14);
}

TEST(SmilesParserTest, aromaticBiphenylConnectingBondIsNotAromatic)
{
  // The explicit '-' is load bearing: between two lower case atoms, writing
  // no bond symbol at all would mean an aromatic bond instead, joining the
  // two rings into a single (unkekulizable) twelve-membered system.
  Molecule mol = parseOk("c1ccc(cc1)-c1ccccc1");
  EXPECT_EQ(mol.atomCount(), 22u);
  EXPECT_EQ(countElement(mol, 6), 12);
  EXPECT_EQ(countElement(mol, 1), 10);
  EXPECT_EQ(countBondOrder(mol, 2), 6);
  // Eleven ring single bonds (five per ring, plus the connecting bond) and
  // ten C-H bonds.
  EXPECT_EQ(countBondOrder(mol, 1), 17);
}

TEST(SmilesParserTest, aromaticCaffeine)
{
  // 1,3,7-trimethylxanthine: a fused imidazole and pyrimidinedione, with two
  // exocyclic C=O bonds written explicitly inside the aromatic ring.
  Molecule mol = parseOk("Cn1cnc2c1c(=O)n(C)c(=O)n2C");
  EXPECT_EQ(mol.atomCount(), 24u);
  EXPECT_EQ(countElement(mol, 6), 8);
  EXPECT_EQ(countElement(mol, 7), 4);
  EXPECT_EQ(countElement(mol, 8), 2);
  EXPECT_EQ(countElement(mol, 1), 10);
}

TEST(SmilesParserTest, errorUnkekulizableAromaticRing)
{
  // Three aromatic carbons: a triangle has no perfect matching, so no
  // arrangement of alternating bonds can satisfy every atom.
  expectError("c1cc1", 0);
}

// ---------------------------------------------------------------------------
// Aromatic round trip: parse, write back out with the writer's default
// (setAromatic(true)), and reparse.
//
// Individual bonds cannot be compared. A ring with more than one valid Kekule
// structure -- benzene, for instance -- can legitimately come back with a
// different one, because perceiving it as aromatic in order to write it
// discards which alternation the original happened to hold.
//
// Two things do survive that, and are worth far more than an atom count. The
// number of double bonds is fixed by kekulize()'s classification rather than
// by the search, so the bond order multiset is invariant. So is each atom's
// total bond order, which is its valence -- and atom maps correlate the two
// molecules exactly, since asking for maps does not turn aromatic output off.

namespace {

/** Total bond order at each atom, which is the atom's valence. */
std::vector<unsigned int> valences(const Molecule& mol)
{
  std::vector<unsigned int> sums(mol.atomCount(), 0);
  for (Index b = 0; b < mol.bondCount(); ++b) {
    const unsigned char order = mol.bondOrders()[b];
    sums[mol.bondPairs()[b].first] += order;
    sums[mol.bondPairs()[b].second] += order;
  }
  return sums;
}

void expectAromaticRoundTrip(const std::string& smiles)
{
  Molecule original = parseOk(smiles);

  SmilesWriter writer; // setAromatic(true) is the default.
  writer.setAtomMaps(true);
  std::string written;
  ASSERT_TRUE(writer.write(original, written))
    << smiles << ": " << writer.error();

  SmilesParser reparser;
  Molecule reparsed;
  ASSERT_TRUE(reparser.parse(written, reparsed))
    << smiles << " -> " << written << ": " << reparser.error();

  ASSERT_EQ(reparsed.atomCount(), original.atomCount()) << smiles;
  EXPECT_EQ(reparsed.bondCount(), original.bondCount()) << smiles;
  for (unsigned char element : { 1, 6, 7, 8, 16 }) {
    EXPECT_EQ(countElement(reparsed, element), countElement(original, element))
      << smiles << ", element " << int(element);
  }
  for (unsigned char order : { 1, 2, 3 }) {
    EXPECT_EQ(countBondOrder(reparsed, order), countBondOrder(original, order))
      << smiles << ", bond order " << int(order);
  }

  const std::vector<unsigned int> before = valences(original);
  const std::vector<unsigned int> after = valences(reparsed);
  const std::vector<size_t>& maps = reparser.atomMaps();
  ASSERT_EQ(maps.size(), reparsed.atomCount()) << smiles;
  for (Index i = 0; i < reparsed.atomCount(); ++i) {
    ASSERT_GT(maps[i], 0u) << smiles;
    const Index originalIndex = static_cast<Index>(maps[i] - 1);
    ASSERT_LT(originalIndex, original.atomCount()) << smiles;
    EXPECT_EQ(reparsed.atomicNumber(i), original.atomicNumber(originalIndex))
      << smiles << ": atom " << i;
    EXPECT_EQ(after[i], before[originalIndex]) << smiles << ": atom " << i;
  }
}

} // namespace

TEST(SmilesParserTest, aromaticRoundTripBenzene)
{
  expectAromaticRoundTrip("c1ccccc1");
}

TEST(SmilesParserTest, aromaticRoundTripPyrrole)
{
  expectAromaticRoundTrip("[nH]1cccc1");
}

TEST(SmilesParserTest, aromaticRoundTripNaphthalene)
{
  expectAromaticRoundTrip("c1ccc2ccccc2c1");
}

TEST(SmilesParserTest, aromaticRoundTripBiphenyl)
{
  expectAromaticRoundTrip("c1ccc(cc1)-c1ccccc1");
}

TEST(SmilesParserTest, aromaticRoundTripCaffeine)
{
  expectAromaticRoundTrip("Cn1cnc2c1c(=O)n(C)c(=O)n2C");
}

// ---------------------------------------------------------------------------
// Round trip: write a parsed-in molecule back out with explicit hydrogens,
// atom maps and no aromatic perception, reparse it, and check that the two
// molecules agree atom for atom.

namespace {

void expectRoundTrip(Molecule& original)
{
  SmilesWriter writer;
  writer.setAtomMaps(true); // Implies explicit hydrogens.
  writer.setAromatic(false);
  std::string smiles;
  ASSERT_TRUE(writer.write(original, smiles)) << writer.error();

  SmilesParser parser;
  Molecule reparsed;
  ASSERT_TRUE(parser.parse(smiles, reparsed))
    << smiles << ": " << parser.error();

  ASSERT_EQ(reparsed.atomCount(), original.atomCount()) << smiles;
  const std::vector<size_t>& maps = parser.atomMaps();
  ASSERT_EQ(maps.size(), reparsed.atomCount());

  // Atom maps correlate the two molecules' atoms: SmilesWriter wrote class
  // N+1 for original atom N, so subtracting one recovers the original index.
  for (Index i = 0; i < reparsed.atomCount(); ++i) {
    ASSERT_GT(maps[i], 0u) << smiles;
    const Index originalIndex = static_cast<Index>(maps[i] - 1);
    ASSERT_LT(originalIndex, original.atomCount()) << smiles;
    EXPECT_EQ(reparsed.atomicNumber(i), original.atomicNumber(originalIndex))
      << smiles << ": atom " << i;
    EXPECT_EQ(reparsed.formalCharge(i), original.formalCharge(originalIndex))
      << smiles << ": atom " << i;
    EXPECT_EQ(reparsed.isotope(i), original.isotope(originalIndex))
      << smiles << ": atom " << i;
  }

  ASSERT_EQ(reparsed.bondCount(), original.bondCount()) << smiles;
  for (Index b = 0; b < reparsed.bondCount(); ++b) {
    const std::pair<Index, Index> pair = reparsed.bondPair(b);
    const Index origA = static_cast<Index>(maps[pair.first] - 1);
    const Index origB = static_cast<Index>(maps[pair.second] - 1);
    const Avogadro::Core::Bond origBond = original.bond(origA, origB);
    ASSERT_TRUE(origBond.isValid()) << smiles;
    EXPECT_EQ(reparsed.bondOrders()[b], origBond.order()) << smiles;
  }
}

Molecule ethanolMolecule()
{
  Molecule mol;
  const Index c1 = mol.addAtom(6).index();
  const Index c2 = mol.addAtom(6).index();
  const Index oxygen = mol.addAtom(8).index();
  mol.addBond(c1, c2, 1);
  mol.addBond(c2, oxygen, 1);
  addHydrogens(mol, c1, 3);
  addHydrogens(mol, c2, 2);
  addHydrogens(mol, oxygen, 1);
  return mol;
}

Molecule cyclohexaneMolecule()
{
  Molecule mol;
  Index ring[6];
  for (int i = 0; i < 6; ++i)
    ring[i] = mol.addAtom(6).index();
  for (int i = 0; i < 6; ++i)
    mol.addBond(ring[i], ring[(i + 1) % 6], 1);
  for (int i = 0; i < 6; ++i)
    addHydrogens(mol, ring[i], 2);
  return mol;
}

Molecule kekuleNaphthaleneMolecule()
{
  Molecule mol;
  Index ring[10];
  for (int i = 0; i < 10; ++i)
    ring[i] = mol.addAtom(6).index();
  // Alternating bond orders around the perimeter, plus the single bond
  // shared by the two fused rings (4a-8a in naphthalene's own numbering).
  for (int i = 0; i < 10; ++i) {
    const unsigned char order = (i % 2 == 0) ? 1 : 2;
    mol.addBond(ring[i], ring[(i + 1) % 10], order);
  }
  mol.addBond(ring[4], ring[9], 1);

  const bool bridgehead[10] = { false, false, false, false, true,
                                false, false, false, false, true };
  for (int i = 0; i < 10; ++i) {
    if (!bridgehead[i])
      addHydrogens(mol, ring[i], 1);
  }
  return mol;
}

Molecule saltMolecule()
{
  Molecule mol;
  const Index sodium = mol.addAtom(11).index();
  mol.setFormalCharge(sodium, 1);
  const Index chlorine = mol.addAtom(17).index();
  mol.setFormalCharge(chlorine, -1);
  return mol;
}

Molecule isotopeLabelledMolecule()
{
  // 13C-labelled methane, with one of its hydrogens replaced by deuterium.
  Molecule mol;
  const Index carbon = mol.addAtom(6).index();
  mol.setIsotope(carbon, 13);
  addHydrogens(mol, carbon, 3);
  const Index deuterium = mol.addAtom(1).index();
  mol.setIsotope(deuterium, 2);
  mol.addBond(carbon, deuterium, 1);
  return mol;
}

} // namespace

TEST(SmilesParserTest, roundTripEthanol)
{
  Molecule mol = ethanolMolecule();
  expectRoundTrip(mol);
}

TEST(SmilesParserTest, roundTripCyclohexane)
{
  Molecule mol = cyclohexaneMolecule();
  expectRoundTrip(mol);
}

TEST(SmilesParserTest, roundTripKekuleNaphthalene)
{
  Molecule mol = kekuleNaphthaleneMolecule();
  expectRoundTrip(mol);
}

TEST(SmilesParserTest, roundTripChargedSalt)
{
  Molecule mol = saltMolecule();
  expectRoundTrip(mol);
}

TEST(SmilesParserTest, roundTripIsotopeLabelled)
{
  Molecule mol = isotopeLabelledMolecule();
  expectRoundTrip(mol);
}
