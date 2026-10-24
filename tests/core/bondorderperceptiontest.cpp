/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bondorderchecks.h"

#include <gtest/gtest.h>

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <map>
#include <numeric>
#include <random>
#include <string>
#include <vector>

using Avogadro::Index;
using Avogadro::MaxIndex;
using Avogadro::Vector3;
using Avogadro::Core::BondOrderOptions;
using Avogadro::Core::BondOrderResult;
using Avogadro::Core::Elements;
using Avogadro::Core::Molecule;
using BondOrderChecks::histogram;
using BondOrderChecks::orderSums;
using BondOrderChecks::saneOrders;
using BondOrderChecks::shuffledCopy;

namespace {

/**
 * A molecule built from a small SMILES-like string, with every bond single
 * (what a coordinate file gives the perceiver) and the orders the string
 * spelled out recorded on the side.
 *
 * Only what these tests need is supported: the organic subset B C N O P S F
 * Cl Br I, aromatic c n o s, bracket atoms such as [nH], [Zn] and [CH],
 * branches, single-digit ring closures, and the bond symbols - = #. Bonds
 * between two aromatic atoms that carry no symbol are "aromatic": they have
 * no recorded order, and count one unit toward the atoms' hydrogen count.
 * Hydrogens are added explicitly so that every atom has its usual valence,
 * which is also the valence the checks below expect.
 */
struct Parsed
{
  Molecule mol;
  std::vector<unsigned char> spelled; //!< 0 where the bond was aromatic.
  std::vector<unsigned int> valence;  //!< Expected order sum; 0 for metals.
};

unsigned int usualValence(unsigned char z)
{
  switch (z) {
    case 1:
    case 9:
    case 17:
    case 35:
    case 53:
      return 1;
    case 5:
    case 7:
    case 15:
      return 3;
    case 6:
      return 4;
    case 8:
    case 16:
      return 2;
    default:
      return 0;
  }
}

Parsed parse(const std::string& text)
{
  struct Pending
  {
    unsigned char z = 0;
    bool aromatic = false;
    int bracketH = -1;
  };
  struct Link
  {
    Index a;
    Index b;
    int symbol; // 0 none, 1 2 3 explicit
  };
  std::vector<Pending> atoms;
  std::vector<Link> links;
  std::map<char, std::pair<Index, int>> openRings;
  std::vector<Index> branchStack;
  Index previous = MaxIndex;
  int symbol = 0;

  auto addAtom = [&](unsigned char z, bool aromatic, int bracketH) {
    atoms.push_back({ z, aromatic, bracketH });
    const Index index = atoms.size() - 1;
    if (previous != MaxIndex)
      links.push_back({ previous, index, symbol });
    symbol = 0;
    previous = index;
  };

  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (c == '(') {
      branchStack.push_back(previous);
    } else if (c == ')') {
      previous = branchStack.back();
      branchStack.pop_back();
    } else if (c == '-' || c == '=' || c == '#') {
      symbol = (c == '-') ? 1 : (c == '=') ? 2 : 3;
    } else if (c >= '0' && c <= '9') {
      auto it = openRings.find(c);
      if (it == openRings.end()) {
        openRings[c] = { previous, symbol };
      } else {
        links.push_back({ it->second.first, previous,
                          symbol != 0 ? symbol : it->second.second });
        openRings.erase(it);
      }
      symbol = 0;
    } else if (c == '[') {
      const std::size_t close = text.find(']', i);
      std::string body = text.substr(i + 1, close - i - 1);
      i = close;
      int hydrogens = 0;
      const std::size_t h = body.find('H');
      std::string element = body;
      if (h != std::string::npos && h > 0) {
        element = body.substr(0, h);
        hydrogens = (h + 1 < body.size()) ? body[h + 1] - '0' : 1;
      }
      const bool aromatic =
        std::islower(static_cast<unsigned char>(element[0]));
      element[0] =
        static_cast<char>(std::toupper(static_cast<unsigned char>(element[0])));
      addAtom(Elements::atomicNumberFromSymbol(element), aromatic, hydrogens);
    } else if (c == 'C' && i + 1 < text.size() && text[i + 1] == 'l') {
      addAtom(17, false, -1);
      ++i;
    } else if (c == 'B' && i + 1 < text.size() && text[i + 1] == 'r') {
      addAtom(35, false, -1);
      ++i;
    } else {
      const bool aromatic = std::islower(static_cast<unsigned char>(c));
      const std::string s(
        1, static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
      addAtom(Elements::atomicNumberFromSymbol(s), aromatic, -1);
    }
  }

  // Count what each atom already has, to work out its hydrogens.
  const std::size_t n = atoms.size();
  std::vector<unsigned int> fixedSum(n, 0), aromaticBonds(n, 0);
  std::vector<bool> multiple(n, false);
  std::vector<bool> aromaticLink(links.size(), false);
  for (std::size_t l = 0; l < links.size(); ++l) {
    const Link& link = links[l];
    const bool metal =
      Elements::isMetal(atoms[link.a].z) || Elements::isMetal(atoms[link.b].z);
    if (link.symbol == 0 && atoms[link.a].aromatic && atoms[link.b].aromatic &&
        !metal) {
      aromaticLink[l] = true;
      ++aromaticBonds[link.a];
      ++aromaticBonds[link.b];
    } else if (!metal) {
      const unsigned int order = (link.symbol == 0) ? 1 : link.symbol;
      fixedSum[link.a] += order;
      fixedSum[link.b] += order;
      if (order > 1) {
        multiple[link.a] = true;
        multiple[link.b] = true;
      }
    }
  }

  Parsed result;
  for (const Pending& atom : atoms)
    result.mol.addAtom(atom.z);
  for (std::size_t l = 0; l < links.size(); ++l) {
    result.mol.addBond(links[l].a, links[l].b, 1);
    result.spelled.push_back(
      aromaticLink[l] ? 0 : (links[l].symbol == 0 ? 1 : links[l].symbol));
  }
  for (std::size_t a = 0; a < n; ++a) {
    const Pending& atom = atoms[a];
    int hydrogens = atom.bracketH;
    if (hydrogens < 0 && !Elements::isMetal(atom.z)) {
      // An aromatic C or N with no spelled-out double bond supplies one pi
      // unit; aromatic O and S do not.
      const int pi =
        (atom.aromatic && (atom.z == 6 || atom.z == 7) && !multiple[a]) ? 1 : 0;
      hydrogens = static_cast<int>(usualValence(atom.z)) -
                  static_cast<int>(fixedSum[a]) -
                  static_cast<int>(aromaticBonds[a]) - pi;
    }
    for (int h = 0; h < std::max(hydrogens, 0); ++h) {
      const Index hydrogen = result.mol.addAtom(1).index();
      result.mol.addBond(a, hydrogen, 1);
      result.spelled.push_back(1);
    }
  }
  for (std::size_t a = 0; a < result.mol.atomCount(); ++a) {
    result.valence.push_back(Elements::isMetal(result.mol.atomicNumber(a))
                               ? 0
                               : usualValence(result.mol.atomicNumber(a)));
  }
  return result;
}

/** Puts the spelled-out orders of the bonds in @a which onto the molecule. */
void applySpelled(Parsed& p, const std::vector<std::size_t>& which)
{
  for (std::size_t bond : which)
    p.mol.setBondOrder(bond, p.spelled[bond]);
}

/** Every valence is filled, orders are 1 to 3, and H/halogen bonds single. */
::testing::AssertionResult valid(const Parsed& p, const Molecule& mol)
{
  const std::vector<unsigned int> sums = orderSums(mol, true);
  for (Index atom = 0; atom < mol.atomCount(); ++atom) {
    if (Elements::isMetal(mol.atomicNumber(atom)))
      continue;
    if (sums[atom] != p.valence[atom]) {
      return ::testing::AssertionFailure()
             << "atom " << atom << " ("
             << Elements::symbol(mol.atomicNumber(atom)) << ") has order sum "
             << sums[atom] << ", expected " << p.valence[atom];
    }
  }
  return saneOrders(mol);
}

/** A shuffled copy of @a p; the usual valences are recomputed for it. */
Parsed shuffledParsed(const Parsed& p, unsigned int seed)
{
  Parsed result;
  result.mol = shuffledCopy(p.mol, seed, false);
  for (Index a = 0; a < result.mol.atomCount(); ++a) {
    result.valence.push_back(Elements::isMetal(result.mol.atomicNumber(a))
                               ? 0
                               : usualValence(result.mol.atomicNumber(a)));
  }
  return result;
}

void expectSolvedUnderShuffles(const std::string& text, int shuffles = 20)
{
  Parsed p = parse(text);
  for (int s = 0; s < shuffles; ++s) {
    Parsed copy = shuffledParsed(p, 1000 + s);
    BondOrderOptions options;
    options.useGeometry = false;
    const BondOrderResult result = copy.mol.perceiveBondOrders(options);
    EXPECT_TRUE(result.success)
      << text << " seed " << s << ": " << result.message;
    EXPECT_TRUE(valid(copy, copy.mol)) << text << " seed " << s;
  }
}

} // namespace

TEST(BondOrderPerceptionTest, simpleMolecules)
{
  const char* cases[] = {
    "c1ccccc1",              // benzene
    "C=CC=C",                // butadiene (bonds spelled; stripped below)
    "CC#N",                  // acetonitrile
    "CC(=O)C",               // acetone
    "C=O",                   // formaldehyde
    "c1ccncc1",              // pyridine
    "c1ccoc1",               // furan
    "c1cc[nH]c1",            // pyrrole
    "c1ccsc1",               // thiophene
    "O=c1cccc[nH]1",         // 2-pyridone
    "c1ccc(cc1)N=Nc1ccccc1", // azobenzene
    "CC(=O)N",               // acetamide
    "C#C",                   // ethyne
    "C=C=C",                 // allene
    "ClC=C",                 // chloroethene: the halogen bond stays single
  };
  for (const char* text : cases) {
    Parsed p = parse(text);
    const BondOrderResult result = p.mol.perceiveBondOrders(BondOrderOptions());
    EXPECT_TRUE(result.success) << text << ": " << result.message;
    EXPECT_TRUE(result.failedAtoms.empty()) << text;
    EXPECT_TRUE(result.message.empty()) << text;
    EXPECT_TRUE(valid(p, p.mol)) << text;
  }
}

TEST(BondOrderPerceptionTest, specificOrders)
{
  Parsed nitrile = parse("CC#N");
  nitrile.mol.perceiveBondOrders();
  EXPECT_EQ(nitrile.mol.bond(0, 1).order(), 1);
  EXPECT_EQ(nitrile.mol.bond(1, 2).order(), 3);

  Parsed acetone = parse("CC(=O)C");
  acetone.mol.perceiveBondOrders();
  EXPECT_EQ(acetone.mol.bond(1, 2).order(), 2);
  EXPECT_EQ(acetone.mol.bond(0, 1).order(), 1);

  // 2-pyridone: the C=O is a double bond, so the ring carbon next to it must
  // not also be given a ring double bond.
  Parsed pyridone = parse("O=c1cccc[nH]1");
  pyridone.mol.perceiveBondOrders();
  EXPECT_EQ(pyridone.mol.bond(0, 1).order(), 2);
  EXPECT_EQ(histogram(pyridone.mol)[2], 3u);
}

TEST(BondOrderPerceptionTest, fusedAromaticsUnderRandomOrderings)
{
  const char* fused[] = {
    "c1ccc2ccccc2c1",                                      // naphthalene
    "c1ccc2cc3ccccc3cc2c1",                                // anthracene
    "c1cc2ccc3cccc4ccc(c1)c2c34",                          // pyrene
    "c1ccc2cc3cc4ccccc4cc3cc2c1",                          // tetracene
    "c1cc2ccc3ccc4ccc5ccc6ccc1c1c2c3c4c5c61",              // coronene
    "C1=CC2=NC1=CC1=CC=C(N1)C=C1C=CC(=N1)C=C1C=CC(=C2)N1", // porphine
    "c1ccc(cc1)N=Nc1ccccc1",                               // azobenzene
    "O=c1cccc[nH]1",                                       // 2-pyridone
    "c1ccc2cccc2cc1",                                      // azulene
  };
  for (const char* text : fused)
    expectSolvedUnderShuffles(text);
}

TEST(BondOrderPerceptionTest, noOrderAboveThree)
{
  // Heavy atoms only: each carbon is three valence units short, which the
  // single C-C bond could only supply as order 4. Phase 1 cannot add
  // hydrogens, so it reports the failure; what matters is that no bond ever
  // leaves the 1 to 3 range. The best effort raises the bond as far as it may
  // go, a triple bond, which leaves each carbon one unit short.
  for (int order : { 2, 3 }) {
    Molecule mol;
    mol.addAtom(6);
    mol.addAtom(6);
    mol.setAtomPosition3d(0, Vector3(0, 0, 0));
    mol.setAtomPosition3d(1, Vector3(order == 2 ? 1.34 : 1.20, 0, 0));
    mol.addBond(0, 1, 1);
    const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failedAtoms, (std::vector<Index>{ 0, 1 }));
    EXPECT_FALSE(result.message.empty());
    EXPECT_EQ(mol.bond(0).order(), 3);
  }
}

TEST(BondOrderPerceptionTest, hydrogenAndHalogenBondsStaySingle)
{
  // A lone C-F with nothing else cannot be satisfied, and must not turn into
  // a double bond to fluorine on the way.
  Molecule mol;
  mol.addAtom(6);
  mol.addAtom(9);
  mol.addBond(0, 1, 1);
  mol.perceiveBondOrders();
  EXPECT_EQ(mol.bond(0).order(), 1);
}

/**
 * Benzene next to an allyl radical, CH2-CH-CH2: three carbons that each want
 * one more bond but have only two bonds to share. @a shift is set to the
 * index of the radical's first carbon.
 */
Molecule benzeneBesideAllylRadical(Index& shift)
{
  Molecule mol = parse("c1ccccc1").mol;
  shift = mol.atomCount();
  const int hydrogens[] = { 2, 1, 2 };
  for (int i = 0; i < 3; ++i)
    mol.addAtom(6);
  mol.addBond(shift, shift + 1, 1);
  mol.addBond(shift + 1, shift + 2, 1);
  for (Index c = 0; c < 3; ++c) {
    for (int h = 0; h < hydrogens[c]; ++h)
      mol.addBond(shift + c, mol.addAtom(1).index(), 1);
  }
  return mol;
}

TEST(BondOrderPerceptionTest, unsatisfiableComponentLeavesOthersAlone)
{
  // The radical cannot be satisfied, the ring can, and each is judged on its
  // own.
  Index shift = 0;
  Molecule combined = benzeneBesideAllylRadical(shift);
  const Index ringBonds = 12; // six ring bonds and six C-H

  const BondOrderResult combinedResult =
    combined.perceiveBondOrders(BondOrderOptions());
  EXPECT_FALSE(combinedResult.success);
  ASSERT_EQ(combinedResult.failedAtoms.size(), 1u);
  EXPECT_GE(combinedResult.failedAtoms[0], shift);
  EXPECT_LE(combinedResult.failedAtoms[0], shift + 2);
  EXPECT_NE(combinedResult.message.find("atom"), std::string::npos);

  // The ring got its three double bonds ...
  std::size_t doubles = 0;
  for (Index b = 0; b < ringBonds; ++b)
    doubles += (combined.bond(b).order() == 2) ? 1 : 0;
  EXPECT_EQ(doubles, 3u);
  // ... and the radical gets a best-effort double bond, one of its two
  // carbon-carbon bonds, with the odd carbon out reported.
  std::size_t radicalDoubles = 0;
  for (Index b = ringBonds; b < combined.bondCount(); ++b)
    radicalDoubles += (combined.bond(b).order() == 2) ? 1 : 0;
  EXPECT_EQ(radicalDoubles, 1u);
}

TEST(BondOrderPerceptionTest, presetMultipleBondIsKept)
{
  // Benzene with one double bond already in place: the rest of the ring is
  // completed around it, and it is not lowered.
  Parsed benzene = parse("c1ccccc1");
  benzene.mol.setBondOrder(1, 2); // C1-C2 (bond 0 is C0-C1)
  EXPECT_TRUE(benzene.mol.perceiveBondOrders(BondOrderOptions()).success);
  EXPECT_EQ(benzene.mol.bond(1).order(), 2);
  EXPECT_TRUE(valid(benzene, benzene.mol));

  // A preset double bond in a chain: the other double bond is built around
  // it and the preset one is not lowered.
  Parsed diene = parse("C=CC=C");
  diene.mol.setBondOrder(2, 2);
  EXPECT_TRUE(diene.mol.perceiveBondOrders(BondOrderOptions()).success);
  EXPECT_EQ(diene.mol.bond(2).order(), 2);
  EXPECT_EQ(diene.mol.bond(0).order(), 2);
  EXPECT_TRUE(valid(diene, diene.mol));
}

TEST(BondOrderPerceptionTest, presetOrdersCountTowardValence)
{
  // Acetone with the carbonyl already double: nothing is left to do, and
  // nothing may be added.
  Parsed acetone = parse("CC(=O)C");
  applySpelled(acetone, { 1 }); // the C=O
  EXPECT_TRUE(acetone.mol.perceiveBondOrders(BondOrderOptions()).success);
  EXPECT_EQ(histogram(acetone.mol)[2], 1u);
  EXPECT_TRUE(valid(acetone, acetone.mol));
}

TEST(BondOrderPerceptionTest, metalLigandStaysAromatic)
{
  Parsed complex = parse("[Zn]n1ccccc1");
  EXPECT_TRUE(complex.mol.perceiveBondOrders(BondOrderOptions()).success);
  EXPECT_TRUE(valid(complex, complex.mol));
  // The Zn-N bond (bond 0) is untouched, the ring has three double bonds.
  EXPECT_EQ(complex.mol.bond(0).order(), 1);
  EXPECT_EQ(histogram(complex.mol)[2], 3u);
}

TEST(BondOrderPerceptionTest, metalCarbonylFailsGracefully)
{
  // Fe(CO) alone: the carbon wants three more units of valence from an
  // oxygen that can give one, so perception reports the failure rather than
  // looping. The best effort makes C=O, and the metal bond is never touched.
  Parsed carbonyl = parse("[Fe]C#O");
  const BondOrderResult result =
    carbonyl.mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_FALSE(result.success);
  EXPECT_EQ(result.failedAtoms, (std::vector<Index>{ 1 }));
  EXPECT_EQ(carbonyl.mol.bond(0, 1).order(), 1);
  EXPECT_EQ(carbonyl.mol.bond(1, 2).order(), 2);
}

TEST(BondOrderPerceptionTest, geometryChoosesBetweenKekuleStructures)
{
  // A benzene ring whose bonds alternate short and long. Both Kekule
  // structures are valid; the geometry says which one to take.
  for (int shift = 0; shift < 2; ++shift) {
    Molecule mol;
    const double delta = 1.5 * 3.14159265358979 / 180.0;
    const double radius = 1.4;
    for (int i = 0; i < 6; ++i) {
      const double angle =
        i * 3.14159265358979 / 3.0 + (((i + shift) % 2 == 0) ? -delta : delta);
      mol.addAtom(6).setPosition3d(
        Vector3(radius * std::cos(angle), radius * std::sin(angle), 0.0));
    }
    for (int i = 0; i < 6; ++i) {
      const double angle =
        i * 3.14159265358979 / 3.0 + (((i + shift) % 2 == 0) ? -delta : delta);
      auto h = mol.addAtom(1);
      h.setPosition3d(
        Vector3(2.49 * std::cos(angle), 2.49 * std::sin(angle), 0.0));
      mol.addBond(i, h.index(), 1);
    }
    for (int i = 0; i < 6; ++i)
      mol.addBond(i, (i + 1) % 6, 1);

    ASSERT_TRUE(mol.perceiveBondOrders(BondOrderOptions()).success);

    // Bond 6 + i joins atoms i and i + 1. Find the shorter bonds.
    double lengths[6];
    for (int i = 0; i < 6; ++i) {
      lengths[i] =
        (mol.atomPosition3d(i) - mol.atomPosition3d((i + 1) % 6)).norm();
    }
    for (int i = 0; i < 6; ++i) {
      const bool shorter = lengths[i] < lengths[(i + 1) % 6];
      EXPECT_EQ(mol.bond(6 + i).order(), shorter ? 2 : 1)
        << "shift " << shift << " bond " << i;
    }
  }
}

TEST(BondOrderPerceptionTest, longPolyeneWithNitroGroup)
{
  // A polyene of 800 carbons (hydrogens included, about 1600 atoms) with a
  // nitro group on one end. The nitro oxygens cannot be satisfied with one
  // fixed valence per atom - that waits for variable valence states - but
  // the polyene must neither be slow nor lose its double bonds because of it.
  constexpr int chain = 800;
  Molecule mol;
  for (int i = 0; i < chain; ++i)
    mol.addAtom(6);
  for (int i = 0; i + 1 < chain; ++i)
    mol.addBond(i, i + 1, 1);
  for (int i = 0; i < chain; ++i) {
    const int hydrogens = (i == 0) ? 1 : (i == chain - 1) ? 2 : 1;
    for (int h = 0; h < hydrogens; ++h)
      mol.addBond(i, mol.addAtom(1).index(), 1);
  }
  const Index nitrogen = mol.addAtom(7).index();
  const Index oxygen1 = mol.addAtom(8).index();
  const Index oxygen2 = mol.addAtom(8).index();
  mol.addBond(0, nitrogen, 1);
  mol.addBond(nitrogen, oxygen1, 1);
  mol.addBond(nitrogen, oxygen2, 1);

  const auto start = std::chrono::steady_clock::now();
  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  const double seconds =
    std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
      .count();
  EXPECT_LT(seconds, 1.0);

  // The nitro oxygens are reported; nothing else is.
  EXPECT_FALSE(result.success);
  EXPECT_EQ(result.failedAtoms, (std::vector<Index>{ oxygen1, oxygen2 }));

  // Every carbon has its fourth valence, with the double bonds alternating
  // along the chain.
  const std::vector<unsigned int> sums = orderSums(mol, true);
  for (int i = 0; i < chain; ++i)
    EXPECT_EQ(sums[i], 4u) << "carbon " << i;
  EXPECT_EQ(histogram(mol)[2], static_cast<std::size_t>(chain / 2));
  EXPECT_EQ(mol.bond(0, nitrogen).order(), 1);
}

/**
 * A parallelogram of hexagonal graphene cells, edge carbons capped with
 * hydrogen, as geometry-only input (coordinates plus bonds). With @a vacancy
 * the carbon nearest the middle is removed, leaving an odd number of carbons
 * (the three neighbours get hydrogen).
 */
Molecule graphene(bool vacancy, std::size_t& carbons)
{
  // A parallelogram of hexagonal graphene cells, edge carbons capped with
  // hydrogen, as geometry-only input (coordinates plus bonds).
  constexpr int cells = 10;
  const Vector3 a1(2.46, 0.0, 0.0);
  const Vector3 a2(1.23, 2.1304, 0.0);
  const Vector3 offset(1.23, 0.7101, 0.0);
  std::vector<Vector3> positions;
  for (int i = 0; i < cells; ++i) {
    for (int j = 0; j < cells; ++j) {
      positions.push_back(i * a1 + j * a2);
      positions.push_back(i * a1 + j * a2 + offset);
    }
  }
  // Drop atoms that would hang off the flake by one bond, until none do.
  for (bool changed = true; changed;) {
    changed = false;
    for (std::size_t p = 0; p < positions.size(); ++p) {
      int neighbours = 0;
      for (std::size_t q = 0; q < positions.size(); ++q) {
        if (p != q && (positions[p] - positions[q]).norm() < 1.6)
          ++neighbours;
      }
      if (neighbours < 2) {
        positions.erase(positions.begin() + static_cast<std::ptrdiff_t>(p));
        changed = true;
        break;
      }
    }
  }

  if (vacancy) {
    // Take out the carbon nearest the middle of the flake.
    Vector3 centre = Vector3::Zero();
    for (const Vector3& position : positions)
      centre += position;
    centre /= static_cast<double>(positions.size());
    std::size_t nearest = 0;
    for (std::size_t p = 1; p < positions.size(); ++p) {
      if ((positions[p] - centre).norm() < (positions[nearest] - centre).norm())
        nearest = p;
    }
    positions.erase(positions.begin() + static_cast<std::ptrdiff_t>(nearest));
  }

  Molecule mol;
  for (const Vector3& position : positions)
    mol.addAtom(6).setPosition3d(position);
  carbons = positions.size();
  for (std::size_t p = 0; p < carbons; ++p) {
    std::vector<std::size_t> neighbours;
    for (std::size_t q = 0; q < carbons; ++q) {
      if (p != q && (positions[p] - positions[q]).norm() < 1.6)
        neighbours.push_back(q);
    }
    for (std::size_t q : neighbours) {
      if (q > p)
        mol.addBond(p, q, 1);
    }
    if (neighbours.size() == 2) {
      Vector3 centre =
        (positions[neighbours[0]] + positions[neighbours[1]]) / 2.0;
      Vector3 outward = (positions[p] - centre).normalized();
      auto h = mol.addAtom(1);
      h.setPosition3d(positions[p] + 1.09 * outward);
      mol.addBond(p, h.index(), 1);
    }
  }
  return mol;
}

TEST(BondOrderPerceptionTest, grapheneFlake)
{
  std::size_t carbons = 0;
  Molecule mol = graphene(false, carbons);
  ASSERT_GT(carbons, 150u);

  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_TRUE(result.success) << result.message;
  const std::vector<unsigned int> sums = orderSums(mol, true);
  for (Index c = 0; c < carbons; ++c)
    EXPECT_EQ(sums[c], 4u) << "carbon " << c;
  EXPECT_EQ(histogram(mol)[2], carbons / 2);
}

TEST(BondOrderPerceptionTest, oddUnsaturationFailsImmediately)
{
  // A flake with a vacancy has an odd number of sp2 carbons: no pairing of
  // their valences exists. That is decided before any search (the old
  // behaviour spent its whole step budget), so the message names the cause
  // rather than the step limit. The rest of the flake still gets a best-
  // effort Kekule structure, leaving exactly one carbon over.
  std::size_t carbons = 0;
  Molecule mol = graphene(true, carbons);
  ASSERT_EQ(carbons % 2, 1u);

  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_FALSE(result.success);
  EXPECT_EQ(result.failedAtoms.size(), 1u);
  EXPECT_NE(result.message.find("odd number of unpaired"), std::string::npos)
    << result.message;
  EXPECT_EQ(result.message.find("step"), std::string::npos) << result.message;
  EXPECT_EQ(histogram(mol)[2], (carbons - 1) / 2);
}

TEST(BondOrderPerceptionTest, oddUnsaturationIsAnotherComponentsBusiness)
{
  // The allyl radical is odd, which is named as the cause; the benzene beside
  // it is not, and is not reported. One radical carbon is left over.
  Index shift = 0;
  Molecule mol = benzeneBesideAllylRadical(shift);
  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_FALSE(result.success);
  EXPECT_NE(result.message.find("odd number"), std::string::npos);
  ASSERT_EQ(result.failedAtoms.size(), 1u);
  EXPECT_GE(result.failedAtoms[0], shift);
  EXPECT_LE(result.failedAtoms[0], shift + 2);
}

TEST(BondOrderPerceptionTest, atomsBondedOnlyToMetalsAreSatisfied)
{
  // Square-planar PtCl4: the chlorines have no non-metal bond, so there is
  // nothing to perceive, and nothing fails.
  Molecule mol;
  mol.addAtom(78);
  for (int i = 0; i < 4; ++i) {
    mol.addAtom(17);
    mol.addBond(0, i + 1, 1);
  }
  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_TRUE(result.success) << result.message;
  EXPECT_TRUE(result.failedAtoms.empty());
  for (Index b = 0; b < mol.bondCount(); ++b)
    EXPECT_EQ(mol.bond(b).order(), 1);
}

TEST(BondOrderPerceptionTest, metalAndNonMetalBondsStillHeldToValence)
{
  // A carbonyl carbon bound to Fe and to O needs three more units of valence
  // from its non-metal bonds but can only get two from the oxygen's one: it
  // is still a failure. The lone chloride on the same metal is not.
  Parsed carbonyl = parse("[Fe]C#O");
  const Index chloride = carbonyl.mol.addAtom(17).index();
  carbonyl.mol.addBond(0, chloride, 1);
  const BondOrderResult result =
    carbonyl.mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_FALSE(result.success);
  for (Index atom : result.failedAtoms)
    EXPECT_NE(atom, chloride);
  EXPECT_FALSE(result.failedAtoms.empty());

  // An atom with no bonds at all is not covered by the metal rule: a lone
  // chlorine beside a bonded pair still fails.
  Molecule lone;
  lone.addAtom(6);
  lone.addAtom(8);
  lone.addBond(0, 1, 1);
  const Index stray = lone.addAtom(17).index();
  const BondOrderResult loneResult =
    lone.perceiveBondOrders(BondOrderOptions());
  EXPECT_FALSE(loneResult.success);
  EXPECT_NE(std::find(loneResult.failedAtoms.begin(),
                      loneResult.failedAtoms.end(), stray),
            loneResult.failedAtoms.end());
}

TEST(BondOrderPerceptionTest, stepBudgetDoesNotStopBestEffort)
{
  // With no budget at all, anything that needs a guess is given up by the
  // exact search. Benzene without a starting double bond needs one, but the
  // best-effort completion that follows finds the Kekule structure anyway
  // (a ring is bipartite), so the group counts as solved.
  Parsed benzene = parse("c1ccccc1");
  BondOrderOptions options;
  options.useGeometry = false;
  options.stepBudgetPerComponent = 0;
  const BondOrderResult result = benzene.mol.perceiveBondOrders(options);
  EXPECT_TRUE(result.success) << result.message;
  EXPECT_TRUE(result.failedAtoms.empty());
  EXPECT_EQ(histogram(benzene.mol)[2], 3u);
}

/** Bare carbon atoms at @a positions, bonded along @a bonds, all single. */
Molecule bareCarbons(const std::vector<Vector3>& positions,
                     const std::vector<std::pair<Index, Index>>& bonds)
{
  Molecule mol;
  for (const Vector3& position : positions)
    mol.addAtom(6).setPosition3d(position);
  for (const auto& bond : bonds)
    mol.addBond(bond.first, bond.second, 1);
  return mol;
}

/** How many double bonds each atom is in. */
std::vector<unsigned int> doubleBondCounts(const Molecule& mol)
{
  std::vector<unsigned int> counts(mol.atomCount(), 0);
  for (Index b = 0; b < mol.bondCount(); ++b) {
    if (mol.bondOrders()[b] == 2) {
      ++counts[mol.bondPairs()[b].first];
      ++counts[mol.bondPairs()[b].second];
    }
  }
  return counts;
}

Molecule bareHexagon()
{
  std::vector<Vector3> positions;
  for (int i = 0; i < 6; ++i) {
    const double angle = i * 3.14159265358979 / 3.0;
    positions.emplace_back(1.39 * std::cos(angle), 1.39 * std::sin(angle), 0.0);
  }
  std::vector<std::pair<Index, Index>> bonds;
  for (Index i = 0; i < 6; ++i)
    bonds.emplace_back(i, (i + 1) % 6);
  return bareCarbons(positions, bonds);
}

TEST(BondOrderPerceptionTest, bareBenzeneRingIsNotACumulene)
{
  // Six carbons and no hydrogens: each has two neighbors and wants two more
  // bonds, which connectivity alone satisfies with six double bonds. A bent
  // period-2 atom is sp2 and carries one pi bond, so the geometry gives three.
  Molecule mol = bareHexagon();
  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_TRUE(result.success) << result.message;
  EXPECT_EQ(histogram(mol)[2], 3u);
  EXPECT_EQ(histogram(mol)[1], 3u);
  for (unsigned int count : doubleBondCounts(mol))
    EXPECT_EQ(count, 1u);
}

TEST(BondOrderPerceptionTest, bareBenzeneRingWithoutGeometry)
{
  // Without geometry nothing says the carbons are bent, so whatever comes
  // out is only required to be an exact assignment.
  Molecule mol = bareHexagon();
  BondOrderOptions options;
  options.useGeometry = false;
  const BondOrderResult result = mol.perceiveBondOrders(options);
  EXPECT_TRUE(result.success) << result.message;
  for (unsigned int sum : orderSums(mol))
    EXPECT_EQ(sum, 4u);
}

TEST(BondOrderPerceptionTest, linearAtomKeepsTwoDoubleBonds)
{
  // Allene, H2C=C=CH2 with explicit hydrogens: the central carbon has two
  // neighbors at 180 degrees, so it is sp and the bent-atom cap must not
  // apply to it.
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(-1.31, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(1.31, 0.0, 0.0));
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 1);
  const double sign[2] = { -1.0, 1.0 };
  for (int end = 0; end < 2; ++end) {
    for (int h = 0; h < 2; ++h) {
      auto hydrogen = mol.addAtom(1);
      hydrogen.setPosition3d(Vector3(sign[end] * 1.88, 0.0, 0.0) +
                             Vector3(0.0, 0.94 * sign[h], 0.0));
      mol.addBond(end == 0 ? 0 : 2, hydrogen.index(), 1);
    }
  }
  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_TRUE(result.success) << result.message;
  EXPECT_EQ(mol.bond(0, 1).order(), 2);
  EXPECT_EQ(mol.bond(1, 2).order(), 2);
}

TEST(BondOrderPerceptionTest, benzyneKeepsItsBentTriple)
{
  // o-Benzyne: the bare carbons are bent but the 1.26 A bond is a triple
  // bond, so the length exception must keep their full demand.
  static const double coordinates[10][3] = {
    { 1.3575, 0.0563, 0.0 },   { 0.7275, 1.1475, 0.0 },
    { -0.6950, 1.2038, 0.0 },  { -1.3900, 0.0000, 0.0 },
    { -0.6950, -1.2038, 0.0 }, { 0.6950, -1.2038, 0.0 },
    { -1.2350, 2.1391, 0.0 },  { -2.4700, 0.0000, 0.0 },
    { -1.2350, -2.1391, 0.0 }, { 1.2350, -2.1391, 0.0 }
  };
  Molecule mol;
  for (int i = 0; i < 10; ++i) {
    mol.addAtom(i < 6 ? 6 : 1)
      .setPosition3d(
        Vector3(coordinates[i][0], coordinates[i][1], coordinates[i][2]));
  }
  mol.perceiveBondsSimple();
  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_TRUE(result.success) << result.message;
  EXPECT_EQ(mol.bond(0, 1).order(), 3);
  EXPECT_EQ(histogram(mol)[3], 1u);
  EXPECT_EQ(histogram(mol)[2], 2u);
}

TEST(BondOrderPerceptionTest, oddSystemGetsBestEffort)
{
  // Allyl radical, CH2-CH-CH2 with explicit hydrogens: no exact answer, but
  // one carbon-carbon double bond is committed and one carbon reported.
  Index shift = 0;
  Molecule mol;
  shift = mol.addAtom(6).index();
  mol.addAtom(6);
  mol.addAtom(6);
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 1);
  const int hydrogens[] = { 2, 1, 2 };
  for (Index c = 0; c < 3; ++c) {
    for (int h = 0; h < hydrogens[c]; ++h)
      mol.addBond(shift + c, mol.addAtom(1).index(), 1);
  }
  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_FALSE(result.success);
  EXPECT_EQ(result.failedAtoms.size(), 1u);
  EXPECT_FALSE(result.message.empty());
  EXPECT_EQ(histogram(mol)[2], 1u);
  for (unsigned int sum : orderSums(mol))
    EXPECT_LE(sum, 4u);
}

TEST(BondOrderPerceptionTest, bentChainKeepsAlternatingDoubleBonds)
{
  // A bare zigzag C4 with 120 degree angles. The interior carbons are sp2
  // and take one double bond each; the terminal carbons are left with
  // dangling valence. The best effort is C=C-C=C and the ends are reported.
  const Vector3 step(1.4, 0.0, 0.0);
  const Vector3 up(0.7, 1.2124, 0.0);
  std::vector<Vector3> positions = { Vector3(0.0, 0.0, 0.0) };
  positions.push_back(positions.back() + step);
  positions.push_back(positions.back() + up);
  positions.push_back(positions.back() + step);
  Molecule mol = bareCarbons(positions, { { 0, 1 }, { 1, 2 }, { 2, 3 } });

  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_FALSE(result.success);
  EXPECT_EQ(mol.bond(0, 1).order(), 2);
  EXPECT_EQ(mol.bond(1, 2).order(), 1);
  EXPECT_EQ(mol.bond(2, 3).order(), 2);
  EXPECT_EQ(result.failedAtoms, (std::vector<Index>{ 0, 3 }));
}

TEST(BondOrderPerceptionTest, hydrogenFreeNanoribbon)
{
  // A bare armchair graphene nanoribbon as ASE writes it (48 carbons, no
  // hydrogens, cut where the periodic cell was). The dangling end atoms
  // cannot be satisfied, but the rest should still be a Kekule pattern.
  static const double coordinates[48][3] = {
    { 7.37854, 0.00000, 0.00000 },  { 8.60829, 0.00000, 0.71000 },
    { 8.60829, 0.00000, 2.13000 },  { 7.37854, 0.00000, 2.84000 },
    { 7.37854, 0.00000, 4.26000 },  { 8.60829, 0.00000, 4.97000 },
    { 8.60829, 0.00000, 6.39000 },  { 7.37854, 0.00000, 7.10000 },
    { 7.37854, 0.00000, 8.52000 },  { 8.60829, 0.00000, 9.23000 },
    { 8.60829, 0.00000, 10.65000 }, { 7.37854, 0.00000, 11.36000 },
    { 4.91902, 0.00000, 0.00000 },  { 6.14878, 0.00000, 0.71000 },
    { 6.14878, 0.00000, 2.13000 },  { 4.91902, 0.00000, 2.84000 },
    { 4.91902, 0.00000, 4.26000 },  { 6.14878, 0.00000, 4.97000 },
    { 6.14878, 0.00000, 6.39000 },  { 4.91902, 0.00000, 7.10000 },
    { 4.91902, 0.00000, 8.52000 },  { 6.14878, 0.00000, 9.23000 },
    { 6.14878, 0.00000, 10.65000 }, { 4.91902, 0.00000, 11.36000 },
    { 2.45951, 0.00000, 0.00000 },  { 3.68927, 0.00000, 0.71000 },
    { 3.68927, 0.00000, 2.13000 },  { 2.45951, 0.00000, 2.84000 },
    { 2.45951, 0.00000, 4.26000 },  { 3.68927, 0.00000, 4.97000 },
    { 3.68927, 0.00000, 6.39000 },  { 2.45951, 0.00000, 7.10000 },
    { 2.45951, 0.00000, 8.52000 },  { 3.68927, 0.00000, 9.23000 },
    { 3.68927, 0.00000, 10.65000 }, { 2.45951, 0.00000, 11.36000 },
    { 0.00000, 0.00000, 0.00000 },  { 1.22976, 0.00000, 0.71000 },
    { 1.22976, 0.00000, 2.13000 },  { 0.00000, 0.00000, 2.84000 },
    { 0.00000, 0.00000, 4.26000 },  { 1.22976, 0.00000, 4.97000 },
    { 1.22976, 0.00000, 6.39000 },  { 0.00000, 0.00000, 7.10000 },
    { 0.00000, 0.00000, 8.52000 },  { 1.22976, 0.00000, 9.23000 },
    { 1.22976, 0.00000, 10.65000 }, { 0.00000, 0.00000, 11.36000 }
  };
  Molecule mol;
  for (const auto& c : coordinates)
    mol.addAtom(6).setPosition3d(Vector3(c[0], c[1], c[2]));
  mol.perceiveBondsSimple();

  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  EXPECT_FALSE(result.success);

  // Every carbon is in exactly one double bond (a perfect matching exists)
  // and none is over its valence.
  for (unsigned int count : doubleBondCounts(mol))
    EXPECT_EQ(count, 1u);
  for (unsigned int sum : orderSums(mol))
    EXPECT_LE(sum, 4u);
  EXPECT_EQ(histogram(mol)[2], 24u);

  // Only the end atoms, which have fewer than three neighbors and so cannot
  // be saturated, are reported; here that is two of them.
  EXPECT_EQ(result.failedAtoms.size(), 2u);
  for (Index atom : result.failedAtoms)
    EXPECT_LT(mol.bonds(atom).size(), 3u);
}
