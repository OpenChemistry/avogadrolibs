/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/aromaticity.h>
#include <avogadro/core/kekulize.h>
#include <avogadro/core/molecule.h>

#include <vector>

using Avogadro::Index;
using Avogadro::MaxIndex;
using Avogadro::Core::AromaticityPerceiver;
using Avogadro::Core::kekulize;
using Avogadro::Core::Molecule;

namespace {

constexpr unsigned char C = 6;
constexpr unsigned char N = 7;
constexpr unsigned char O = 8;
constexpr unsigned char S = 16;

/**
 * Builds a molecule while keeping a bond-is-aromatic mask in lockstep: bonds
 * are appended to a Molecule with sequential indices, so recording "aromatic"
 * or not right next to every addBond() call is the simplest way to keep the
 * two in sync.
 */
class Builder
{
public:
  Index atom(unsigned char atomicNumber, signed char charge = 0)
  {
    const Index index = mol.addAtom(atomicNumber).index();
    if (charge != 0)
      mol.setFormalCharge(index, charge);
    return index;
  }

  void aromaticBond(Index a, Index b)
  {
    mol.addBond(a, b, 1);
    aromatic.push_back(true);
  }

  void plainBond(Index a, Index b, unsigned char order = 1)
  {
    mol.addBond(a, b, order);
    aromatic.push_back(false);
  }

  /** A single hydrogen, attached to @a heavy with a non-aromatic bond. */
  Index hydrogen(Index heavy)
  {
    const Index h = atom(1);
    plainBond(heavy, h);
    return h;
  }

  Molecule mol;
  std::vector<bool> aromatic;
};

/** One entry per ring atom: which ring bonds are aromatic, added in order. */
void ringBonds(Builder& b, const std::vector<Index>& ring)
{
  for (size_t i = 0; i < ring.size(); ++i)
    b.aromaticBond(ring[i], ring[(i + 1) % ring.size()]);
}

int countOrder(const Builder& b, unsigned char order)
{
  int count = 0;
  for (Index bond = 0; bond < b.mol.bondCount(); ++bond) {
    if (b.aromatic[bond] && b.mol.bondOrders()[bond] == order)
      ++count;
  }
  return count;
}

/**
 * Kekulizes @a b.mol and, on success, checks the strongest available
 * consistency test: AromaticityPerceiver, run on the result, must perceive
 * exactly the bonds flagged aromatic going in -- neither more nor less. This
 * is what catches an assignment that is valence-legal but chemically wrong.
 */
void expectKekulizedAndRoundTrips(Builder& b)
{
  Index failedAtom = MaxIndex;
  ASSERT_TRUE(kekulize(b.mol, b.aromatic, &failedAtom))
    << "failed at atom " << failedAtom;

  AromaticityPerceiver perceiver(&b.mol);
  const std::vector<bool>& perceived = perceiver.aromaticBonds();
  ASSERT_EQ(perceived.size(), b.aromatic.size());
  for (Index bond = 0; bond < b.aromatic.size(); ++bond)
    EXPECT_EQ(perceived[bond], b.aromatic[bond]) << "bond " << bond;
}

} // namespace

// ---------------------------------------------------------------------------
// No-op.

TEST(KekulizeTest, noAromaticBondsIsNoOp)
{
  // Plain ethane: every bond added through plainBond(), so the mask is all
  // false and there is nothing for kekulize() to do.
  Builder b;
  const Index c1 = b.atom(C);
  const Index c2 = b.atom(C);
  b.plainBond(c1, c2);
  for (int i = 0; i < 3; ++i)
    b.hydrogen(c1);
  for (int i = 0; i < 3; ++i)
    b.hydrogen(c2);

  EXPECT_TRUE(kekulize(b.mol, b.aromatic));
  for (Index bond = 0; bond < b.mol.bondCount(); ++bond)
    EXPECT_EQ(b.mol.bondOrders()[bond], 1) << "bond " << bond;
}

// ---------------------------------------------------------------------------
// Six-membered rings.

TEST(KekulizeTest, benzene)
{
  Builder b;
  std::vector<Index> ring;
  for (int i = 0; i < 6; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  for (Index atom : ring)
    b.hydrogen(atom);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 3);
  EXPECT_EQ(countOrder(b, 1), 3);
}

TEST(KekulizeTest, pyridine)
{
  // Ring: N, then five CH.
  Builder b;
  std::vector<Index> ring;
  ring.push_back(b.atom(N));
  for (int i = 0; i < 5; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  for (size_t i = 1; i < ring.size(); ++i)
    b.hydrogen(ring[i]);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 3);
  EXPECT_EQ(countOrder(b, 1), 3);
}

TEST(KekulizeTest, naphthalene)
{
  // Two fused six-membered rings, sharing the bond between atoms 3 and 4
  // (connectivity matches AromaticityTest.fusedRings).
  Builder b;
  std::vector<Index> atoms;
  for (int i = 0; i < 10; ++i)
    atoms.push_back(b.atom(C));
  const int bonds[11][2] = { { 0, 1 }, { 1, 2 }, { 2, 3 }, { 3, 4 },
                             { 4, 5 }, { 5, 0 }, { 4, 6 }, { 6, 7 },
                             { 7, 8 }, { 8, 9 }, { 9, 3 } };
  for (const auto& bond : bonds)
    b.aromaticBond(atoms[bond[0]], atoms[bond[1]]);
  const bool bridgehead[10] = { false, false, false, true,  true,
                                false, false, false, false, false };
  for (int i = 0; i < 10; ++i) {
    if (!bridgehead[i])
      b.hydrogen(atoms[i]);
  }

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 5);
  EXPECT_EQ(countOrder(b, 1), 6);
  // The bridgehead bond specifically must come out single.
  const Avogadro::Core::Bond bridge = b.mol.bond(atoms[3], atoms[4]);
  ASSERT_TRUE(bridge.isValid());
  EXPECT_EQ(bridge.order(), 1);
}

TEST(KekulizeTest, anthracene)
{
  // Naphthalene (as above), extended with a third ring fused to the second
  // at the edge directly opposite the first fusion (a linear, catacondensed
  // acene, not an angular one).
  Builder b;
  std::vector<Index> atoms;
  for (int i = 0; i < 14; ++i)
    atoms.push_back(b.atom(C));
  const int bonds[16][2] = { { 0, 1 },   { 1, 2 },   { 2, 3 },   { 3, 4 },
                             { 4, 5 },   { 5, 0 },   { 4, 6 },   { 6, 7 },
                             { 7, 8 },   { 8, 9 },   { 9, 3 },   { 8, 10 },
                             { 10, 11 }, { 11, 12 }, { 12, 13 }, { 13, 7 } };
  for (const auto& bond : bonds)
    b.aromaticBond(atoms[bond[0]], atoms[bond[1]]);
  const bool fusion[14] = { false, false, false, true,  true,  false, false,
                            true,  true,  false, false, false, false, false };
  for (int i = 0; i < 14; ++i) {
    if (!fusion[i])
      b.hydrogen(atoms[i]);
  }

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 7);
  EXPECT_EQ(countOrder(b, 1), 9);
}

TEST(KekulizeTest, biphenylConnectingBondIsNotAromatic)
{
  // Two benzene rings joined by a single, non-aromatic bond: only the twelve
  // ring bonds are aromatic.
  Builder b;
  std::vector<Index> ringA, ringB;
  for (int i = 0; i < 6; ++i)
    ringA.push_back(b.atom(C));
  for (int i = 0; i < 6; ++i)
    ringB.push_back(b.atom(C));
  ringBonds(b, ringA);
  ringBonds(b, ringB);
  b.plainBond(ringA[0], ringB[0]); // The connecting bond: not aromatic.
  for (int i = 1; i < 6; ++i)
    b.hydrogen(ringA[i]);
  for (int i = 1; i < 6; ++i)
    b.hydrogen(ringB[i]);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 6);
  EXPECT_EQ(countOrder(b, 1), 6);
  const Avogadro::Core::Bond connecting = b.mol.bond(ringA[0], ringB[0]);
  ASSERT_TRUE(connecting.isValid());
  EXPECT_EQ(connecting.order(), 1);
}

// ---------------------------------------------------------------------------
// Five-membered rings.

TEST(KekulizeTest, pyrrole)
{
  Builder b;
  std::vector<Index> ring;
  ring.push_back(b.atom(N));
  for (int i = 0; i < 4; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  for (Index atom : ring)
    b.hydrogen(atom); // N-H, then the four ring C-H.

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 2);
  EXPECT_EQ(countOrder(b, 1), 3);
}

TEST(KekulizeTest, furan)
{
  Builder b;
  std::vector<Index> ring;
  ring.push_back(b.atom(O));
  for (int i = 0; i < 4; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  for (size_t i = 1; i < ring.size(); ++i)
    b.hydrogen(ring[i]);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 2);
  EXPECT_EQ(countOrder(b, 1), 3);
}

TEST(KekulizeTest, thiophene)
{
  Builder b;
  std::vector<Index> ring;
  ring.push_back(b.atom(S));
  for (int i = 0; i < 4; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  for (size_t i = 1; i < ring.size(); ++i)
    b.hydrogen(ring[i]);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 2);
  EXPECT_EQ(countOrder(b, 1), 3);
}

TEST(KekulizeTest, imidazole)
{
  // N1(H) - C2 - N3 - C4 - C5 - back to N1.
  Builder b;
  const Index n1 = b.atom(N);
  const Index c2 = b.atom(C);
  const Index n3 = b.atom(N);
  const Index c4 = b.atom(C);
  const Index c5 = b.atom(C);
  ringBonds(b, { n1, c2, n3, c4, c5 });
  b.hydrogen(n1);
  b.hydrogen(c2);
  b.hydrogen(c4);
  b.hydrogen(c5);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 2);
  EXPECT_EQ(countOrder(b, 1), 3);
  // The textbook Kekule structure: C2=N3 and C4=C5.
  EXPECT_EQ(b.mol.bond(c2, n3).order(), 2);
  EXPECT_EQ(b.mol.bond(c4, c5).order(), 2);
  EXPECT_EQ(b.mol.bond(n1, c2).order(), 1);
  EXPECT_EQ(b.mol.bond(n3, c4).order(), 1);
  EXPECT_EQ(b.mol.bond(c5, n1).order(), 1);
}

TEST(KekulizeTest, pyrazole)
{
  // N1(H) - N2 - C3 - C4 - C5 - back to N1.
  Builder b;
  const Index n1 = b.atom(N);
  const Index n2 = b.atom(N);
  const Index c3 = b.atom(C);
  const Index c4 = b.atom(C);
  const Index c5 = b.atom(C);
  ringBonds(b, { n1, n2, c3, c4, c5 });
  b.hydrogen(n1);
  b.hydrogen(c3);
  b.hydrogen(c4);
  b.hydrogen(c5);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 2);
  EXPECT_EQ(countOrder(b, 1), 3);
  EXPECT_EQ(b.mol.bond(n2, c3).order(), 2);
  EXPECT_EQ(b.mol.bond(c4, c5).order(), 2);
}

TEST(KekulizeTest, nMethylpyrrole)
{
  // Like pyrrole, but the N carries a methyl instead of a hydrogen -- still
  // three connections, so the classification is unchanged.
  Builder b;
  std::vector<Index> ring;
  ring.push_back(b.atom(N));
  for (int i = 0; i < 4; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  const Index methyl = b.atom(C);
  b.plainBond(ring[0], methyl);
  for (int i = 0; i < 3; ++i)
    b.hydrogen(methyl);
  for (size_t i = 1; i < ring.size(); ++i)
    b.hydrogen(ring[i]);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 2);
  EXPECT_EQ(countOrder(b, 1), 3);
}

TEST(KekulizeTest, nMethylpyridinium)
{
  // [n+](C) in a six-membered ring: the quaternary nitrogen now needs a
  // double bond too, same as a ring carbon.
  Builder b;
  std::vector<Index> ring;
  ring.push_back(b.atom(N, 1));
  for (int i = 0; i < 5; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  const Index methyl = b.atom(C);
  b.plainBond(ring[0], methyl);
  for (int i = 0; i < 3; ++i)
    b.hydrogen(methyl);
  for (size_t i = 1; i < ring.size(); ++i)
    b.hydrogen(ring[i]);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 3);
  EXPECT_EQ(countOrder(b, 1), 3);
}

TEST(KekulizeTest, cyclopentadienylAnion)
{
  // One carbon carries the -1 charge (a localized resonance structure); it
  // must not take a double bond, and its two ring bonds must come out single.
  Builder b;
  std::vector<Index> ring;
  ring.push_back(b.atom(C, -1));
  for (int i = 0; i < 4; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  for (Index atom : ring)
    b.hydrogen(atom);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 2);
  EXPECT_EQ(countOrder(b, 1), 3);
  EXPECT_EQ(b.mol.bond(ring[0], ring[1]).order(), 1);
  EXPECT_EQ(b.mol.bond(ring[4], ring[0]).order(), 1);
}

TEST(KekulizeTest, tropylium)
{
  // Seven-membered ring, one carbon carrying the +1 charge; it must not take
  // a double bond.
  Builder b;
  std::vector<Index> ring;
  ring.push_back(b.atom(C, 1));
  for (int i = 0; i < 6; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  for (Index atom : ring)
    b.hydrogen(atom);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 3);
  EXPECT_EQ(countOrder(b, 1), 4);
  EXPECT_EQ(b.mol.bond(ring[0], ring[1]).order(), 1);
  EXPECT_EQ(b.mol.bond(ring[6], ring[0]).order(), 1);
}

TEST(KekulizeTest, pyridinoneExocyclicCarbonylTakesNoRingDouble)
{
  // 2-pyridone: N1(H) - C2(=O, exocyclic) - C3 - C4 - C5 - C6 - back to N1.
  Builder b;
  const Index n1 = b.atom(N);
  const Index c2 = b.atom(C);
  const Index c3 = b.atom(C);
  const Index c4 = b.atom(C);
  const Index c5 = b.atom(C);
  const Index c6 = b.atom(C);
  ringBonds(b, { n1, c2, c3, c4, c5, c6 });
  b.hydrogen(n1);
  const Index oxygen = b.atom(O);
  b.plainBond(c2, oxygen, 2); // The exocyclic carbonyl, already order 2.
  b.hydrogen(c3);
  b.hydrogen(c4);
  b.hydrogen(c5);
  b.hydrogen(c6);

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 2);
  EXPECT_EQ(countOrder(b, 1), 4);
  // Neither of the carbonyl carbon's ring bonds may be the double one.
  EXPECT_EQ(b.mol.bond(n1, c2).order(), 1);
  EXPECT_EQ(b.mol.bond(c2, c3).order(), 1);
  EXPECT_EQ(b.mol.bond(c2, oxygen).order(), 2) << "untouched: not aromatic";
}

// ---------------------------------------------------------------------------
// A fused system whose two rings are not independently 4n+2.

TEST(KekulizeTest, azulene)
{
  // Five-membered ring (0-1-2-3-4) fused to a seven-membered ring
  // (0-5-6-7-8-9-4), sharing the bond 4-0 (matches
  // AromaticityTest.azuleneNeedsTheWholeSystem's connectivity).
  Builder b;
  std::vector<Index> atoms;
  for (int i = 0; i < 10; ++i)
    atoms.push_back(b.atom(C));
  const int bonds[11][2] = { { 0, 1 }, { 1, 2 }, { 2, 3 }, { 3, 4 },
                             { 4, 0 }, { 0, 5 }, { 5, 6 }, { 6, 7 },
                             { 7, 8 }, { 8, 9 }, { 9, 4 } };
  for (const auto& bond : bonds)
    b.aromaticBond(atoms[bond[0]], atoms[bond[1]]);
  const bool bridgehead[10] = { true,  false, false, false, true,
                                false, false, false, false, false };
  for (int i = 0; i < 10; ++i) {
    if (!bridgehead[i])
      b.hydrogen(atoms[i]);
  }

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 5);
  EXPECT_EQ(countOrder(b, 1), 6);
}

// ---------------------------------------------------------------------------
// A larger, peri-fused system: pyrene, four six-membered rings sharing two
// central carbons that each belong to three of them. Its size and the
// central carbons are what exercise the backtracking search rather than
// forced moves alone.

TEST(KekulizeTest, pyrene)
{
  // IUPAC numbering 1,2,3,3a,4,5,5a,6,7,8,8a,9,10,10a,10b,10c mapped to
  // 0-15 in that order. Perimeter, then the five internal bonds that close
  // the four rings around the central 10b-10c bond.
  Builder b;
  std::vector<Index> atoms;
  for (int i = 0; i < 16; ++i)
    atoms.push_back(b.atom(C));
  const int perimeter[14][2] = { { 0, 1 },   { 1, 2 },  { 2, 3 },   { 3, 4 },
                                 { 4, 5 },   { 5, 6 },  { 6, 7 },   { 7, 8 },
                                 { 8, 9 },   { 9, 10 }, { 10, 11 }, { 11, 12 },
                                 { 12, 13 }, { 13, 0 } };
  for (const auto& bond : perimeter)
    b.aromaticBond(atoms[bond[0]], atoms[bond[1]]);
  const int internal[5][2] = {
    { 13, 14 }, { 3, 14 }, { 6, 15 }, { 10, 15 }, { 14, 15 }
  };
  for (const auto& bond : internal)
    b.aromaticBond(atoms[bond[0]], atoms[bond[1]]);
  const bool fusion[16] = { false, false, false, true,  false, false,
                            true,  false, false, false, true,  false,
                            false, true,  true,  true };
  for (int i = 0; i < 16; ++i) {
    if (!fusion[i])
      b.hydrogen(atoms[i]);
  }

  expectKekulizedAndRoundTrips(b);
  EXPECT_EQ(countOrder(b, 2), 8);
  EXPECT_EQ(countOrder(b, 1), 11);
}

// ---------------------------------------------------------------------------
// Failure cases.

TEST(KekulizeTest, oddCarbocycleHasNoPerfectMatching)
{
  // Three CH carbons, all needing a double bond: a triangle can match at
  // most one pair, always leaving one atom uncovered.
  Builder b;
  std::vector<Index> ring;
  for (int i = 0; i < 3; ++i)
    ring.push_back(b.atom(C));
  ringBonds(b, ring);
  for (Index atom : ring)
    b.hydrogen(atom);

  Index failedAtom = MaxIndex;
  EXPECT_FALSE(kekulize(b.mol, b.aromatic, &failedAtom));
  EXPECT_LT(failedAtom, 3u) << "failedAtom should name one of the ring atoms";
}

TEST(KekulizeTest, atomWithNoCandidatePartnerFails)
{
  // atom0 (a CH carbon) has a single aromatic bond, to atom1; atom1 is a
  // carbon whose other three bonds already fill its valence, so it does not
  // need a double bond and atom0 is left with no candidate at all.
  Builder b;
  const Index atom0 = b.atom(C);
  const Index atom1 = b.atom(C);
  b.aromaticBond(atom0, atom1);
  b.hydrogen(atom0);
  for (int i = 0; i < 3; ++i)
    b.hydrogen(atom1);

  Index failedAtom = MaxIndex;
  EXPECT_FALSE(kekulize(b.mol, b.aromatic, &failedAtom));
  EXPECT_EQ(failedAtom, atom0);
}
