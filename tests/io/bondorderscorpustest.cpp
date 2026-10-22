/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

#include <avogadro/io/mdlformat.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <numeric>
#include <random>
#include <string>
#include <vector>

using Avogadro::Index;
using Avogadro::Core::BondOrderOptions;
using Avogadro::Core::BondOrderResult;
using Avogadro::Core::Elements;
using Avogadro::Core::Molecule;
using Avogadro::Io::MdlFormat;

namespace {

// The corpus lives in avogadrodata/data/bondorders: neutral closed-shell
// organics with explicit hydrogens, 3D coordinates and Kekule bond orders.
// The tests below throw the orders away and ask perception to find them
// again. Aromatic systems have more than one valid Kekule structure, so the
// comparison is "up to resonance": every atom must end with the same order
// sum as in the file, and the molecule must have the same number of single,
// double and triple bonds.

std::vector<std::string> corpusFiles()
{
  std::vector<std::string> files;
  const std::filesystem::path dir =
    std::filesystem::path(AVOGADRO_DATA) / "data" / "bondorders";
  std::error_code error;
  for (const auto& entry : std::filesystem::directory_iterator(dir, error)) {
    if (entry.path().extension() == ".mol")
      files.push_back(entry.path().string());
  }
  std::sort(files.begin(), files.end());
  return files;
}

std::vector<unsigned int> orderSums(const Molecule& mol)
{
  std::vector<unsigned int> sums(mol.atomCount(), 0);
  for (Index b = 0; b < mol.bondCount(); ++b) {
    sums[mol.bondPairs()[b].first] += mol.bondOrders()[b];
    sums[mol.bondPairs()[b].second] += mol.bondOrders()[b];
  }
  return sums;
}

std::map<unsigned int, std::size_t> histogram(const Molecule& mol)
{
  std::map<unsigned int, std::size_t> counts;
  for (Index b = 0; b < mol.bondCount(); ++b)
    ++counts[mol.bondOrders()[b]];
  return counts;
}

/** Every order is 1 to 3 and every bond to H or a halogen is single. */
void expectSaneOrders(const Molecule& mol, const std::string& name)
{
  for (Index b = 0; b < mol.bondCount(); ++b) {
    const unsigned int order = mol.bondOrders()[b];
    EXPECT_GE(order, 1u) << name;
    EXPECT_LE(order, 3u) << name;
    for (Index end : { mol.bondPairs()[b].first, mol.bondPairs()[b].second }) {
      const unsigned char z = mol.atomicNumber(end);
      if (z == 1 || z == 9 || z == 17 || z == 35 || z == 53)
        EXPECT_EQ(order, 1u) << name << " bond " << b;
    }
  }
}

/** A copy of @a source with atoms and bonds in a random order, all single. */
Molecule shuffledSingle(const Molecule& source, unsigned int seed)
{
  std::mt19937 rng(seed);
  std::vector<Index> perm(source.atomCount());
  std::iota(perm.begin(), perm.end(), Index(0));
  std::shuffle(perm.begin(), perm.end(), rng);
  std::vector<Index> newIndex(perm.size());
  Molecule result;
  for (std::size_t i = 0; i < perm.size(); ++i) {
    newIndex[perm[i]] = i;
    result.addAtom(source.atomicNumber(perm[i]))
      .setPosition3d(source.atomPosition3d(perm[i]));
  }
  std::vector<Index> bondOrder(source.bondCount());
  std::iota(bondOrder.begin(), bondOrder.end(), Index(0));
  std::shuffle(bondOrder.begin(), bondOrder.end(), rng);
  for (Index b : bondOrder) {
    result.addBond(newIndex[source.bondPairs()[b].first],
                   newIndex[source.bondPairs()[b].second], 1);
  }
  return result;
}

} // namespace

TEST(BondOrdersCorpusTest, corpusIsPresent)
{
  EXPECT_GE(corpusFiles().size(), 45u);
}

TEST(BondOrdersCorpusTest, perceiveUpToResonance)
{
  for (const std::string& path : corpusFiles()) {
    MdlFormat mdl;
    Molecule truth;
    ASSERT_TRUE(mdl.readFile(path, truth)) << path << ": " << mdl.error();
    const std::string name = std::filesystem::path(path).stem().string();

    for (bool useGeometry : { true, false }) {
      Molecule mol = truth;
      for (Index b = 0; b < mol.bondCount(); ++b)
        mol.setBondOrder(b, 1);
      BondOrderOptions options;
      options.useGeometry = useGeometry;
      const BondOrderResult result = mol.perceiveBondOrders(options);
      EXPECT_TRUE(result.success) << name << ": " << result.message;
      EXPECT_EQ(orderSums(mol), orderSums(truth)) << name;
      EXPECT_EQ(histogram(mol), histogram(truth)) << name;
      expectSaneOrders(mol, name);
    }
  }
}

TEST(BondOrdersCorpusTest, permutedAtomOrderGivesSameResultUpToResonance)
{
  for (const std::string& path : corpusFiles()) {
    MdlFormat mdl;
    Molecule truth;
    ASSERT_TRUE(mdl.readFile(path, truth)) << path << ": " << mdl.error();
    const std::string name = std::filesystem::path(path).stem().string();

    for (unsigned int seed = 1; seed <= 20; ++seed) {
      Molecule mol = shuffledSingle(truth, seed);
      const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
      EXPECT_TRUE(result.success)
        << name << " seed " << seed << ": " << result.message;
      EXPECT_EQ(histogram(mol), histogram(truth)) << name << " seed " << seed;
      // Order sums follow the elements: the same multiset as the original.
      std::vector<unsigned int> got = orderSums(mol);
      std::vector<unsigned int> want = orderSums(truth);
      std::sort(got.begin(), got.end());
      std::sort(want.begin(), want.end());
      EXPECT_EQ(got, want) << name << " seed " << seed;
      expectSaneOrders(mol, name);
    }
  }
}
