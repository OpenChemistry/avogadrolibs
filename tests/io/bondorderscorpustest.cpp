/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bondorderchecks.h"
#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/ringperceiver.h>

#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/mdlformat.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
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
using Avogadro::Io::CjsonFormat;
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

using BondOrderChecks::histogram;
using BondOrderChecks::orderSums;

/**
 * Per-atom order sums that leave out every bond to a metal (and give metals
 * zero): perception does not assign or count metal-ligand bond orders.
 */
std::vector<unsigned int> ligandOrderSums(const Molecule& mol)
{
  std::vector<unsigned int> sums(mol.atomCount(), 0);
  for (Index b = 0; b < mol.bondCount(); ++b) {
    const auto pair = mol.bondPairs()[b];
    if (Elements::isMetal(mol.atomicNumber(pair.first)) ||
        Elements::isMetal(mol.atomicNumber(pair.second)))
      continue;
    sums[pair.first] += mol.bondOrders()[b];
    sums[pair.second] += mol.bondOrders()[b];
  }
  return sums;
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

// ---------------------------------------------------------------------
// Manifest-driven corpus runs.
//
// data/bondorders/known-failures.txt lists the (file, charge mode) pairs that
// perception is expected not to get right, one per line:
//
//   <path relative to data/bondorders>  <charged|neutral|both>
//   <fail|wrong|kekule> <reason ...>
//
// "wrong" means perception claims success but ends with different valences
// from the file (for example when hydrogens are missing); "fail" means
// perception reports failure for part of the molecule and must do so cleanly;
// "kekule" means it succeeds with valid valences but picks a different Kekule
// structure than the reference. Everything not listed has to pass the strict
// ring-level comparison. A listed file that passes is reported but is not an
// error, so the list can shrink as perception improves. "charged" runs with the
// formal charges as stored in the file, "neutral" with all formal charges set
// to zero.

enum class Outcome
{
  Pass,
  Fail,  //!< perception reported failure
  Wrong, //!< perception reported success, but the valences are not the file's
  Kekule //!< valid valences, different Kekule structure
};

struct Evaluation
{
  Outcome outcome = Outcome::Pass;
  std::string detail;
  bool cleanFailure = true;
  std::string cleanDetail;
  std::string note; //!< extra facts for the report, e.g. fullerene bond counts
  double seconds = 0.0;
  std::size_t atoms = 0;
};

struct Expectation
{
  std::string kind;
  std::string reason;
};

std::map<std::string, Expectation> readManifest()
{
  std::map<std::string, Expectation> manifest;
  std::ifstream in(std::string(AVOGADRO_DATA) +
                   "/data/bondorders/known-failures.txt");
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#')
      continue;
    std::istringstream fields(line);
    std::string path, mode, kind, reason;
    fields >> path >> mode >> kind;
    std::getline(fields, reason);
    if (!reason.empty() && reason[0] == ' ')
      reason.erase(0, 1);
    for (const char* m : { "charged", "neutral" }) {
      if (mode == "both" || mode == m)
        manifest[path + " " + m] = { kind, reason };
    }
  }
  return manifest;
}

/** Reads a MDL molfile/SDF or a CJSON file, chosen by extension. */
bool readAny(const std::string& path, Molecule& mol, std::string& error)
{
  if (std::filesystem::path(path).extension() == ".cjson") {
    CjsonFormat cjson;
    const bool ok = cjson.readFile(path, mol);
    error = cjson.error();
    return ok;
  }
  MdlFormat mdl;
  const bool ok = mdl.readFile(path, mol);
  error = mdl.error();
  return ok;
}

unsigned int usualValence(unsigned char z)
{
  if (z == 1)
    return 1;
  if (z == 6)
    return 4;
  return 0;
}

Evaluation evaluate(const std::string& fullPath, bool stripCharges)
{
  Evaluation eval;
  Molecule truth;
  std::string readError;
  if (!readAny(fullPath, truth, readError)) {
    eval.outcome = Outcome::Fail;
    eval.detail = "unreadable: " + readError;
    return eval;
  }
  eval.atoms = truth.atomCount();

  bool anyMultiple = false;
  for (Index b = 0; b < truth.bondCount(); ++b)
    anyMultiple = anyMultiple || truth.bondOrders()[b] > 1;

  // The sums every atom must end with: those of the reference, or, for the
  // carbon systems that come without a reference, carbon 4 and hydrogen 1.
  std::vector<unsigned int> wanted = ligandOrderSums(truth);
  if (!anyMultiple) {
    for (Index a = 0; a < truth.atomCount(); ++a) {
      if (usualValence(truth.atomicNumber(a)) != 0)
        wanted[a] = usualValence(truth.atomicNumber(a));
    }
  }
  std::vector<bool> metal(truth.atomCount(), false);
  for (Index a = 0; a < truth.atomCount(); ++a)
    metal[a] = Elements::isMetal(truth.atomicNumber(a));

  // A molecule of only carbon and hydrogen has no valence to argue about, so
  // for those the sums are carbon 4 and hydrogen 1 whatever the file says. A
  // file whose own bond orders do not add up to that (a few of the small
  // fullerenes have carbons with only three bonds' worth) is then not a
  // usable Kekule reference, and only the valences are checked.
  bool hydrocarbon = true;
  for (Index a = 0; a < truth.atomCount(); ++a) {
    const unsigned char z = truth.atomicNumber(a);
    hydrocarbon = hydrocarbon && (z == 1 || z == 6);
  }
  bool referenceUsable = true;
  if (hydrocarbon) {
    for (Index a = 0; a < truth.atomCount(); ++a)
      wanted[a] = usualValence(truth.atomicNumber(a));
    referenceUsable = (ligandOrderSums(truth) == wanted);
  }

  Molecule mol = truth;
  for (Index b = 0; b < mol.bondCount(); ++b)
    mol.setBondOrder(b, 1);
  if (stripCharges) {
    for (Index a = 0; a < mol.atomCount(); ++a)
      mol.setFormalCharge(a, 0);
  }

  const auto start = std::chrono::steady_clock::now();
  const BondOrderResult result = mol.perceiveBondOrders(BondOrderOptions());
  eval.seconds =
    std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
      .count();

  if (!result.success) {
    eval.outcome = Outcome::Fail;
    std::set<std::string> elements;
    for (Index a : result.failedAtoms) {
      elements.insert(
        Elements::symbol(mol.atomicNumber(a)) +
        std::string(truth.formalCharge(a) != 0 ? "(charged)" : ""));
    }
    for (const std::string& e : elements)
      eval.detail += (eval.detail.empty() ? "" : ",") + e;
    eval.detail += " x" + std::to_string(result.failedAtoms.size());

    // A clean failure: failedAtoms is not empty, and the failed component --
    // which failedAtoms lists in full, since an atom is only listed when it
    // still wanted bond order -- kept every bond at order 1, while the atoms
    // outside it have the valence they should have.
    std::vector<bool> region(mol.atomCount(), false);
    for (Index a : result.failedAtoms)
      region[a] = true;
    eval.cleanFailure = !result.failedAtoms.empty() && !result.message.empty();
    if (!eval.cleanFailure)
      eval.cleanDetail = "no failed atoms or message";
    for (Index b = 0; b < mol.bondCount() && eval.cleanFailure; ++b) {
      const auto pair = mol.bondPairs()[b];
      if (region[pair.first] && region[pair.second] &&
          mol.bondOrders()[b] != 1) {
        eval.cleanFailure = false;
        eval.cleanDetail = "bond changed inside the failed component";
      }
    }
    // An atom outside the failed component can still be short of its
    // reference valence when the atom causing the failure is its neighbour:
    // sulfonyl sulfur, for instance, stays at valence 4 while its oxygens
    // are the failed atoms. Anything further away must be right.
    std::vector<bool> nearFailure = region;
    for (Index b = 0; b < mol.bondCount(); ++b) {
      const auto pair = mol.bondPairs()[b];
      if (region[pair.first])
        nearFailure[pair.second] = true;
      if (region[pair.second])
        nearFailure[pair.first] = true;
    }
    const std::vector<unsigned int> got = ligandOrderSums(mol);
    for (Index a = 0; a < mol.atomCount() && eval.cleanFailure; ++a) {
      if (!nearFailure[a] && got[a] != wanted[a]) {
        eval.cleanFailure = false;
        eval.cleanDetail =
          "atom " + std::to_string(a) + " outside the failure is wrong";
      }
    }
    return eval;
  }

  // Fullerene-like cages: how many double bonds sit in pentagons, for the
  // report. The reference counts as the 6:6 (Fries-type) structure when none
  // of its double bonds do.
  bool referenceIsSixSix = false;
  if (hydrocarbon && anyMultiple && referenceUsable) {
    Molecule ref = truth;
    Avogadro::Core::RingPerceiver perceiver(&ref);
    std::vector<bool> inPentagon(truth.bondCount(), false);
    bool anyPentagon = false;
    for (const auto& ring : perceiver.rings()) {
      if (ring.size() != 5)
        continue;
      anyPentagon = true;
      for (std::size_t i = 0; i < 5; ++i)
        inPentagon[ref.bond(ring[i], ring[(i + 1) % 5]).index()] = true;
    }
    if (anyPentagon) {
      std::size_t refIn = 0, gotIn = 0, doubles = 0;
      for (Index b = 0; b < truth.bondCount(); ++b) {
        if (!inPentagon[b])
          continue;
        refIn += truth.bondOrders()[b] > 1 ? 1 : 0;
        gotIn += mol.bondOrders()[b] > 1 ? 1 : 0;
      }
      for (Index b = 0; b < truth.bondCount(); ++b)
        doubles += mol.bondOrders()[b] > 1 ? 1 : 0;
      referenceIsSixSix = (refIn == 0);
      eval.note = "doubles " + std::to_string(doubles) +
                  ", in pentagons: result " + std::to_string(gotIn) +
                  ", reference " + std::to_string(refIn);
    }
  }

  const std::vector<unsigned int> got = ligandOrderSums(mol);
  if (got != wanted) {
    eval.outcome = Outcome::Wrong;
    eval.detail = "reported success with wrong valences";
    return eval;
  }
  const bool cage = eval.note.size() > 0;
  // A cage's reference is only a reference when it is the 6:6 structure.
  if (anyMultiple && referenceUsable && (!cage || referenceIsSixSix)) {
    const std::string difference =
      BondOrderChecks::strictDifference(truth, mol, &metal);
    if (!difference.empty()) {
      eval.outcome = Outcome::Kekule;
      eval.detail = difference;
    }
  }
  return eval;
}

struct Tally
{
  int passed = 0, knownFailed = 0, unexpectedPass = 0, unexpectedFail = 0;
  double slowest = 0.0;
  std::string slowestName;
};

/** Runs every file with @a extension in @a subdirectory. */
void runCorpus(const std::string& subdirectory, const std::string& extension,
               bool bothChargeModes, bool recursive = false)
{
  const std::map<std::string, Expectation> manifest = readManifest();
  const std::filesystem::path root =
    std::filesystem::path(AVOGADRO_DATA) / "data" / "bondorders";
  const std::filesystem::path dir = root / subdirectory;
  std::vector<std::string> files;
  std::error_code error;
  if (recursive) {
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(dir, error)) {
      if (entry.path().extension() == extension)
        files.push_back(entry.path().lexically_relative(dir).generic_string());
    }
  } else {
    for (const auto& entry : std::filesystem::directory_iterator(dir, error)) {
      if (entry.path().extension() == extension)
        files.push_back(entry.path().filename().string());
    }
  }
  std::sort(files.begin(), files.end());
  ASSERT_FALSE(files.empty()) << dir;

  const char* reportPath = std::getenv("AVOGADRO_BONDORDERS_REPORT");
  std::ofstream report;
  if (reportPath != nullptr)
    report.open(reportPath, std::ios::app);

  Tally tally;
  std::vector<std::string> unexpected;
  for (const std::string& file : files) {
    const std::string relative =
      subdirectory.empty() ? file : subdirectory + "/" + file;
    // The neutral run only differs when the file has formal charges.
    Molecule probe;
    std::string probeError;
    ASSERT_TRUE(readAny((dir / file).string(), probe, probeError))
      << relative << ": " << probeError;
    bool charged = false;
    for (Index a = 0; a < probe.atomCount(); ++a)
      charged = charged || probe.formalCharge(a) != 0;

    std::vector<std::pair<std::string, bool>> modes = { { "charged", false } };
    if (bothChargeModes && charged)
      modes.push_back({ "neutral", true });

    for (const auto& mode : modes) {
      const Evaluation eval = evaluate((dir / file).string(), mode.second);
      const std::string key = relative + " " + mode.first;
      const auto expected = manifest.find(key);
      const char* name =
        eval.outcome == Outcome::Pass
          ? "pass"
          : (eval.outcome == Outcome::Fail
               ? "fail"
               : (eval.outcome == Outcome::Wrong ? "wrong" : "kekule"));
      if (report.is_open()) {
        report << relative << '\t' << mode.first << '\t' << name << '\t'
               << eval.detail << '\t' << eval.atoms << '\t' << eval.seconds
               << '\t' << (eval.cleanFailure ? "clean" : "DIRTY") << '\t'
               << eval.note << '\n';
      }
      if (eval.seconds > tally.slowest) {
        tally.slowest = eval.seconds;
        tally.slowestName = key;
      }

      if (expected == manifest.end()) {
        if (eval.outcome == Outcome::Pass) {
          ++tally.passed;
        } else {
          ++tally.unexpectedFail;
          ADD_FAILURE() << key << ": " << name << " (" << eval.detail << ")";
        }
      } else {
        const bool matches =
          (expected->second.kind == "fail" && eval.outcome == Outcome::Fail) ||
          (expected->second.kind == "wrong" &&
           eval.outcome == Outcome::Wrong) ||
          (expected->second.kind == "kekule" &&
           eval.outcome == Outcome::Kekule);
        if (eval.outcome == Outcome::Pass) {
          ++tally.unexpectedPass;
          unexpected.push_back(key + " (expected " + expected->second.kind +
                               ", passed)");
        } else {
          ++tally.knownFailed;
          if (!matches) {
            unexpected.push_back(key + " (expected " + expected->second.kind +
                                 ", got " + name + ")");
          }
          if (eval.outcome == Outcome::Fail) {
            EXPECT_TRUE(eval.cleanFailure)
              << key << ": not a clean failure: " << eval.cleanDetail;
          }
        }
      }
    }
  }
  std::cout << "[ corpus " << (subdirectory.empty() ? "." : subdirectory)
            << " ] pass " << tally.passed << ", known failure "
            << tally.knownFailed << ", unexpected pass " << tally.unexpectedPass
            << ", unexpected failure " << tally.unexpectedFail << "; slowest "
            << tally.slowestName << " " << tally.slowest << " s\n";
  for (const std::string& line : unexpected)
    std::cout << "[ corpus ]   note: " << line << "\n";
}

} // namespace

TEST(BondOrdersCorpusTest, strictRingComparison)
{
  runCorpus("", ".mol", false);
}

TEST(BondOrdersCorpusTest, heteroaromatics)
{
  runCorpus("hetero", ".mol", false);
}

TEST(BondOrdersCorpusTest, moleculesRepository)
{
  // A selection of the Open Chemistry "molecules" repository (BSD 3-Clause,
  // see data/bondorders/molecules/LICENSE).
  runCorpus("molecules", ".cjson", true, true);
}

TEST(BondOrdersCorpusTest, fullerenesAndNanotubes)
{
  runCorpus("carbon", ".mol", false);
}

TEST(BondOrdersCorpusTest, ccdLigands)
{
  runCorpus("ccd", ".sdf", true);
}

// Developer sweep, not part of the normal run: set
// AVOGADRO_BONDORDERS_SWEEP to a directory and every .cjson/.mol/.sdf below it
// is evaluated (both charge modes), with the result appended as a table to
// AVOGADRO_BONDORDERS_REPORT. Nothing is asserted.
TEST(BondOrdersCorpusTest, sweepExternalDirectory)
{
  const char* sweep = std::getenv("AVOGADRO_BONDORDERS_SWEEP");
  const char* reportPath = std::getenv("AVOGADRO_BONDORDERS_REPORT");
  if (sweep == nullptr || reportPath == nullptr)
    GTEST_SKIP() << "set AVOGADRO_BONDORDERS_SWEEP and ..._REPORT";
  std::ofstream report(reportPath, std::ios::app);
  std::vector<std::string> files;
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(sweep)) {
    const std::string ext = entry.path().extension().string();
    if (ext == ".cjson" || ext == ".mol" || ext == ".sdf")
      files.push_back(entry.path().string());
  }
  std::sort(files.begin(), files.end());
  for (const std::string& file : files) {
    Molecule probe;
    std::string error;
    if (!readAny(file, probe, error))
      continue;
    bool charged = false;
    for (Index a = 0; a < probe.atomCount(); ++a)
      charged = charged || probe.formalCharge(a) != 0;
    for (bool strip : { false, true }) {
      if (strip && !charged)
        continue;
      const Evaluation eval = evaluate(file, strip);
      const char* name =
        eval.outcome == Outcome::Pass
          ? "pass"
          : (eval.outcome == Outcome::Fail
               ? "fail"
               : (eval.outcome == Outcome::Wrong ? "wrong" : "kekule"));
      report << std::filesystem::path(file).lexically_relative(sweep).string()
             << '\t' << (strip ? "neutral" : "charged") << '\t' << name << '\t'
             << eval.detail << '\t' << eval.atoms << '\t' << eval.seconds
             << '\t' << (eval.cleanFailure ? "clean" : "DIRTY") << '\t'
             << eval.note << '\n';
    }
  }
}

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
