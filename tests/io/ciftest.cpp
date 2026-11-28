/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/io/cifformat.h>
#include <avogadro/io/cifsymmetry.h>
#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <gemmi/cif.hpp>

#include <cmath>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using Avogadro::Vector3;
using Avogadro::Core::Molecule;
using Avogadro::Core::SpaceGroups;
using Avogadro::Core::UnitCell;
using Avogadro::Io::CifFormat;
using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;

namespace cif = gemmi::cif;

// The MemorySanitizer CI job cannot run a test that throws: the first throw
// dies as "stack-overflow" inside its instrumented unwinder, and gemmi throws
// on a syntax error. Those cases are left out there. See the note in
// .github/workflows/msan_linux.yml.
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define AVOGADRO_MSAN_BUILD 1
#endif
#endif
#ifndef AVOGADRO_MSAN_BUILD
#define AVOGADRO_MSAN_BUILD 0
#endif

namespace {

std::string readText(const std::string& path)
{
  std::ifstream in(path, std::ios::binary);
  std::stringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

std::string codFile(const std::string& id)
{
  return std::string(AVOGADRO_DATA) + "/data/cif/" + id + ".cif";
}

// A CIF with a 20 angstrom cubic cell and the given loop of atoms.
std::string cubicCif(const std::string& columns, const std::string& rows,
                     const std::string& extra = std::string())
{
  return "data_test\n_cell_length_a 20.0\n_cell_length_b 20.0\n"
         "_cell_length_c 20.0\n_cell_angle_alpha 90\n_cell_angle_beta 90\n"
         "_cell_angle_gamma 90\n" +
         extra + "loop_\n" + columns + rows;
}

// A format that stands in for the Open Babel plugin, which is not part of IO.
class FakeOpenBabel : public FileFormat
{
public:
  explicit FakeOpenBabel(bool* called = nullptr, bool succeed = true)
    : m_called(called), m_succeed(succeed)
  {
  }

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }
  FileFormat* newInstance() const override
  {
    return new FakeOpenBabel(m_called, m_succeed);
  }
  std::string identifier() const override { return "OpenBabel: Fake CIF"; }
  std::string name() const override { return "Fake CIF"; }
  std::string description() const override { return "A test-only format."; }
  std::string specificationUrl() const override { return ""; }
  std::vector<std::string> fileExtensions() const override { return { "cif" }; }
  std::vector<std::string> mimeTypes() const override { return {}; }

  bool read(std::istream& in, Molecule& molecule) override
  {
    if (m_called != nullptr)
      *m_called = true;
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    // the delegate is handed the whole file
    molecule.setData("delegateBytes", static_cast<int>(text.size()));
    if (!m_succeed) {
      appendError("fake failure");
      return false;
    }
    molecule.addAtom(6);
    return true;
  }
  bool write(std::ostream&, const Molecule&) override { return false; }

private:
  bool* m_called;
  bool m_succeed;
};

// Registers a fake Open Babel for the life of the object.
struct ScopedFakeOpenBabel
{
  explicit ScopedFakeOpenBabel(bool* called, bool succeed = true)
  {
    registered =
      FileFormatManager::registerFormat(new FakeOpenBabel(called, succeed));
  }
  ~ScopedFakeOpenBabel()
  {
    if (registered)
      FileFormatManager::unregisterFormat("OpenBabel: Fake CIF");
  }
  bool registered = false;
};

// The atoms of a file as the file lists them, found with gemmi: label ->
// (disorder assembly, disorder group).
std::map<std::string, std::pair<std::string, std::string>> disorderOf(
  const std::string& path)
{
  std::map<std::string, std::pair<std::string, std::string>> result;
  cif::Document doc = cif::read_file(path);
  cif::Table table = doc.sole_block().find(
    "_atom_site_", { "label", "?disorder_assembly", "?disorder_group" });
  for (auto row : table) {
    result[row[0]] = { row.has(1) ? row[1] : ".", row.has(2) ? row[2] : "." };
  }
  return result;
}

bool bonded(const Molecule& molecule, const std::string& a,
            const std::string& b)
{
  std::size_t ia = molecule.atomCount();
  std::size_t ib = molecule.atomCount();
  for (std::size_t i = 0; i < molecule.atomCount(); ++i) {
    if (molecule.atomLabel(i) == a)
      ia = i;
    if (molecule.atomLabel(i) == b)
      ib = i;
  }
  if (ia == molecule.atomCount() || ib == molecule.atomCount())
    return false;
  return molecule.bond(ia, ib).isValid();
}

} // namespace

TEST(CifTest, identity)
{
  EXPECT_TRUE(CifFormat().supportedOperations() & FileFormat::Write);
  CifFormat format;
  EXPECT_EQ(format.identifier(), "Avogadro: CIF");
  EXPECT_EQ(format.name(), "CIF");
  EXPECT_EQ(format.fileExtensions(), std::vector<std::string>{ "cif" });
  EXPECT_EQ(format.mimeTypes(), std::vector<std::string>{ "chemical/x-cif" });
  EXPECT_TRUE(format.supportedOperations() & FileFormat::Read);
  EXPECT_TRUE(format.supportedOperations() & FileFormat::Stream);
  EXPECT_TRUE(format.supportedOperations() & FileFormat::String);
}

TEST(CifTest, readCodFile)
{
  CifFormat format;
  Molecule molecule;
  ASSERT_TRUE(format.readFile(codFile("1100686"), molecule)) << format.error();

  // every row of the atom loop, and no atom that symmetry would add
  cif::Document doc = cif::read_file(codFile("1100686"));
  const cif::Table rows =
    doc.sole_block().find("_atom_site_", { "label", "fract_x" });
  ASSERT_TRUE(rows.ok());
  EXPECT_EQ(molecule.atomCount(), rows.length());

  // the space group follows the operations of the file
  const auto symmetry =
    Avogadro::Io::readCifSymmetry(readText(codFile("1100686")));
  ASSERT_NE(symmetry.hallFromOperations, 0);
  EXPECT_EQ(molecule.hallNumber(), symmetry.hallFromOperations);

  // the cell, in angstrom and radians
  const UnitCell* cell = molecule.unitCell();
  ASSERT_NE(cell, nullptr);
  EXPECT_NEAR(cell->a(), 5.2095, 1e-6);
  EXPECT_NEAR(cell->b(), 14.1845, 1e-6);
  EXPECT_NEAR(cell->c(), 6.0638, 1e-6);
  EXPECT_NEAR(cell->alpha(), 90.0 * Avogadro::DEG_TO_RAD, 1e-6);
  EXPECT_NEAR(cell->beta(), 101.545 * Avogadro::DEG_TO_RAD, 1e-6);
  EXPECT_NEAR(cell->gamma(), 90.0 * Avogadro::DEG_TO_RAD, 1e-6);

  // the first atom: N1 at 0.2475 0.57512 0.6820
  EXPECT_EQ(molecule.atomicNumber(0), 7);
  EXPECT_EQ(molecule.atomLabel(0), "N1");
  const Vector3 expected = cell->toCartesian(Vector3(0.2475, 0.57512, 0.6820));
  EXPECT_NEAR((molecule.atomPosition3d(0) - expected).norm(), 0.0, 1e-9);
  EXPECT_EQ(molecule.atomLabel(4), "H4A");
  EXPECT_EQ(molecule.atomicNumber(4), 1);

  // bonds were perceived
  EXPECT_GT(molecule.bondCount(), 0u);
}

TEST(CifTest, readFromStringAndStream)
{
  const std::string text = readText(codFile("1100686"));
  Molecule fromString;
  CifFormat format;
  ASSERT_TRUE(format.readString(text, fromString)) << format.error();

  Molecule fromStream;
  std::istringstream stream(text);
  CifFormat other;
  ASSERT_TRUE(other.read(stream, fromStream)) << other.error();
  EXPECT_EQ(fromString.atomCount(), fromStream.atomCount());
  EXPECT_EQ(fromString.hallNumber(), fromStream.hallNumber());

  // and through the manager
  Molecule fromManager;
  EXPECT_TRUE(
    FileFormatManager::instance().readString(fromManager, text, "cif"));
  EXPECT_EQ(fromManager.atomCount(), fromString.atomCount());
}

TEST(CifTest, moleculeName)
{
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(
    cubicCif("_atom_site_label\n_atom_site_fract_x\n_atom_site_fract_y\n"
             "_atom_site_fract_z\nC1 0.1 0.1 0.1\n",
             "", "_chemical_name_common 'ethane'\n"),
    molecule));
  EXPECT_EQ(molecule.data("name").toString(), "ethane");

  Molecule unnamed;
  CifFormat other;
  ASSERT_TRUE(other.readString(
    cubicCif("_atom_site_label\n_atom_site_fract_x\n_atom_site_fract_y\n"
             "_atom_site_fract_z\nC1 0.1 0.1 0.1\n",
             ""),
    unnamed));
  EXPECT_EQ(unnamed.data("name").toString(), "test");
}

TEST(CifTest, untabulatedOperationsAreKeptOnTheMolecule)
{
  // A-1, I-1 and F-1 settings are in no table entry: the reader keeps the
  // asymmetric unit and the operations of the file instead of a Hall number.
  for (const char* id : { "7006564", "7011106", "2019269", "2311997" }) {
    SCOPED_TRACE(id);
    Molecule molecule;
    CifFormat format;
    ASSERT_TRUE(format.readFile(codFile(id), molecule)) << format.error();
    EXPECT_EQ(molecule.hallNumber(), 0);
    EXPECT_FALSE(molecule.hasData(SpaceGroups::internationalNumberKey()));

    const auto symmetry = Avogadro::Io::readCifSymmetry(readText(codFile(id)));
    ASSERT_TRUE(symmetry.hasUntabulatedOperations());
    EXPECT_FALSE(symmetry.name.empty());
    EXPECT_EQ(SpaceGroups::storedOperations(molecule), symmetry.operations);
    EXPECT_EQ(molecule.data(SpaceGroups::fileNameKey()).toString(),
              symmetry.name);

    // the atoms read are the atoms of the asymmetric unit
    cif::Document doc = cif::read_file(codFile(id));
    cif::Table rows = doc.sole_block().find(
      "_atom_site_", { "label", "fract_x", "fract_y", "fract_z" });
    ASSERT_TRUE(rows.ok());
    std::size_t sites = 0;
    for (auto row : rows) {
      (void)row;
      ++sites;
    }
    EXPECT_EQ(molecule.atomCount(), sites);

    // and the operations expand them
    Molecule filled(molecule);
    ASSERT_TRUE(SpaceGroups::fillUnitCellFromOperations(
      filled, SpaceGroups::storedOperations(molecule), 0.25));
    EXPECT_GT(filled.atomCount(), molecule.atomCount());
    EXPECT_EQ(filled.hallNumber(), 0);
    EXPECT_FALSE(SpaceGroups::storedOperations(filled).empty());

    // 2311997 is '-B 1': 148 atoms in the file, 592 once the cell is filled
    if (std::string(id) == "2311997") {
      EXPECT_EQ(molecule.atomCount(), 148u);
      EXPECT_EQ(SpaceGroups::storedOperations(molecule).size(), 4u);
      EXPECT_EQ(filled.atomCount(), 592u);
    }
  }
}

TEST(CifTest, disorderGroupsOfTheSameAssemblyAreNotBonded)
{
  const std::string path = codFile("2017715");
  Molecule molecule;
  CifFormat format;
  format.setOptions(R"({"disorder": "all"})");
  ASSERT_TRUE(format.readFile(path, molecule)) << format.error();
  ASSERT_GT(molecule.bondCount(), 0u);

  const auto disorder = disorderOf(path);
  auto isSet = [](const std::string& group) {
    return group != "." && group != "?" && group != "0";
  };

  std::size_t alternatives = 0;
  for (const auto& pair : molecule.bondPairs()) {
    const auto& a = disorder.at(molecule.atomLabel(pair.first));
    const auto& b = disorder.at(molecule.atomLabel(pair.second));
    if (isSet(a.second) && isSet(b.second) && a.second != b.second &&
        a.first == b.first)
      ++alternatives;
  }
  EXPECT_EQ(alternatives, 0u);

  // atoms of the same group (and ordered atoms) are still bonded
  EXPECT_TRUE(bonded(molecule, "C7A", "H71A"));
  EXPECT_TRUE(bonded(molecule, "C71A", "H72A"));
  EXPECT_TRUE(bonded(molecule, "C1A", "C6A"));
}

namespace {
const char* const siteColumns =
  "_atom_site_label\n_atom_site_type_symbol\n_atom_site_fract_x\n"
  "_atom_site_fract_y\n_atom_site_fract_z\n";
} // namespace

TEST(CifTest, disorderRule)
{
  // three carbon atoms in a row, 1.4 angstrom apart: C3 - C1 - C2
  const std::string rows =
    "C1 C 0.5 0.5 0.5\nC2 C 0.57 0.5 0.5\nC3 C 0.43 0.5 0.5\n";
  auto read = [&](const std::string& assembly, const std::string& groups) {
    // the columns come in the order of the rows' extra values
    std::string text =
      cubicCif(std::string(siteColumns) +
                 "_atom_site_disorder_assembly\n_atom_site_disorder_group\n",
               rows);
    // append the disorder values to each row
    std::istringstream in(text);
    std::string line, result;
    int atom = 0;
    std::istringstream groupList(groups);
    std::vector<std::string> g;
    for (std::string item; groupList >> item;)
      g.push_back(item);
    std::istringstream assemblyList(assembly);
    std::vector<std::string> a;
    for (std::string item; assemblyList >> item;)
      a.push_back(item);
    while (std::getline(in, line)) {
      if (line.rfind("C", 0) == 0 && line.size() > 2 && line[2] == ' ') {
        line += " " + a[atom] + " " + g[atom];
        ++atom;
      }
      result += line + "\n";
    }
    Molecule molecule;
    CifFormat format;
    format.setOptions(R"({"disorder": "all"})");
    EXPECT_TRUE(format.readString(result, molecule)) << format.error();
    return molecule;
  };

  // different groups, one implicit assembly: C1 and C2 are alternatives
  Molecule molecule = read(". . .", "1 2 .");
  EXPECT_FALSE(bonded(molecule, "C1", "C2"));
  EXPECT_TRUE(bonded(molecule, "C1", "C3"));

  // the same group
  molecule = read(". . .", "1 1 .");
  EXPECT_TRUE(bonded(molecule, "C1", "C2"));

  // different explicit assemblies
  molecule = read("A B .", "1 2 .");
  EXPECT_TRUE(bonded(molecule, "C1", "C2"));

  // the same explicit assembly
  molecule = read("A A .", "1 2 .");
  EXPECT_FALSE(bonded(molecule, "C1", "C2"));

  // a group of 0, ? or . means the atom is not disordered
  molecule = read(". . .", "1 0 .");
  EXPECT_TRUE(bonded(molecule, "C1", "C2"));
  molecule = read(". . .", "1 ? .");
  EXPECT_TRUE(bonded(molecule, "C1", "C2"));

  // groups are strings: negative and non-integer ones too
  molecule = read(". . .", "-1 1 .");
  EXPECT_FALSE(bonded(molecule, "C1", "C2"));
  molecule = read(". . .", "a b .");
  EXPECT_FALSE(bonded(molecule, "C1", "C2"));
}

TEST(CifTest, geomBondLoop)
{
  // C1 and C2 are alternatives, so they are not bonded by distance, but the
  // file lists the bond; C4 is far away.
  const std::string rows =
    "C1 C 0.5 0.5 0.5 1\nC2 C 0.57 0.5 0.5 2\nC3 C 0.43 0.5 0.5 .\n"
    "C4 C 0.1 0.1 0.1 .\n";
  const std::string columns =
    std::string(siteColumns) + "_atom_site_disorder_group\n";

  auto read = [&](const std::string& bondRows) {
    Molecule molecule;
    CifFormat format;
    format.setOptions(R"({"disorder": "all"})");
    EXPECT_TRUE(format.readString(
      cubicCif(columns, rows, "") +
        "loop_\n_geom_bond_atom_site_label_1\n"
        "_geom_bond_atom_site_label_2\n"
        "_geom_bond_site_symmetry_1\n_geom_bond_site_symmetry_2\n" +
        bondRows,
      molecule));
    return molecule;
  };
  // note: the loop above must follow the atom loop
  Molecule molecule =
    read("C1 C2 . 1_555\nC1 C4 . 2_655\nC3 C4 ? ?\nC1 Zz . .\n");
  EXPECT_TRUE(bonded(molecule, "C1", "C2"));  // from the file
  EXPECT_FALSE(bonded(molecule, "C1", "C4")); // across a symmetry operation
  EXPECT_TRUE(bonded(molecule, "C3", "C4"));  // "?" codes mean none
  EXPECT_TRUE(bonded(molecule, "C1", "C3"));  // by distance

  // without a symmetry column
  Molecule plain;
  CifFormat format;
  format.setOptions(R"({"disorder": "all"})");
  ASSERT_TRUE(format.readString(
    cubicCif(columns, rows) +
      "loop_\n_geom_bond_atom_site_label_1\n_geom_bond_atom_site_label_2\n"
      "C1 C4\n",
    plain));
  EXPECT_TRUE(bonded(plain, "C1", "C4"));
}

TEST(CifTest, elementsFromTypeSymbols)
{
  const std::string rows =
    "A1 O2- 0.1 0.1 0.1\nA2 Fe3+ 0.2 0.2 0.2\nA3 Cu1+ 0.3 0.3 0.3\n"
    "A4 Cl- 0.4 0.4 0.4\nA5 D 0.5 0.5 0.5\nA6 T 0.6 0.6 0.6\n"
    "A7 Zz 0.7 0.7 0.7\nA8 FE 0.8 0.8 0.8\nA9 Q 0.9 0.9 0.9\n"
    "B1 X 0.15 0.15 0.15\nB2 Du 0.25 0.25 0.25\nB3 Zr4+ 0.35 0.35 0.35\n";
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(cubicCif(siteColumns, rows), molecule))
    << format.error();

  // A7 "Zz" is not an element and its label does not say either: dropped, as
  // are the dummy atoms Q, X and Du
  ASSERT_EQ(molecule.atomCount(), 8u);
  EXPECT_EQ(molecule.atomicNumber(0), 8);
  EXPECT_EQ(molecule.atomicNumber(1), 26);
  EXPECT_EQ(molecule.atomicNumber(2), 29);
  EXPECT_EQ(molecule.atomicNumber(3), 17);
  EXPECT_EQ(molecule.atomicNumber(4), 1);
  EXPECT_EQ(molecule.atom(4).isotope(), 2);
  EXPECT_EQ(molecule.atomicNumber(5), 1);
  EXPECT_EQ(molecule.atom(5).isotope(), 3);
  EXPECT_EQ(molecule.atomicNumber(6), 26); // "FE"
  EXPECT_EQ(molecule.atomicNumber(7), 40);
  EXPECT_EQ(molecule.atomLabel(7), "B3");
  EXPECT_EQ(molecule.atomLabel(6), "A8");
}

TEST(CifTest, elementsFromLabels)
{
  const std::string rows =
    "Cl1 0.1 0.1 0.1\nC12 0.2 0.2 0.2\nFe1 0.3 0.3 0.3\nO1W 0.4 0.4 0.4\n"
    "Na1 0.5 0.5 0.5\nH1A 0.6 0.6 0.6\nCa2 0.7 0.7 0.7\nN3 0.8 0.8 0.8\n"
    "Q1 0.9 0.9 0.9\n";
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(
    cubicCif("_atom_site_label\n_atom_site_fract_x\n_atom_site_fract_y\n"
             "_atom_site_fract_z\n",
             rows),
    molecule))
    << format.error();
  ASSERT_EQ(molecule.atomCount(), 8u); // Q1 is not an element
  const unsigned char expected[] = { 17, 6, 26, 8, 11, 1, 20, 7 };
  for (std::size_t i = 0; i < 8; ++i)
    EXPECT_EQ(molecule.atomicNumber(i), expected[i]) << i;
}

TEST(CifTest, dummyCalcFlagAndMissingCoordinates)
{
  const std::string rows = "C1 C 0.1 0.1 0.1 d\n"
                           "C2 C 0.2 0.2 0.2 dum\n" // codespell:ignore dum
                           "C3 C ? 0.3 0.3 d\n"
                           "C4 C 0.4 . 0.4 d\n"
                           "C5 C 0.5 0.5 0.5 calc\n";
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(
    cubicCif(std::string(siteColumns) + "_atom_site_calc_flag\n", rows),
    molecule))
    << format.error();
  ASSERT_EQ(molecule.atomCount(), 2u);
  EXPECT_EQ(molecule.atomLabel(0), "C1");
  EXPECT_EQ(molecule.atomLabel(1), "C5");

  // nothing usable left: no atom, and no other reader to try
  Molecule empty;
  CifFormat other;
  EXPECT_FALSE(other.readString(
    cubicCif(siteColumns, "Q1 Q 0.1 0.1 0.1\nC2 C ? ? ?\n"), empty));
  EXPECT_FALSE(other.error().empty());
}

TEST(CifTest, standardUncertainties)
{
  const std::string text =
    "data_test\n_cell_length_a 10.000(3)\n_cell_length_b 11.0(12)\n"
    "_cell_length_c 12\n_cell_angle_alpha 90.00(1)\n_cell_angle_beta 100.5(2)\n"
    "_cell_angle_gamma 90\nloop_\n_atom_site_label\n_atom_site_type_symbol\n"
    "_atom_site_fract_x\n_atom_site_fract_y\n_atom_site_fract_z\n"
    "C1 C 0.25000(15) -0.5(1) 0.125\n";
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(text, molecule)) << format.error();
  const UnitCell* cell = molecule.unitCell();
  ASSERT_NE(cell, nullptr);
  EXPECT_NEAR(cell->a(), 10.0, 1e-9);
  EXPECT_NEAR(cell->b(), 11.0, 1e-9);
  EXPECT_NEAR(cell->beta(), 100.5 * Avogadro::DEG_TO_RAD, 1e-9);
  const Vector3 frac = cell->toFractional(molecule.atomPosition3d(0));
  EXPECT_NEAR(frac.x(), 0.25, 1e-9);
  EXPECT_NEAR(frac.y(), -0.5, 1e-9);
  EXPECT_NEAR(frac.z(), 0.125, 1e-9);
}

TEST(CifTest, dottedTags)
{
  const std::string text = R"CIF(data_ddlm
_cell.length_a 8.0
_cell.length_b 9.0
_cell.length_c 10.0
_cell.angle_alpha 90
_cell.angle_beta 90
_cell.angle_gamma 90
_space_group.name_H-M_alt 'P -1'
loop_
_space_group_symop.id
_space_group_symop.operation_xyz
1 x,y,z
2 -x,-y,-z
loop_
_atom_site.label
_atom_site.type_symbol
_atom_site.fract_x
_atom_site.fract_y
_atom_site.fract_z
C1 C 0.10 0.10 0.10
C2 C 0.20 0.10 0.10
loop_
_geom_bond.atom_site_label_1
_geom_bond.atom_site_label_2
C1 C2
)CIF";
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(text, molecule)) << format.error();
  ASSERT_EQ(molecule.atomCount(), 2u);
  EXPECT_EQ(molecule.hallNumber(), 2);
  EXPECT_NEAR(molecule.unitCell()->c(), 10.0, 1e-9);
  EXPECT_TRUE(bonded(molecule, "C1", "C2"));
}

TEST(CifTest, spaceGroupNameWhenThereAreNoOperations)
{
  const std::string text =
    cubicCif(siteColumns, "C1 C 0.1 0.1 0.1\n",
             "_symmetry_space_group_name_H-M 'P 21/c'\n");
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(text, molecule)) << format.error();
  EXPECT_EQ(molecule.hallNumber(), SpaceGroups::hallNumber("P 21/c"));
  EXPECT_NE(molecule.hallNumber(), 0);

  // an international table number alone
  Molecule numbered;
  CifFormat other;
  ASSERT_TRUE(other.readString(
    cubicCif(siteColumns, "C1 C 0.1 0.1 0.1\n", "_space_group_IT_number 2\n"),
    numbered));
  EXPECT_EQ(numbered.hallNumber(), 2);

  // a Hall symbol
  Molecule hall;
  CifFormat third;
  ASSERT_TRUE(third.readString(cubicCif(siteColumns, "C1 C 0.1 0.1 0.1\n",
                                        "_space_group_name_Hall '-P 2ybc'\n"),
                               hall));
  EXPECT_EQ(hall.hallNumber(), SpaceGroups::hallNumber("-P 2ybc"));
}

TEST(CifTest, mmcifIsHandedToAnotherReader)
{
  bool called = false;
  ScopedFakeOpenBabel fake(&called);
  ASSERT_TRUE(fake.registered);

  Molecule molecule;
  CifFormat format;
  const std::string path = std::string(AVOGADRO_DATA) + "/data/gemmi/5i55.cif";
  ASSERT_TRUE(format.readFile(path, molecule)) << format.error();
  EXPECT_TRUE(called);
  // the delegate got the whole file, and made the molecule
  EXPECT_EQ(molecule.atomCount(), 1u);
  EXPECT_EQ(molecule.data("delegateBytes").toInt(),
            static_cast<int>(readText(path).size()));
}

TEST(CifTest, unusableCellOrAtomsAreHandedToAnotherReader)
{
  bool called = false;
  ScopedFakeOpenBabel fake(&called);
  ASSERT_TRUE(fake.registered);

  const std::string atoms = "C1 C 0.1 0.1 0.1\n";
  // an angle of 200 degrees, a missing length and no usable atom
  const std::string badCells[] = {
    "data_a\n_cell_length_a 5\n_cell_length_b 5\n_cell_length_c 5\n"
    "_cell_angle_alpha 90\n_cell_angle_beta 200\n_cell_angle_gamma 90\n",
    "data_b\n_cell_length_a 5\n_cell_length_b 5\n"
    "_cell_angle_alpha 90\n_cell_angle_beta 90\n_cell_angle_gamma 90\n",
    "data_c\n_cell_length_a 5\n_cell_length_b 5\n_cell_length_c -5\n"
    "_cell_angle_alpha 90\n_cell_angle_beta 90\n_cell_angle_gamma 90\n"
  };
  for (const std::string& cell : badCells) {
    called = false;
    Molecule molecule;
    CifFormat format;
    EXPECT_TRUE(
      format.readString(cell + "loop_\n" + siteColumns + atoms, molecule))
      << format.error();
    EXPECT_TRUE(called) << cell;
  }

  called = false;
  Molecule molecule;
  CifFormat format;
  EXPECT_TRUE(
    format.readString(cubicCif(siteColumns, "Q1 Q 0.1 0.1 0.1\n"), molecule));
  EXPECT_TRUE(called);
}

TEST(CifTest, failingDelegateErrorIsReported)
{
  ScopedFakeOpenBabel fake(nullptr, false);
  ASSERT_TRUE(fake.registered);
  Molecule molecule;
  CifFormat format;
  EXPECT_FALSE(format.readString("data_x\n_cell_length_a 5\n", molecule));
  EXPECT_NE(format.error().find("fake failure"), std::string::npos);
}

TEST(CifTest, noOtherReaderIsAnError)
{
  // the native format alone: an mmCIF cannot be read
  Molecule molecule;
  CifFormat format;
  const std::string path = std::string(AVOGADRO_DATA) + "/data/gemmi/5i55.cif";
  EXPECT_FALSE(format.readFile(path, molecule));
  EXPECT_FALSE(format.error().empty());
  EXPECT_EQ(molecule.atomCount(), 0u);
}

namespace {

// The atoms of @p b match those of @p a: the same element within 1e-4
// angstrom, up to lattice translations.
void expectSameAtoms(const Molecule& a, const Molecule& b)
{
  ASSERT_EQ(a.atomCount(), b.atomCount());
  const UnitCell* cell = a.unitCell();
  ASSERT_NE(cell, nullptr);
  std::vector<bool> used(b.atomCount(), false);
  for (std::size_t i = 0; i < a.atomCount(); ++i) {
    bool found = false;
    for (std::size_t j = 0; j < b.atomCount() && !found; ++j) {
      if (used[j] || a.atomicNumber(i) != b.atomicNumber(j))
        continue;
      Vector3 delta =
        cell->toFractional(a.atomPosition3d(i) - b.atomPosition3d(j));
      delta -= delta.array().round().matrix();
      if (cell->toCartesian(delta).norm() < 1e-4) {
        used[j] = found = true;
      }
    }
    EXPECT_TRUE(found) << "atom " << i << " has no match";
  }
}

Molecule triclinicMolecule()
{
  Molecule molecule;
  molecule.setUnitCell(new UnitCell(7.1, 8.3, 9.7, 80.0 * Avogadro::DEG_TO_RAD,
                                    95.0 * Avogadro::DEG_TO_RAD,
                                    105.0 * Avogadro::DEG_TO_RAD));
  const UnitCell* cell = molecule.unitCell();
  struct Entry
  {
    unsigned char element;
    Vector3 fractional;
    const char* label;
  };
  const Entry entries[] = { { 6, Vector3(0.10, 0.20, 0.30), "C1" },
                            { 6, Vector3(1.25, -0.30, 0.50), "C1" }, // outside
                            { 8, Vector3(0.40, 0.45, 0.55), "" },
                            { 8, Vector3(0.75, 0.65, 0.05), "Ow" },
                            { 6, Vector3(0.90, 0.85, 0.95), "" } };
  for (const Entry& entry : entries) {
    Avogadro::Core::Atom atom = molecule.addAtom(entry.element);
    atom.setPosition3d(cell->toCartesian(entry.fractional));
    if (entry.label[0] != '\0')
      molecule.setAtomLabel(atom.index(), entry.label);
  }
  molecule.setHallNumber(1);
  molecule.setData("name", "a test molecule");
  return molecule;
}

void expectSameCell(const UnitCell& a, const UnitCell& b)
{
  EXPECT_NEAR(a.a(), b.a(), 1e-5);
  EXPECT_NEAR(a.b(), b.b(), 1e-5);
  EXPECT_NEAR(a.c(), b.c(), 1e-5);
  EXPECT_NEAR(a.alpha(), b.alpha(), 1e-5);
  EXPECT_NEAR(a.beta(), b.beta(), 1e-5);
  EXPECT_NEAR(a.gamma(), b.gamma(), 1e-5);
}

} // namespace

TEST(CifTest, writeP1RoundTrip)
{
  const Molecule original = triclinicMolecule();

  // through a string
  std::string text;
  CifFormat writer;
  ASSERT_TRUE(writer.writeString(text, original)) << writer.error();
  EXPECT_NE(text.find("data_a_test_molecule"), std::string::npos);
  EXPECT_NE(text.find("_space_group_name_H-M_alt"), std::string::npos);
  EXPECT_NE(text.find("_cell_volume"), std::string::npos);
  EXPECT_EQ(text.find("_geom_bond"), std::string::npos);

  Molecule fromString;
  CifFormat reader;
  ASSERT_TRUE(reader.readString(text, fromString)) << reader.error();
  ASSERT_NE(fromString.unitCell(), nullptr);
  expectSameCell(*original.unitCell(), *fromString.unitCell());
  EXPECT_EQ(fromString.hallNumber(), 1);
  EXPECT_EQ(fromString.data("name").toString(), "a_test_molecule");

  // positions are kept as they were, not wrapped into the cell
  ASSERT_EQ(fromString.atomCount(), original.atomCount());
  for (std::size_t i = 0; i < original.atomCount(); ++i) {
    EXPECT_EQ(fromString.atomicNumber(i), original.atomicNumber(i));
    EXPECT_LT(
      (fromString.atomPosition3d(i) - original.atomPosition3d(i)).norm(), 1e-4);
  }

  // the label of an atom is kept unless it is empty or already taken
  EXPECT_EQ(fromString.atomLabel(0), "C1");
  EXPECT_EQ(fromString.atomLabel(1), "C2");
  EXPECT_EQ(fromString.atomLabel(2), "O1");
  EXPECT_EQ(fromString.atomLabel(3), "Ow");
  EXPECT_EQ(fromString.atomLabel(4), "C3");

  // and through a file
  const std::filesystem::path path =
    std::filesystem::temp_directory_path() / "avogadro_ciftest_roundtrip.cif";
  CifFormat fileWriter;
  ASSERT_TRUE(fileWriter.writeFile(path.string(), original))
    << fileWriter.error();
  Molecule fromFile;
  CifFormat fileReader;
  const bool read = fileReader.readFile(path.string(), fromFile);
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
  ASSERT_TRUE(read) << fileReader.error();
  expectSameCell(*original.unitCell(), *fromFile.unitCell());
  expectSameAtoms(original, fromFile);
  EXPECT_EQ(fromFile.hallNumber(), 1);
}

TEST(CifTest, writeFillsTheCellOfASpaceGroup)
{
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readFile(codFile("1100686"), molecule)) << format.error();
  ASSERT_GT(molecule.hallNumber(), 1);

  // what the Fill Unit Cell action makes of it
  Molecule reference(molecule);
  SpaceGroups::fillUnitCell(reference, molecule.hallNumber());
  ASSERT_GT(reference.atomCount(), molecule.atomCount());

  // the molecule as the caller has it
  const std::size_t atomCount = molecule.atomCount();
  const auto numbers = molecule.atomicNumbers();
  const auto positions = molecule.atomPositions3d();
  const double a = molecule.unitCell()->a(), b = molecule.unitCell()->b(),
               c = molecule.unitCell()->c(),
               alpha = molecule.unitCell()->alpha(),
               beta = molecule.unitCell()->beta(),
               gamma = molecule.unitCell()->gamma();
  const auto hall = molecule.hallNumber();

  std::string text;
  CifFormat writer;
  ASSERT_TRUE(writer.writeString(text, molecule)) << writer.error();

  // the molecule itself is not changed
  EXPECT_EQ(molecule.hallNumber(), hall);
  EXPECT_EQ(molecule.hallNumber(), reference.hallNumber());
  ASSERT_EQ(molecule.atomCount(), atomCount);
  for (std::size_t i = 0; i < atomCount; ++i) {
    EXPECT_EQ(molecule.atomicNumber(i), numbers[i]);
    EXPECT_EQ(molecule.atomPosition3d(i), positions[i]);
  }
  EXPECT_EQ(molecule.unitCell()->a(), a);
  EXPECT_EQ(molecule.unitCell()->b(), b);
  EXPECT_EQ(molecule.unitCell()->c(), c);
  EXPECT_EQ(molecule.unitCell()->alpha(), alpha);
  EXPECT_EQ(molecule.unitCell()->beta(), beta);
  EXPECT_EQ(molecule.unitCell()->gamma(), gamma);

  Molecule readBack;
  CifFormat reader;
  ASSERT_TRUE(reader.readString(text, readBack)) << reader.error();
  EXPECT_EQ(readBack.hallNumber(), 1);
  expectSameCell(*molecule.unitCell(), *readBack.unitCell());
  expectSameAtoms(reference, readBack);
}

TEST(CifTest, writeNeedsACellAndAtoms)
{
  Molecule noCell;
  noCell.addAtom(6);
  std::string text;
  CifFormat format;
  EXPECT_FALSE(format.writeString(text, noCell));
  EXPECT_NE(format.error().find("unit cell"), std::string::npos);

  Molecule noAtoms;
  noAtoms.setUnitCell(
    new UnitCell(5.0, 5.0, 5.0, 1.5707963, 1.5707963, 1.5707963));
  CifFormat other;
  EXPECT_FALSE(other.writeString(text, noAtoms));
  EXPECT_FALSE(other.error().empty());
}

TEST(CifTest, independentFillOfAnOriginShiftedInversion)
{
  // P-1 with the inversion center at (1/8, 1/8, 1/8) is in no table entry, so
  // the molecule keeps the operations of the file, which fill the cell. The
  // images are worked out by hand, not with the library: x' = 1/4 - x for each
  // fractional coordinate, then wrapped into [0, 1).
  //
  // The cell is orthorhombic, a = 5, b = 6, c = 7 angstrom.
  //  C1 (0.10, 0.20, 0.30) -> (0.15, 0.05, -0.05) -> (0.15, 0.05, 0.95)
  //     -> (0.15 * 5, 0.05 * 6, 0.95 * 7) = (0.75, 0.30, 6.65)
  //  O1 (0.40, 0.35, 0.15) -> (-0.15, -0.10, 0.10) -> (0.85, 0.90, 0.10)
  //     -> (0.85 * 5, 0.90 * 6, 0.10 * 7) = (4.25, 5.40, 0.70)
  // and the atoms themselves are at (0.5, 1.2, 2.1) and (2.0, 2.1, 1.05).
  const std::string text =
    "data_shifted\n_cell_length_a 5.0\n_cell_length_b 6.0\n"
    "_cell_length_c 7.0\n_cell_angle_alpha 90\n_cell_angle_beta 90\n"
    "_cell_angle_gamma 90\n"
    "loop_\n_space_group_symop_operation_xyz\n'x,y,z'\n"
    "'-x+1/4,-y+1/4,-z+1/4'\n"
    "loop_\n_atom_site_label\n_atom_site_type_symbol\n_atom_site_fract_x\n"
    "_atom_site_fract_y\n_atom_site_fract_z\n"
    "C1 C 0.10 0.20 0.30\nO1 O 0.40 0.35 0.15\n";

  ASSERT_EQ(
    SpaceGroups::hallNumberFromTransforms({ "x,y,z", "-x+1/4,-y+1/4,-z+1/4" }),
    0);

  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(text, molecule)) << format.error();
  EXPECT_EQ(molecule.hallNumber(), 0);
  ASSERT_EQ(molecule.atomCount(), 2u);
  const auto operations = SpaceGroups::storedOperations(molecule);
  ASSERT_EQ(operations.size(), 2u);
  ASSERT_TRUE(SpaceGroups::fillUnitCellFromOperations(molecule, operations,
                                                      0.25, true, false));
  ASSERT_EQ(molecule.atomCount(), 4u);

  struct Expected
  {
    unsigned char element;
    Vector3 position;
  };
  const Expected expected[] = { { 6, Vector3(0.5, 1.2, 2.1) },
                                { 8, Vector3(2.0, 2.1, 1.05) },
                                { 6, Vector3(0.75, 0.30, 6.65) },
                                { 8, Vector3(4.25, 5.40, 0.70) } };
  const double lengths[] = { 5.0, 6.0, 7.0 };
  std::vector<bool> used(molecule.atomCount(), false);
  for (const Expected& want : expected) {
    int matches = 0;
    for (std::size_t i = 0; i < molecule.atomCount(); ++i) {
      if (molecule.atomicNumber(i) != want.element)
        continue;
      Vector3 delta = molecule.atomPosition3d(i) - want.position;
      for (int k = 0; k < 3; ++k) // minimum image, the cell is orthorhombic
        delta[k] -= lengths[k] * std::round(delta[k] / lengths[k]);
      if (delta.norm() < 1e-4) {
        ++matches;
        used[i] = true;
      }
    }
    EXPECT_EQ(matches, 1) << "element " << int(want.element);
  }
  for (bool u : used)
    EXPECT_TRUE(u);
}

TEST(CifTest, disorderRuleWithStoredOperations)
{
  // The same origin-shifted P-1, so the operations are kept. C1 and C2 are
  // alternatives 1.4 angstrom apart, in the middle of the cell, and must not be
  // bonded.
  const std::string text =
    "data_alt\n_cell_length_a 20.0\n_cell_length_b 20.0\n"
    "_cell_length_c 20.0\n_cell_angle_alpha 90\n_cell_angle_beta 90\n"
    "_cell_angle_gamma 90\n"
    "loop_\n_space_group_symop_operation_xyz\n'x,y,z'\n"
    "'-x+1/4,-y+1/4,-z+1/4'\n"
    "loop_\n_atom_site_label\n_atom_site_type_symbol\n_atom_site_fract_x\n"
    "_atom_site_fract_y\n_atom_site_fract_z\n_atom_site_disorder_assembly\n"
    "_atom_site_disorder_group\n"
    "C1 C 0.40 0.40 0.40 A 1\nC2 C 0.47 0.40 0.40 A 2\n";
  Molecule molecule;
  CifFormat format;
  format.setOptions(R"({"perceiveBonds": true, "disorder": "all"})");
  ASSERT_TRUE(format.readString(text, molecule)) << format.error();
  EXPECT_EQ(molecule.hallNumber(), 0);
  ASSERT_EQ(molecule.atomCount(), 2u);
  EXPECT_FALSE(bonded(molecule, "C1", "C2"));
}

namespace {

// Reads text with the given options and returns the labels of the atoms.
std::set<std::string> labelsOf(const std::string& text,
                               const std::string& options = std::string())
{
  Molecule molecule;
  CifFormat format;
  if (!options.empty())
    format.setOptions(options);
  EXPECT_TRUE(format.readString(text, molecule)) << format.error();
  std::set<std::string> labels;
  for (std::size_t i = 0; i < molecule.atomCount(); ++i)
    labels.insert(molecule.atomLabel(i));
  return labels;
}

// Atoms far apart, one per row: label, assembly, group, occupancy.
std::string disorderedCif(const std::string& rows)
{
  return cubicCif(std::string(siteColumns) +
                    "_atom_site_disorder_assembly\n"
                    "_atom_site_disorder_group\n_atom_site_occupancy\n",
                  rows);
}

std::size_t countOf(const std::set<std::string>& labels,
                    const std::string& label)
{
  return labels.count(label);
}

// The labels of a COD file that belong to the given disorder group, in the
// assemblies that also have the other group (a lone group is always kept).
std::vector<std::string> labelsInGroup(const std::string& path,
                                       const std::string& group,
                                       const std::string& other)
{
  const auto disorder = disorderOf(path);
  std::set<std::string> assemblies;
  for (const auto& entry : disorder) {
    if (entry.second.second == other)
      assemblies.insert(entry.second.first);
  }
  std::vector<std::string> result;
  for (const auto& entry : disorder) {
    if (entry.second.second == group && assemblies.count(entry.second.first))
      result.push_back(entry.first);
  }
  return result;
}

} // namespace

TEST(CifTest, majorDisorderGroupOfTheIssueFile)
{
  const std::string path = codFile("issue2437");
  Molecule major;
  CifFormat format;
  ASSERT_TRUE(format.readFile(path, major)) << format.error();
  for (const char* label : { "Cl1A", "Cl2A", "Cl3A", "H4AA" }) {
    for (std::size_t i = 0; i < major.atomCount(); ++i)
      EXPECT_NE(major.atomLabel(i), label);
  }
  EXPECT_TRUE(bonded(major, "C4A", "Cl1"));
  EXPECT_TRUE(bonded(major, "C4A", "Cl2"));
  EXPECT_TRUE(bonded(major, "C4A", "Cl3"));
  EXPECT_TRUE(bonded(major, "C4A", "H4A"));
  std::size_t carbon = major.atomCount();
  for (std::size_t i = 0; i < major.atomCount(); ++i) {
    if (major.atomLabel(i) == "C4A")
      carbon = i;
  }
  ASSERT_LT(carbon, major.atomCount());
  EXPECT_EQ(major.bonds(carbon).size(), 4u);

  Molecule all;
  CifFormat allFormat;
  allFormat.setOptions(R"({"disorder": "all"})");
  ASSERT_TRUE(allFormat.readFile(path, all)) << allFormat.error();
  EXPECT_GT(all.atomCount(), major.atomCount());
  std::set<std::string> labels;
  for (std::size_t i = 0; i < all.atomCount(); ++i)
    labels.insert(all.atomLabel(i));
  for (const char* label : { "Cl1A", "Cl2A", "Cl3A", "H4AA" })
    EXPECT_EQ(countOf(labels, label), 1u) << label;
}

TEST(CifTest, majorDisorderGroupOfCodFiles)
{
  for (const char* id : { "2017715", "1543858" }) {
    const std::string path = codFile(id);
    // every group-2 atom goes, lone groups of low occupancy included
    std::vector<std::string> minor;
    for (const auto& entry : disorderOf(path)) {
      if (entry.second.second == "2")
        minor.push_back(entry.first);
    }
    const auto major = labelsInGroup(path, "1", "2");
    ASSERT_FALSE(minor.empty()) << id;
    ASSERT_FALSE(major.empty()) << id;

    Molecule molecule;
    CifFormat format;
    ASSERT_TRUE(format.readFile(path, molecule)) << format.error();
    std::set<std::string> labels;
    for (std::size_t i = 0; i < molecule.atomCount(); ++i)
      labels.insert(molecule.atomLabel(i));
    for (const auto& label : minor)
      EXPECT_EQ(countOf(labels, label), 0u) << id << " " << label;
    for (const auto& label : major)
      EXPECT_EQ(countOf(labels, label), 1u) << id << " " << label;
  }
}

TEST(CifTest, majorDisorderGroupIsChosenByOccupancy)
{
  // the minor group comes first in the file
  const std::string text = disorderedCif("C1 C 0.1 0.1 0.1 . 1 0.3\n"
                                         "C2 C 0.3 0.1 0.1 . 2 0.7\n"
                                         "C3 C 0.5 0.5 0.5 . . 1.0\n");
  auto labels = labelsOf(text);
  EXPECT_EQ(countOf(labels, "C1"), 0u);
  EXPECT_EQ(countOf(labels, "C2"), 1u);
  EXPECT_EQ(countOf(labels, "C3"), 1u);

  // the mean over the sites of a group decides
  labels = labelsOf(disorderedCif("C1 C 0.1 0.1 0.1 . 1 0.9\n"
                                  "C2 C 0.3 0.1 0.1 . 1 0.1\n"
                                  "C3 C 0.5 0.1 0.1 . 2 0.6\n"));
  EXPECT_EQ(countOf(labels, "C1"), 0u);
  EXPECT_EQ(countOf(labels, "C2"), 0u);
  EXPECT_EQ(countOf(labels, "C3"), 1u);
}

TEST(CifTest, loneDisorderGroupNeedsHalfOccupancy)
{
  auto labels = labelsOf(disorderedCif("C1 C 0.1 0.1 0.1 . 1 0.3\n"
                                       "C2 C 0.5 0.5 0.5 . . 1.0\n"));
  EXPECT_EQ(countOf(labels, "C1"), 0u);
  EXPECT_EQ(countOf(labels, "C2"), 1u);

  labels = labelsOf(disorderedCif("C1 C 0.1 0.1 0.1 . 1 0.5\n"));
  EXPECT_EQ(countOf(labels, "C1"), 1u);

  // no occupancy column counts as 1.0
  labels = labelsOf(cubicCif(std::string(siteColumns) +
                               "_atom_site_disorder_assembly\n"
                               "_atom_site_disorder_group\n",
                             "C1 C 0.1 0.1 0.1 . 1\n"));
  EXPECT_EQ(countOf(labels, "C1"), 1u);
}

TEST(CifTest, majorDisorderGroupTieKeepsTheFirst)
{
  const auto labels = labelsOf(disorderedCif("C1 C 0.1 0.1 0.1 . 2 0.5\n"
                                             "C2 C 0.3 0.1 0.1 . 1 0.5\n"));
  EXPECT_EQ(countOf(labels, "C1"), 1u);
  EXPECT_EQ(countOf(labels, "C2"), 0u);
}

TEST(CifTest, majorDisorderGroupWithoutOccupancyKeepsTheFirst)
{
  const std::string text = cubicCif(
    std::string(siteColumns) +
      "_atom_site_disorder_assembly\n_atom_site_disorder_group\n",
    "C1 C 0.1 0.1 0.1 . 2\nC2 C 0.3 0.1 0.1 . 1\nC3 C 0.5 0.5 0.5 . .\n");
  const auto labels = labelsOf(text);
  EXPECT_EQ(countOf(labels, "C1"), 1u);
  EXPECT_EQ(countOf(labels, "C2"), 0u);
  EXPECT_EQ(countOf(labels, "C3"), 1u);

  // an unreadable occupancy counts as one
  const auto unreadable = labelsOf(
    disorderedCif("C1 C 0.1 0.1 0.1 . 1 ?\nC2 C 0.3 0.1 0.1 . 2 0.9\n"));
  EXPECT_EQ(countOf(unreadable, "C1"), 1u);
  EXPECT_EQ(countOf(unreadable, "C2"), 0u);
}

TEST(CifTest, majorDisorderAssembliesAreIndependent)
{
  const auto labels = labelsOf(disorderedCif("C1 C 0.1 0.1 0.1 A 1 0.3\n"
                                             "C2 C 0.2 0.1 0.1 A 2 0.7\n"
                                             "C3 C 0.5 0.5 0.5 B 1 0.8(2)\n"
                                             "C4 C 0.7 0.5 0.5 B 2 0.2(2)\n"));
  EXPECT_EQ(countOf(labels, "C1"), 0u);
  EXPECT_EQ(countOf(labels, "C2"), 1u);
  EXPECT_EQ(countOf(labels, "C3"), 1u);
  EXPECT_EQ(countOf(labels, "C4"), 0u);
}

TEST(CifTest, negativeDisorderGroupsAreNeverDropped)
{
  const auto labels = labelsOf(disorderedCif("C1 C 0.1 0.1 0.1 . -1 0.3\n"
                                             "C2 C 0.3 0.1 0.1 . -2 0.2\n"
                                             "C3 C 0.5 0.5 0.5 . 1 0.4\n"
                                             "C4 C 0.7 0.5 0.5 . 2 0.6\n"));
  EXPECT_EQ(countOf(labels, "C1"), 1u);
  EXPECT_EQ(countOf(labels, "C2"), 1u);
  EXPECT_EQ(countOf(labels, "C3"), 0u);
  EXPECT_EQ(countOf(labels, "C4"), 1u);
}

TEST(CifTest, majorDisorderGroupsWithTextLabels)
{
  const auto labels = labelsOf(disorderedCif("C1 C 0.1 0.1 0.1 . a 0.4\n"
                                             "C2 C 0.3 0.1 0.1 . b 0.6\n"));
  EXPECT_EQ(countOf(labels, "C1"), 0u);
  EXPECT_EQ(countOf(labels, "C2"), 1u);
}

TEST(CifTest, disorderOptionAllKeepsEverything)
{
  const std::string text = disorderedCif("C1 C 0.1 0.1 0.1 . 1 0.3\n"
                                         "C2 C 0.3 0.1 0.1 . 2 0.7\n");
  for (const char* value : { "all", "ALL", "All" }) {
    const auto labels =
      labelsOf(text, std::string(R"({"disorder": ")") + value + R"("})");
    EXPECT_EQ(labels.size(), 2u) << value;
  }
  // any other value means the default
  EXPECT_EQ(labelsOf(text, R"({"disorder": "bogus"})").size(), 1u);
}

TEST(CifTest, writeFillsTheCellWithStoredOperations)
{
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readFile(codFile("7006564"), molecule)) << format.error();
  ASSERT_EQ(molecule.hallNumber(), 0);
  const auto operations = SpaceGroups::storedOperations(molecule);
  ASSERT_FALSE(operations.empty());

  Molecule reference(molecule);
  ASSERT_TRUE(SpaceGroups::fillUnitCellFromOperations(reference, operations));
  ASSERT_GT(reference.atomCount(), molecule.atomCount());
  const std::size_t atomCount = molecule.atomCount();

  std::string text;
  CifFormat writer;
  ASSERT_TRUE(writer.writeString(text, molecule)) << writer.error();
  // the molecule is not changed
  EXPECT_EQ(molecule.atomCount(), atomCount);
  EXPECT_EQ(SpaceGroups::storedOperations(molecule), operations);

  Molecule readBack;
  CifFormat reader;
  ASSERT_TRUE(reader.readString(text, readBack)) << reader.error();
  EXPECT_EQ(readBack.hallNumber(), 1);
  EXPECT_EQ(readBack.atomCount(), reference.atomCount());
  expectSameCell(*molecule.unitCell(), *readBack.unitCell());
  expectSameAtoms(reference, readBack);
}

TEST(CifTest, unquotedOperationsAreBounded)
{
  // many values without a comma, as valid CIF syntax: no hang, and no group
  // is made from them
  std::string rows;
  for (int i = 0; i < 20000; ++i)
    rows += "xyz\n";
  const std::string text =
    "data_many\n_cell_length_a 5.0\n_cell_length_b 5.0\n"
    "_cell_length_c 5.0\n_cell_angle_alpha 90\n_cell_angle_beta 90\n"
    "_cell_angle_gamma 90\n"
    "loop_\n_space_group_symop_operation_xyz\n" +
    rows +
    "loop_\n_atom_site_label\n_atom_site_type_symbol\n_atom_site_fract_x\n"
    "_atom_site_fract_y\n_atom_site_fract_z\nC1 C 0.1 0.2 0.3\n";
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(text, molecule)) << format.error();
  EXPECT_EQ(molecule.atomCount(), 1u);
  EXPECT_LE(molecule.hallNumber(), 1);
  EXPECT_FALSE(Avogadro::Io::readCifSymmetry(text).hallNumber() > 1);
}

TEST(CifTest, bondSymmetryCodeOneIsTheIdentity)
{
  // the atoms are 10 angstrom apart, so only the file bonds them
  const std::string columns = std::string(siteColumns);
  const std::string text =
    cubicCif(columns, "C1 C 0.1 0.1 0.1\nC2 C 0.6 0.1 0.1\n") +
    "loop_\n_geom_bond_atom_site_label_1\n_geom_bond_atom_site_label_2\n"
    "_geom_bond_site_symmetry_1\n_geom_bond_site_symmetry_2\n"
    "C1 C2 1 1\n";
  Molecule molecule;
  CifFormat format;
  format.setOptions("{ \"perceiveBonds\": false }");
  ASSERT_TRUE(format.readString(text, molecule)) << format.error();
  EXPECT_EQ(molecule.atomCount(), 2u);
  EXPECT_TRUE(bonded(molecule, "C1", "C2"));
}

TEST(CifTest, writeKeepsDeuteriumAndTritium)
{
  for (unsigned short isotope : { 2, 3 }) {
    SCOPED_TRACE(isotope);
    Molecule original;
    original.setUnitCell(new UnitCell(8.0, 9.0, 10.0, 1.5707963267948966,
                                      1.5707963267948966, 1.5707963267948966));
    original.addAtom(6).setPosition3d(Vector3(1.0, 2.0, 3.0));
    Avogadro::Core::Atom h = original.addAtom(1);
    h.setPosition3d(Vector3(4.0, 5.0, 6.0));
    h.setIsotope(isotope);
    original.setHallNumber(1);

    std::string text;
    CifFormat writer;
    ASSERT_TRUE(writer.writeString(text, original)) << writer.error();
    Molecule readBack;
    CifFormat reader;
    ASSERT_TRUE(reader.readString(text, readBack)) << reader.error();
    ASSERT_EQ(readBack.atomCount(), 2u);
    EXPECT_EQ(readBack.atomicNumber(1), 1);
    EXPECT_EQ(readBack.isotope(1), isotope);
    EXPECT_EQ(readBack.isotope(0), 0);
  }
}

TEST(CifTest, writeKeepsDeuteriumOfASpaceGroup)
{
  // P -1: the images of a deuterium atom are deuterium atoms
  const unsigned short hall = SpaceGroups::hallNumberFromHallSymbol("-P 1");
  ASSERT_GT(hall, 1);
  Molecule original;
  original.setUnitCell(new UnitCell(8.0, 9.0, 10.0, 1.5707963267948966,
                                    1.5707963267948966, 1.5707963267948966));
  Avogadro::Core::Atom d = original.addAtom(1);
  d.setPosition3d(Vector3(1.0, 2.0, 3.0));
  d.setIsotope(2);
  original.setHallNumber(hall);

  std::string text;
  CifFormat writer;
  ASSERT_TRUE(writer.writeString(text, original)) << writer.error();
  Molecule readBack;
  CifFormat reader;
  ASSERT_TRUE(reader.readString(text, readBack)) << reader.error();
  ASSERT_EQ(readBack.atomCount(), 2u);
  for (std::size_t i = 0; i < readBack.atomCount(); ++i) {
    EXPECT_EQ(readBack.atomicNumber(i), 1);
    EXPECT_EQ(readBack.isotope(i), 2);
  }
}

#if !AVOGADRO_MSAN_BUILD

TEST(CifTest, malformedInputIsHandedToAnotherReader)
{
  bool called = false;
  ScopedFakeOpenBabel fake(&called);
  ASSERT_TRUE(fake.registered);

  // an unterminated quote and a text field that never ends make gemmi throw
  for (const char* text : { "data_x\n_cell_length_a 'unterminated\n",
                            "data_x\n_a\n;\nnever\n", "loop_\n_a\n_b\n1\n" }) {
    called = false;
    Molecule molecule;
    CifFormat format;
    EXPECT_TRUE(format.readString(text, molecule)) << text;
    EXPECT_TRUE(called) << text;
  }
}

TEST(CifTest, malformedInputWithoutAnotherReaderIsAnError)
{
  for (const char* text : { "data_x\n_cell_length_a 'unterminated\n", "" }) {
    Molecule molecule;
    CifFormat format;
    EXPECT_FALSE(format.readString(text, molecule)) << text;
    EXPECT_FALSE(format.error().empty()) << text;
    EXPECT_EQ(molecule.atomCount(), 0u);
  }
}

#endif // !AVOGADRO_MSAN_BUILD

namespace {
Molecule readOccupancyCif(const std::string& rows,
                          const std::string& options = std::string())
{
  Molecule molecule;
  CifFormat format;
  if (!options.empty())
    format.setOptions(options);
  EXPECT_TRUE(format.readString(
    cubicCif(std::string(siteColumns) + "_atom_site_occupancy\n", rows),
    molecule))
    << format.error();
  return molecule;
}
} // namespace

TEST(CifTest, readsOccupancies)
{
  const Molecule molecule = readOccupancyCif("C1 C 0.1 0.1 0.1 0.5(2)\n"
                                             "O1 O 0.5 0.5 0.5 1\n"
                                             "N1 N 0.7 0.7 0.7 ?\n");
  ASSERT_EQ(molecule.atomCount(), 3);
  ASSERT_EQ(molecule.occupancies().size(), 3u);
  EXPECT_EQ(molecule.occupancy(0), 0.5);
  EXPECT_EQ(molecule.occupancy(1), 1.0);
  EXPECT_EQ(molecule.occupancy(2), 1.0);
}

TEST(CifTest, occupanciesInBothDisorderModes)
{
  const std::string columns = std::string(siteColumns) +
                              "_atom_site_disorder_assembly\n"
                              "_atom_site_disorder_group\n"
                              "_atom_site_occupancy\n";
  const std::string text =
    cubicCif(columns, "C1 C 0.1 0.1 0.1 . 1 0.3\nC2 C 0.3 0.1 0.1 . 2 0.7\n");

  Molecule major;
  CifFormat majorFormat;
  ASSERT_TRUE(majorFormat.readString(text, major)) << majorFormat.error();
  ASSERT_EQ(major.atomCount(), 1);
  EXPECT_EQ(major.atomLabel(0), "C2");
  EXPECT_EQ(major.occupancy(0), 0.7);

  Molecule all;
  CifFormat allFormat;
  allFormat.setOptions(R"({"disorder": "all"})");
  ASSERT_TRUE(allFormat.readString(text, all)) << allFormat.error();
  ASSERT_EQ(all.atomCount(), 2);
  EXPECT_EQ(all.occupancy(0), 0.3);
  EXPECT_EQ(all.occupancy(1), 0.7);
}

TEST(CifTest, plainCifStoresNoOccupancies)
{
  EXPECT_TRUE(readOccupancyCif("C1 C 0.1 0.1 0.1 1.0\nO1 O 0.5 0.5 0.5 1\n")
                .occupancies()
                .empty());
  // no occupancy column at all
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(
    format.readString(cubicCif(siteColumns, "C1 C 0.1 0.1 0.1\n"), molecule))
    << format.error();
  EXPECT_TRUE(molecule.occupancies().empty());
}

TEST(CifTest, negativeOccupancyCountsAsOne)
{
  const Molecule molecule =
    readOccupancyCif("C1 C 0.1 0.1 0.1 -0.5\nO1 O 0.5 0.5 0.5 0.5\n");
  ASSERT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(molecule.occupancy(0), 1.0);
  EXPECT_EQ(molecule.occupancy(1), 0.5);
}

TEST(CifTest, symmetryExpansionCarriesOccupancy)
{
  const std::string text =
    cubicCif(std::string(siteColumns) + "_atom_site_occupancy\n",
             "C1 C 0.1 0.2 0.3 0.5\n",
             "_symmetry_space_group_name_H-M 'P -1'\nloop_\n"
             "_symmetry_equiv_pos_as_xyz\n'x, y, z'\n'-x, -y, -z'\n");
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(text, molecule)) << format.error();
  // the reader keeps the asymmetric unit; filling the cell makes the images
  ASSERT_EQ(molecule.atomCount(), 1);
  ASSERT_NE(molecule.hallNumber(), 0);
  EXPECT_EQ(molecule.occupancy(0), 0.5);
  SpaceGroups::fillUnitCell(molecule, molecule.hallNumber());
  ASSERT_EQ(molecule.atomCount(), 2);
  ASSERT_EQ(molecule.occupancies().size(), 2u);
  EXPECT_EQ(molecule.occupancy(0), 0.5);
  EXPECT_EQ(molecule.occupancy(1), 0.5);
}

TEST(CifTest, writeKeepsOccupancy)
{
  Molecule original;
  original.setUnitCell(new UnitCell(8.0, 9.0, 10.0, 1.5707963267948966,
                                    1.5707963267948966, 1.5707963267948966));
  original.addAtom(6).setPosition3d(Vector3(1.0, 2.0, 3.0));
  original.addAtom(8).setPosition3d(Vector3(4.0, 5.0, 6.0));
  original.setHallNumber(1);
  ASSERT_TRUE(original.setOccupancy(1, 0.25));

  std::string text;
  CifFormat writer;
  ASSERT_TRUE(writer.writeString(text, original)) << writer.error();
  EXPECT_NE(text.find("_atom_site_occupancy"), std::string::npos);

  Molecule readBack;
  CifFormat reader;
  ASSERT_TRUE(reader.readString(text, readBack)) << reader.error();
  ASSERT_EQ(readBack.atomCount(), 2);
  EXPECT_EQ(readBack.occupancy(0), 1.0);
  EXPECT_EQ(readBack.occupancy(1), 0.25);

  // A molecule without occupancies writes no column
  Molecule plain;
  plain.setUnitCell(new UnitCell(8.0, 9.0, 10.0, 1.5707963267948966,
                                 1.5707963267948966, 1.5707963267948966));
  plain.addAtom(6).setPosition3d(Vector3(1.0, 2.0, 3.0));
  plain.setHallNumber(1);
  std::string plainText;
  ASSERT_TRUE(writer.writeString(plainText, plain)) << writer.error();
  EXPECT_EQ(plainText.find("occupancy"), std::string::npos);
}

TEST(CifTest, writeKeepsTinyOccupancy)
{
  Molecule original;
  original.setUnitCell(new UnitCell(8.0, 9.0, 10.0, 1.5707963267948966,
                                    1.5707963267948966, 1.5707963267948966));
  original.addAtom(6).setPosition3d(Vector3(1.0, 2.0, 3.0));
  original.addAtom(8).setPosition3d(Vector3(4.0, 5.0, 6.0));
  original.addAtom(7).setPosition3d(Vector3(2.0, 3.0, 4.0));
  original.setHallNumber(1);
  // below 0.00005, four fixed decimals would write zero
  ASSERT_TRUE(original.setOccupancy(0, 0.00002));
  ASSERT_TRUE(original.setOccupancy(1, 0.0));
  ASSERT_TRUE(original.setOccupancy(2, 0.375));

  std::string text;
  CifFormat writer;
  ASSERT_TRUE(writer.writeString(text, original)) << writer.error();

  Molecule readBack;
  CifFormat reader;
  ASSERT_TRUE(reader.readString(text, readBack)) << reader.error();
  ASSERT_EQ(readBack.atomCount(), 3);
  EXPECT_GT(readBack.occupancy(0), 0.0);
  EXPECT_NEAR(readBack.occupancy(0), 0.00002, 1e-9);
  EXPECT_EQ(readBack.occupancy(1), 0.0);
  EXPECT_EQ(readBack.occupancy(2), 0.375);
}

TEST(CifTest, writeExpandsToP1WithOccupancy)
{
  // P -1 stored as a Hall number: the writer fills the cell, and every image
  // keeps the occupancy
  Molecule original;
  original.setUnitCell(new UnitCell(8.0, 9.0, 10.0, 1.5707963267948966,
                                    1.5707963267948966, 1.5707963267948966));
  original.addAtom(6).setPosition3d(Vector3(1.0, 2.0, 3.0));
  ASSERT_TRUE(original.setOccupancy(0, 0.5));
  ASSERT_TRUE(SpaceGroups::setSpaceGroup(original, "P -1"));

  std::string text;
  CifFormat writer;
  ASSERT_TRUE(writer.writeString(text, original)) << writer.error();
  Molecule readBack;
  CifFormat reader;
  ASSERT_TRUE(reader.readString(text, readBack)) << reader.error();
  ASSERT_EQ(readBack.atomCount(), 2);
  EXPECT_EQ(readBack.occupancy(0), 0.5);
  EXPECT_EQ(readBack.occupancy(1), 0.5);
}

namespace {

// Check the labels stored on the atoms against what the file lists.
void expectDisorderLabelsOfFile(const std::string& path,
                                const Molecule& molecule)
{
  const auto disorder = disorderOf(path);
  auto isNull = [](const std::string& value) {
    return value == "." || value == "?";
  };
  std::size_t grouped = 0;
  for (std::size_t i = 0; i < molecule.atomCount(); ++i) {
    const auto it = disorder.find(molecule.atomLabel(i));
    ASSERT_NE(it, disorder.end()) << molecule.atomLabel(i);
    const std::string assembly =
      isNull(it->second.first) ? "" : it->second.first;
    std::string group = isNull(it->second.second) ? "" : it->second.second;
    if (group == "0")
      group = "";
    EXPECT_EQ(molecule.disorderAssembly(i), assembly) << molecule.atomLabel(i);
    EXPECT_EQ(molecule.disorderGroup(i), group) << molecule.atomLabel(i);
    if (!group.empty())
      ++grouped;
  }
  EXPECT_GT(grouped, 0u);
}

} // namespace

TEST(CifTest, disorderLabelsAreStoredOnTheAtoms)
{
  const std::string path = codFile("2017715");
  const auto disorder = disorderOf(path);
  std::set<std::string> assemblies;
  for (const auto& entry : disorder)
    assemblies.insert(entry.second.first);
  ASSERT_GT(assemblies.size(), 2u); // A, B and C (and ".")

  std::size_t allCount = 0;
  for (const char* options : { R"({"disorder": "all"})", "" }) {
    SCOPED_TRACE(options);
    Molecule molecule;
    CifFormat format;
    if (std::string(options).size() > 0)
      format.setOptions(options);
    ASSERT_TRUE(format.readFile(path, molecule)) << format.error();
    expectDisorderLabelsOfFile(path, molecule);
    if (allCount == 0)
      allCount = molecule.atomCount();
    else
      EXPECT_LT(molecule.atomCount(), allCount); // "major" drops minor groups
  }
}

TEST(CifTest, orderedFileStoresNoDisorder)
{
  Molecule molecule;
  CifFormat format;
  ASSERT_TRUE(format.readString(disorderedCif("C1 C 0.1 0.1 0.1 . . 1.0\n"
                                              "C2 C 0.5 0.5 0.5 A 0 1.0\n"),
                                molecule))
    << format.error();
  EXPECT_TRUE(molecule.disorderGroups().empty());
  EXPECT_TRUE(molecule.disorderAssemblies().empty());
}

TEST(CifTest, disorderLabelsRoundTripThroughWrite)
{
  const std::string text = disorderedCif("C1 C 0.10 0.10 0.10 A 1 0.5\n"
                                         "C2 C 0.15 0.10 0.10 A 2 0.5\n"
                                         "C3 C 0.50 0.50 0.50 . . 1.0\n"
                                         "C4 C 0.70 0.70 0.70 . -1 1.0\n"
                                         "C5 C 0.30 0.80 0.30 B 3 1.0\n");
  Molecule original;
  CifFormat reader;
  reader.setOptions(R"({"disorder": "all"})");
  ASSERT_TRUE(reader.readString(text, original)) << reader.error();
  ASSERT_EQ(original.atomCount(), 5u);
  EXPECT_EQ(original.disorderAssembly(0), "A");
  EXPECT_EQ(original.disorderGroup(1), "2");
  EXPECT_EQ(original.disorderGroup(2), "");
  EXPECT_EQ(original.disorderGroup(3), "-1");
  EXPECT_EQ(original.disorderAssembly(3), "");
  // alternatives of one assembly are not bonded even though they are close
  EXPECT_FALSE(original.bond(0, 1).isValid());

  std::string written;
  CifFormat writer;
  ASSERT_TRUE(writer.writeString(written, original)) << writer.error();
  EXPECT_NE(written.find("_atom_site_disorder_assembly"), std::string::npos);
  EXPECT_NE(written.find("_atom_site_disorder_group"), std::string::npos);

  Molecule readBack;
  CifFormat second;
  second.setOptions(R"({"disorder": "all"})");
  ASSERT_TRUE(second.readString(written, readBack)) << second.error();
  ASSERT_EQ(readBack.atomCount(), original.atomCount());
  for (std::size_t i = 0; i < original.atomCount(); ++i) {
    EXPECT_EQ(readBack.disorderAssembly(i), original.disorderAssembly(i)) << i;
    EXPECT_EQ(readBack.disorderGroup(i), original.disorderGroup(i)) << i;
  }
  EXPECT_FALSE(readBack.bond(0, 1).isValid());

  // a molecule without disorder writes neither column
  Molecule plain;
  CifFormat plainReader;
  ASSERT_TRUE(
    plainReader.readString(disorderedCif("C1 C 0.1 0.1 0.1 . . 1.0\n"), plain));
  std::string plainText;
  ASSERT_TRUE(writer.writeString(plainText, plain)) << writer.error();
  EXPECT_EQ(plainText.find("disorder"), std::string::npos);
}

TEST(CifTest, disorderLabelsSurviveACellFillAndBondsStayOff)
{
  // two alternatives close to each other, in a group with an inversion
  const std::string text =
    cubicCif(std::string(siteColumns) +
               "_atom_site_disorder_assembly\n_atom_site_disorder_group\n",
             "C1 C 0.10 0.10 0.10 A 1\nC2 C 0.1675 0.10 0.10 A 2\n",
             "_space_group_name_H-M_alt 'P -1'\nloop_\n_space_group_symop_id\n"
             "_space_group_symop_operation_xyz\n1 x,y,z\n2 -x,-y,-z\n");
  Molecule molecule;
  CifFormat format;
  format.setOptions(R"({"disorder": "all"})");
  ASSERT_TRUE(format.readString(text, molecule)) << format.error();
  // the asymmetric unit is kept
  ASSERT_EQ(molecule.atomCount(), 2u);
  EXPECT_EQ(molecule.disorderGroup(0), "1");
  EXPECT_EQ(molecule.disorderGroup(1), "2");
  EXPECT_FALSE(molecule.bond(0, 1).isValid());

  SpaceGroups::fillUnitCell(molecule, molecule.hallNumber());
  ASSERT_EQ(molecule.atomCount(), 4u);
  for (std::size_t i = 0; i < molecule.atomCount(); ++i)
    EXPECT_EQ(molecule.disorderAssembly(i), "A") << i;
  EXPECT_EQ(molecule.disorderGroup(2), "1"); // images keep their group
  EXPECT_EQ(molecule.disorderGroup(3), "2");

  // perceiving the bonds again, after the fill, still skips the alternatives
  molecule.clearBonds();
  molecule.perceiveBondsSimple();
  EXPECT_FALSE(molecule.bond(0, 1).isValid());
  EXPECT_FALSE(molecule.bond(2, 3).isValid());
}
