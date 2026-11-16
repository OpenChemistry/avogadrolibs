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

#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

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

TEST(CifTest, untabulatedOperationsExpandToP1)
{
  // A-1, I-1 and F-1 settings are in no table entry; the atoms are expanded
  // with the operations of the file, exactly as expandCifAtoms() does.
  for (const char* id : { "7006564", "7011106", "2019269" }) {
    SCOPED_TRACE(id);
    Molecule molecule;
    CifFormat format;
    ASSERT_TRUE(format.readFile(codFile(id), molecule)) << format.error();
    EXPECT_EQ(molecule.hallNumber(), 1);

    const auto symmetry = Avogadro::Io::readCifSymmetry(readText(codFile(id)));
    ASSERT_TRUE(symmetry.hasUntabulatedOperations());

    // the asymmetric unit, expanded by hand
    cif::Document doc = cif::read_file(codFile(id));
    cif::Table rows = doc.sole_block().find(
      "_atom_site_", { "label", "fract_x", "fract_y", "fract_z" });
    ASSERT_TRUE(rows.ok());
    Molecule reference;
    reference.setUnitCell(new UnitCell(*molecule.unitCell()));
    for (auto row : rows) {
      Avogadro::Core::Atom atom = reference.addAtom(6);
      atom.setPosition3d(molecule.unitCell()->toCartesian(
        Vector3(std::stod(row[1]), std::stod(row[2]), std::stod(row[3]))));
    }
    const std::size_t asymmetric = reference.atomCount();
    ASSERT_TRUE(Avogadro::Io::expandCifAtoms(symmetry, reference));
    EXPECT_GT(reference.atomCount(), asymmetric);
    EXPECT_EQ(molecule.atomCount(), reference.atomCount());
    EXPECT_EQ(reference.hallNumber(), 1);
  }
}

TEST(CifTest, disorderGroupsOfTheSameAssemblyAreNotBonded)
{
  const std::string path = codFile("2017715");
  Molecule molecule;
  CifFormat format;
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
