/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <cmath>
#include <iomanip>
#include <sstream>

#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>

#include <avogadro/io/pdbformat.h>

using Avogadro::Core::Molecule;
using Avogadro::Io::PdbFormat;

namespace {

bool hasAtomAt(const Molecule& molecule, double x, double y, double z)
{
  constexpr double tolerance = 1e-6;
  for (Avogadro::Index i = 0; i < molecule.atomCount(); ++i) {
    const auto pos = molecule.atomPosition3d(i);
    if (std::abs(pos.x() - x) < tolerance &&
        std::abs(pos.y() - y) < tolerance &&
        std::abs(pos.z() - z) < tolerance) {
      return true;
    }
  }

  return false;
}

} // namespace

TEST(PdbTest, read)
{
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/1MYK.pdb", molecule);

  // how many atoms?
  EXPECT_EQ(molecule.atomCount(), 780);
  EXPECT_EQ(molecule.residueCount(), 108);
}

TEST(PdbTest, altLoc)
{
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/1FDT.pdb", molecule);

  EXPECT_EQ(molecule.coordinate3dCount(), 2);

  EXPECT_FLOAT_EQ(molecule.atomPosition3d(264).x(),
                  molecule.coordinate3d(1)[264].x());
  EXPECT_FLOAT_EQ(molecule.atomPosition3d(264).y(),
                  molecule.coordinate3d(1)[264].y());
  EXPECT_FLOAT_EQ(molecule.atomPosition3d(264).z(),
                  molecule.coordinate3d(1)[264].z());

  EXPECT_TRUE(
    molecule.atomPosition3d(265).x() != molecule.coordinate3d(1)[265].x() ||
    molecule.atomPosition3d(265).y() != molecule.coordinate3d(1)[265].y() ||
    molecule.atomPosition3d(265).z() != molecule.coordinate3d(1)[265].z());
}

TEST(PdbTest, readVillin)
{
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/villin_N68H.pdb",
               molecule);

  // how many atoms?
  EXPECT_EQ(molecule.atomCount(), 8867);

  // The reader walks the residue records of every MODEL, but atoms are only
  // added for MODEL 1 (subsequent models populate coordinate sets).  This
  // file has 10 models with 2798 residue transitions each, giving 27980.
  EXPECT_EQ(molecule.residueCount(), 27980);

  EXPECT_EQ(molecule.coordinate3dCount(), 10);
}

TEST(PdbTest, cryst1)
{
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/cryst1.pdb", molecule);

  EXPECT_EQ(molecule.atomCount(), 7);

  // make sure it has a unit cell
  bool hasUnitCell = (molecule.unitCell() != nullptr);
  EXPECT_TRUE(hasUnitCell);
}

TEST(PdbTest, cryst2)
{
  // Crash fixed with #2182.  The ATOM records in this file are missing the
  // residue name / chain / residue-id columns, so the hardened reader now
  // rejects them.  The important guarantee is no crash and that CRYST1
  // (parsed before any ATOM record) still produces a unit cell.
  PdbFormat pdb;
  Molecule molecule;
  const bool readOk =
    pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/cryst2.pdb", molecule);

  EXPECT_FALSE(readOk);
  EXPECT_EQ(molecule.atomCount(), 0);

  // make sure it has a unit cell
  bool hasUnitCell = (molecule.unitCell() != nullptr);
  EXPECT_TRUE(hasUnitCell);
}

TEST(PdbTest, cryst3)
{
  // Crash fixed with #2182
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/cryst3.pdb", molecule);

  EXPECT_EQ(molecule.atomCount(), 7);

  // make sure it has a unit cell
  bool hasUnitCell = (molecule.unitCell() != nullptr);
  EXPECT_TRUE(hasUnitCell);
}

TEST(PdbTest, pdb1)
{
  // Windows crash reported as #2456
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/1.pdb", molecule);

  // should be 60 atoms, sequence is TRP-LEU-ASN
  EXPECT_EQ(molecule.atomCount(), 60);

  // should be three residues
  EXPECT_EQ(molecule.residueCount(), 3);

  auto residues = molecule.residues();
  EXPECT_EQ(residues[0].residueName(), "TRP");
  EXPECT_EQ(residues[1].residueName(), "LEU");
  EXPECT_EQ(residues[2].residueName(), "ASN");
}

TEST(PdbTest, biomtPreservesCoordinateSets)
{
  const std::string pdbData =
    "REMARK 350 BIOMOLECULE: 1\n"
    "REMARK 350 APPLY THE FOLLOWING TO CHAINS: A\n"
    "REMARK 350   BIOMT1   1  1.000000  0.000000  0.000000        0.00000\n"
    "REMARK 350   BIOMT2   1  0.000000  1.000000  0.000000        0.00000\n"
    "REMARK 350   BIOMT3   1  0.000000  0.000000  1.000000        0.00000\n"
    "REMARK 350   BIOMT1   2  1.000000  0.000000  0.000000       10.00000\n"
    "REMARK 350   BIOMT2   2  0.000000  1.000000  0.000000        0.00000\n"
    "REMARK 350   BIOMT3   2  0.000000  0.000000  1.000000        0.00000\n"
    "MODEL        1\n"
    "ATOM      1  N   GLY A   1       1.000   2.000   3.000  1.00 20.00        "
    "   N  \n"
    "TER       2      GLY A   1\n"
    "ENDMDL\n"
    "MODEL        2\n"
    "ATOM      1  N   GLY A   1       4.000   5.000   6.000  1.00 20.00        "
    "   N  \n"
    "TER       2      GLY A   1\n"
    "ENDMDL\n"
    "END\n";

  PdbFormat pdb;
  Molecule molecule;
  std::istringstream input(pdbData);

  EXPECT_TRUE(pdb.read(input, molecule));
  EXPECT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(molecule.coordinate3dCount(), 2);
  EXPECT_EQ(molecule.coordinate3d(0).size(), molecule.atomCount());
  EXPECT_EQ(molecule.coordinate3d(1).size(), molecule.atomCount());

  EXPECT_DOUBLE_EQ(molecule.atomPosition3d(1).x(), 11.0);
  EXPECT_DOUBLE_EQ(molecule.atomPosition3d(1).y(), 2.0);
  EXPECT_DOUBLE_EQ(molecule.atomPosition3d(1).z(), 3.0);
  EXPECT_DOUBLE_EQ(molecule.coordinate3d(0)[1].x(), 11.0);
  EXPECT_DOUBLE_EQ(molecule.coordinate3d(1)[1].x(), 14.0);
  EXPECT_DOUBLE_EQ(molecule.coordinate3d(1)[1].y(), 5.0);
  EXPECT_DOUBLE_EQ(molecule.coordinate3d(1)[1].z(), 6.0);
}

TEST(PdbTest, biomtKeepsChainGroupsSeparated)
{
  const std::string pdbData =
    "REMARK 350 BIOMOLECULE: 1\n"
    "REMARK 350 APPLY THE FOLLOWING TO CHAINS: A\n"
    "REMARK 350   BIOMT1   1  1.000000  0.000000  0.000000        0.00000\n"
    "REMARK 350   BIOMT2   1  0.000000  1.000000  0.000000        0.00000\n"
    "REMARK 350   BIOMT3   1  0.000000  0.000000  1.000000        0.00000\n"
    "REMARK 350   BIOMT1   2  1.000000  0.000000  0.000000       10.00000\n"
    "REMARK 350   BIOMT2   2  0.000000  1.000000  0.000000        0.00000\n"
    "REMARK 350   BIOMT3   2  0.000000  0.000000  1.000000        0.00000\n"
    "REMARK 350 APPLY THE FOLLOWING TO CHAINS: B\n"
    "REMARK 350   BIOMT1   1  1.000000  0.000000  0.000000        0.00000\n"
    "REMARK 350   BIOMT2   1  0.000000  1.000000  0.000000        0.00000\n"
    "REMARK 350   BIOMT3   1  0.000000  0.000000  1.000000        0.00000\n"
    "REMARK 350   BIOMT1   2  1.000000  0.000000  0.000000        0.00000\n"
    "REMARK 350   BIOMT2   2  0.000000  1.000000  0.000000       20.00000\n"
    "REMARK 350   BIOMT3   2  0.000000  0.000000  1.000000        0.00000\n"
    "ATOM      1  N   GLY A   1       1.000   1.000   1.000  1.00 20.00        "
    "   N  \n"
    "ATOM      2  N   GLY B   2       2.000   2.000   2.000  1.00 20.00        "
    "   N  \n"
    "TER       3      GLY B   2\n"
    "END\n";

  PdbFormat pdb;
  Molecule molecule;
  std::istringstream input(pdbData);

  EXPECT_TRUE(pdb.read(input, molecule));
  EXPECT_EQ(molecule.atomCount(), 4);
  EXPECT_TRUE(hasAtomAt(molecule, 1.0, 1.0, 1.0));
  EXPECT_TRUE(hasAtomAt(molecule, 2.0, 2.0, 2.0));
  EXPECT_TRUE(hasAtomAt(molecule, 11.0, 1.0, 1.0));
  EXPECT_TRUE(hasAtomAt(molecule, 2.0, 22.0, 2.0));
  EXPECT_FALSE(hasAtomAt(molecule, 12.0, 2.0, 2.0));
  EXPECT_FALSE(hasAtomAt(molecule, 1.0, 21.0, 1.0));
}

TEST(PdbTest, chainChangeStartsNewResidue)
{
  const std::string pdbText = "ATOM      1  CA  GLY A   1      11.000  12.000  "
                              "13.000  1.00 20.00           C\n"
                              "TER       2      GLY A   1\n"
                              "ATOM      3  CA  GLY B   1      21.000  22.000  "
                              "23.000  1.00 20.00           C\n"
                              "END\n";

  PdbFormat pdb;
  Molecule molecule;
  ASSERT_TRUE(pdb.readString(pdbText, molecule)) << pdb.error();

  ASSERT_EQ(molecule.residueCount(), 2);
  EXPECT_EQ(molecule.residue(0).chainId(), 'A');
  EXPECT_EQ(molecule.residue(0).residueId(), 1);
  EXPECT_EQ(molecule.residue(1).chainId(), 'B');
  EXPECT_EQ(molecule.residue(1).residueId(), 1);
}

// A PDB record written out with exact column positions. The element field in
// columns 77-78 is deliberately left off, so these exercise the atom-name
// fallback. Columns: 1-6 record, 7-11 serial, 13-16 atom name, 18-20 residue,
// 22 chain, 23-26 residue sequence, 31-38/39-46/47-54 coordinates.
static std::string pdbAtomRecord(int serial, const std::string& name,
                                 const std::string& residue, int residueId,
                                 double x)
{
  std::ostringstream line;
  line << "ATOM  " << std::setw(5) << serial << ' ' << std::setw(4) << std::left
       << name << std::right << ' ' << std::setw(3) << residue << " A"
       << std::setw(4) << residueId << "    " << std::fixed
       << std::setprecision(3) << std::setw(8) << x << std::setw(8) << 0.0
       << std::setw(8) << 0.0 << "  1.00  0.00";
  return line.str() + "\n";
}

// The element symbol sits right justified in columns 13-14, so a leading
// space means a one-character symbol. " CA " is therefore a protein carbon
// alpha while "CA  " is a calcium ion, and getting that backwards silently
// turns a whole protein backbone into calcium (or drops it entirely).
TEST(PdbTest, elementFromAtomNameColumns)
{
  std::string contents;
  contents += pdbAtomRecord(1, " N  ", "ALA", 1, 0.0);
  contents += pdbAtomRecord(2, " CA ", "ALA", 1, 1.0);
  contents += pdbAtomRecord(3, " C  ", "ALA", 1, 2.0);
  contents += pdbAtomRecord(4, " O  ", "ALA", 1, 3.0);
  contents += pdbAtomRecord(5, " SG ", "CYS", 2, 4.0);
  contents += pdbAtomRecord(6, " OG1", "THR", 3, 5.0);
  contents += pdbAtomRecord(7, "1HB ", "ALA", 4, 6.0);
  contents += "HETATM    8 CA    CA A   5       7.000   0.000   0.000\n";
  contents += "HETATM    9 FE   HEM A   6       8.000   0.000   0.000\n";
  contents += "END\n";

  PdbFormat pdb;
  Molecule molecule;
  ASSERT_TRUE(pdb.readString(contents, molecule)) << pdb.error();
  ASSERT_EQ(molecule.atomCount(), 9);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 7);  // N
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 6);  // carbon alpha, not calcium
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 6);  // C
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 8);  // O
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 16); // sulfur gamma
  EXPECT_EQ(molecule.atom(5).atomicNumber(), 8);  // oxygen gamma 1
  EXPECT_EQ(molecule.atom(6).atomicNumber(), 1);  // numbered hydrogen
  EXPECT_EQ(molecule.atom(7).atomicNumber(), 20); // calcium ion
  EXPECT_EQ(molecule.atom(8).atomicNumber(), 26); // iron
}

// 1CRN.pdb is an old-style entry: columns 77-80 carry "1CRN" plus a line
// serial rather than an element symbol, so every record falls through to the
// atom-name fallback. Reading it used to drop the 189 atoms whose names are
// two characters long, which in turn shifted the CONECT serial mapping and
// read past the end of it, killing the process.
TEST(PdbTest, oldStyleElementColumns)
{
  PdbFormat pdb;
  Molecule molecule;
  ASSERT_TRUE(
    pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/1CRN.pdb", molecule))
    << pdb.error();

  // Crambin: 327 non-hydrogen atoms, and the file has exactly 327 ATOM
  // records. The six sulfurs are the three disulfide bridges.
  EXPECT_EQ(molecule.atomCount(), 327);
  int carbon = 0, nitrogen = 0, oxygen = 0, sulfur = 0, other = 0;
  for (Avogadro::Index i = 0; i < molecule.atomCount(); ++i) {
    switch (molecule.atom(i).atomicNumber()) {
      case 6:
        ++carbon;
        break;
      case 7:
        ++nitrogen;
        break;
      case 8:
        ++oxygen;
        break;
      case 16:
        ++sulfur;
        break;
      default:
        ++other;
        break;
    }
  }
  EXPECT_EQ(carbon, 202);
  EXPECT_EQ(nitrogen, 55);
  EXPECT_EQ(oxygen, 64);
  EXPECT_EQ(sulfur, 6);
  EXPECT_EQ(other, 0);

  // Every bond must reference a real atom. This is the invariant that the
  // unchecked CONECT lookup used to violate.
  for (Avogadro::Index i = 0; i < molecule.bondCount(); ++i) {
    EXPECT_LT(molecule.bond(i).atom1().index(), molecule.atomCount());
    EXPECT_LT(molecule.bond(i).atom2().index(), molecule.atomCount());
  }
}

// A CONECT serial past the end of the file's atoms must be ignored rather
// than used as an array index. These values come straight out of the file,
// and PDB files are routinely fetched over the network.
TEST(PdbTest, conectSerialOutOfRange)
{
  std::string contents;
  contents += pdbAtomRecord(1, " N  ", "ALA", 1, 0.0);
  contents += pdbAtomRecord(2, " CA ", "ALA", 1, 1.0);
  contents += "CONECT    1    2\n";
  contents += "CONECT    1 9999\n"; // second atom does not exist
  contents += "CONECT 4242    2\n"; // first atom does not exist
  contents += "CONECT   -5    2\n"; // negative after adjustment
  contents += "END\n";

  PdbFormat pdb;
  Molecule molecule;
  ASSERT_TRUE(pdb.readString(contents, molecule)) << pdb.error();
  EXPECT_EQ(molecule.atomCount(), 2);
  for (Avogadro::Index i = 0; i < molecule.bondCount(); ++i) {
    EXPECT_LT(molecule.bond(i).atom1().index(), molecule.atomCount());
    EXPECT_LT(molecule.bond(i).atom2().index(), molecule.atomCount());
  }
}

// A record that cannot be turned into an atom still has to occupy its slot in
// the serial-number mapping, or every later CONECT record bonds the wrong
// pair. "XX" is not an element under either fallback.
TEST(PdbTest, skippedRecordKeepsConectAligned)
{
  std::string contents;
  contents += pdbAtomRecord(1, " N  ", "ALA", 1, 0.0);
  contents += pdbAtomRecord(2, "XX  ", "UNK", 1, 1.0); // unresolvable
  contents += pdbAtomRecord(3, " C  ", "ALA", 1, 2.0);
  contents += pdbAtomRecord(4, " O  ", "ALA", 1, 3.0);
  contents += "CONECT    3    4\n"; // the two atoms after the skipped record
  contents += "END\n";

  PdbFormat pdb;
  Molecule molecule;
  ASSERT_TRUE(pdb.readString(contents, molecule)) << pdb.error();
  ASSERT_EQ(molecule.atomCount(), 3); // N, C, O -- the "XX" record is dropped

  // Serials 3 and 4 are the carbon and the oxygen, which are atoms 1 and 2
  // once the unreadable record is gone. Before the fix the mapping was short
  // by one and this bonded the wrong atoms.
  bool bondedCarbonToOxygen = false;
  for (Avogadro::Index i = 0; i < molecule.bondCount(); ++i) {
    const auto z1 = molecule.bond(i).atom1().atomicNumber();
    const auto z2 = molecule.bond(i).atom2().atomicNumber();
    if ((z1 == 6 && z2 == 8) || (z1 == 8 && z2 == 6))
      bondedCarbonToOxygen = true;
  }
  EXPECT_TRUE(bondedCarbonToOxygen);
}

// Build a record that also fills the element (77-78) and charge (79-80)
// fields, which pdbAtomRecord deliberately leaves off.
static std::string pdbAtomRecordWithElement(int serial, const std::string& name,
                                            const std::string& residue,
                                            int residueId, double x,
                                            const std::string& element,
                                            const std::string& charge)
{
  std::string line = pdbAtomRecord(serial, name, residue, residueId, x);
  if (!line.empty() && line.back() == '\n')
    line.pop_back();
  line.resize(76, ' ');
  line += (element.size() == 2) ? element : (" " + element); // right justified
  line.resize(78, ' ');
  line += charge;
  line.resize(80, ' ');
  return line + "\n";
}

// Columns 77-78 are the element field and take precedence over any guess made
// from the atom name.
TEST(PdbTest, elementColumnWinsOverAtomName)
{
  std::string contents;
  // An atom name that identifies nothing, with a perfectly good element field.
  contents += pdbAtomRecordWithElement(1, "XX  ", "UNK", 1, 0.0, "C", "  ");
  // A name that would read as carbon by the column convention, but the file
  // says calcium, so calcium it is.
  contents += pdbAtomRecordWithElement(2, " CA ", "UNK", 1, 1.0, "CA", "  ");
  // Lower case in the file is still a valid symbol once normalised.
  contents += pdbAtomRecordWithElement(3, "ZN  ", "UNK", 1, 2.0, "zn", "  ");
  contents += "END\n";

  PdbFormat pdb;
  Molecule molecule;
  ASSERT_TRUE(pdb.readString(contents, molecule)) << pdb.error();
  ASSERT_EQ(molecule.atomCount(), 3);
  EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 20);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 30);
}

// Columns 79-80 carry the formal charge, magnitude first then sign.
TEST(PdbTest, formalChargeColumns)
{
  std::string contents;
  contents += pdbAtomRecordWithElement(1, "NA  ", "UNK", 1, 0.0, "NA", "1+");
  contents += pdbAtomRecordWithElement(2, "CL  ", "UNK", 1, 1.0, "CL", "1-");
  contents += pdbAtomRecordWithElement(3, "MG  ", "UNK", 1, 2.0, "MG", "2+");
  contents += pdbAtomRecordWithElement(4, " O  ", "UNK", 1, 3.0, "O", "  ");
  // Some writers put the sign first.
  contents += pdbAtomRecordWithElement(5, "FE  ", "UNK", 1, 4.0, "FE", "+3");
  contents += "END\n";

  PdbFormat pdb;
  Molecule molecule;
  ASSERT_TRUE(pdb.readString(contents, molecule)) << pdb.error();
  ASSERT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.atom(0).formalCharge(), 1);
  EXPECT_EQ(molecule.atom(1).formalCharge(), -1);
  EXPECT_EQ(molecule.atom(2).formalCharge(), 2);
  EXPECT_EQ(molecule.atom(3).formalCharge(), 0);
  EXPECT_EQ(molecule.atom(4).formalCharge(), 3);
}

// Anything that is not a magnitude and a sign is not a charge. Files written
// before those columns were defined put other things there, and 1CRN.pdb is
// exactly that case: it runs "1CRN" plus a line serial through columns 73-80,
// leaving digits in 79-80 for every one of its 327 atoms.
TEST(PdbTest, nonChargeInChargeColumnsIgnored)
{
  std::string contents;
  contents += pdbAtomRecordWithElement(1, " N  ", "UNK", 1, 0.0, "N", "70");
  contents += pdbAtomRecordWithElement(2, " C  ", "UNK", 1, 1.0, "C", "-9");
  contents += "END\n";

  PdbFormat pdb;
  Molecule molecule;
  ASSERT_TRUE(pdb.readString(contents, molecule)) << pdb.error();
  ASSERT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(molecule.atom(0).formalCharge(), 0)
    << "two digits are not a charge";
  EXPECT_EQ(molecule.atom(1).formalCharge(), -9) << "sign first is a charge";

  PdbFormat crn;
  Molecule crambin;
  ASSERT_TRUE(
    crn.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/1CRN.pdb", crambin))
    << crn.error();
  for (Avogadro::Index i = 0; i < crambin.atomCount(); ++i)
    ASSERT_EQ(crambin.atom(i).formalCharge(), 0)
      << "atom " << i << " picked up a line serial as a charge";
}
