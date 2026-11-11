/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>

#include <avogadro/io/mdlformat.h>
#include <avogadro/io/sdfformat.h>

#include <cctype>
#include <cmath>
#include <clocale>
#include <cstdio>
#include <sstream>
#include <string>

using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Molecule;
using Avogadro::Core::SP2;
using Avogadro::Core::Variant;
using Avogadro::Io::FileFormat;
using Avogadro::Io::MdlFormat;
using Avogadro::Io::MdlV3000Format;
using Avogadro::Io::SdfFormat;
using Avogadro::Io::SdfV3000Format;

TEST(MdlTest, readFile)
{
  MdlFormat mdl;
  Molecule molecule;
  bool success =
    mdl.readFile(std::string(AVOGADRO_DATA) + "/data/sdf/ethane.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").type(), Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
}

TEST(MdlTest, atoms)
{
  MdlFormat mdl;
  Molecule molecule;
  bool success =
    mdl.readFile(std::string(AVOGADRO_DATA) + "/data/sdf/ethane.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  Atom atom = molecule.atom(0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  atom = molecule.atom(1);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_DOUBLE_EQ(atom.position3d().x(), 0.7516);
  EXPECT_DOUBLE_EQ(atom.position3d().y(), -0.0224);
  EXPECT_DOUBLE_EQ(atom.position3d().z(), -0.0208);

  atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_DOUBLE_EQ(atom.position3d().x(), -1.1850);
  EXPECT_DOUBLE_EQ(atom.position3d().y(), 0.0044);
  EXPECT_DOUBLE_EQ(atom.position3d().z(), -0.9875);
}

TEST(MdlTest, bonds)
{
  MdlFormat mdl;
  Molecule molecule;
  bool success =
    mdl.readFile(std::string(AVOGADRO_DATA) + "/data/sdf/ethane.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(7));

  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
  bond = molecule.bond(6);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(4));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(7));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(MdlTest, saveFile)
{
  MdlFormat mdl;
  Molecule savedMolecule, molecule;
  bool success = mdl.readFile(
    std::string(AVOGADRO_DATA) + "/data/sdf/ethane.mol", savedMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");

  success = mdl.writeFile("ethanetmp.mol", savedMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");

  // Now read the file back in and check a few key values are still present.
  success = mdl.readFile("ethanetmp.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(7));
  Atom atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_DOUBLE_EQ(atom.position3d().x(), -1.1850);
  EXPECT_DOUBLE_EQ(atom.position3d().y(), 0.0044);
  EXPECT_DOUBLE_EQ(atom.position3d().z(), -0.9875);
  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(MdlTest, readMulti)
{
  MdlFormat multi;
  multi.open(AVOGADRO_DATA "/data/sdf/multi.sdf",
             FileFormat::Read | FileFormat::MultiMolecule);
  Molecule molecule;

  // Read in the first structure.
  EXPECT_TRUE(multi.readMolecule(molecule));
  ASSERT_EQ(multi.error(), "");

  EXPECT_EQ(molecule.data("name").toString(), "Methane");
  EXPECT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.bondCount(), 4);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 1);

  EXPECT_DOUBLE_EQ(molecule.atom(4).position3d().x(), -0.5134);
  EXPECT_DOUBLE_EQ(molecule.atom(4).position3d().y(), 0.8892);
  EXPECT_DOUBLE_EQ(molecule.atom(4).position3d().z(), -0.3630);

  // Now read in the second structure.
  Molecule molecule2;
  EXPECT_TRUE(multi.readMolecule(molecule2));
  ASSERT_EQ(multi.error(), "");
  EXPECT_EQ(molecule2.data("name").toString(), "Caffeine");
  EXPECT_EQ(molecule2.atomCount(), 24);
  EXPECT_EQ(molecule2.bondCount(), 25);

  // Should return false when there are no more molecules to be read in.
  EXPECT_FALSE(multi.readMolecule(molecule));
}

TEST(MdlTest, writeMulti)
{
  MdlFormat multi;
  multi.open(AVOGADRO_DATA "/data/sdf/multi.sdf",
             FileFormat::Read | FileFormat::MultiMolecule);
  Molecule mol[2];

  // Read in the two structures in the file.
  EXPECT_TRUE(multi.readMolecule(mol[0]));
  ASSERT_EQ(multi.error(), "");
  EXPECT_TRUE(multi.readMolecule(mol[1]));
  ASSERT_EQ(multi.error(), "");
  multi.close();

  // Now attempt to write out a multi-molecule file.
  multi.open("multitmp.sdf", FileFormat::Write | FileFormat::MultiMolecule);
  multi.writeMolecule(mol[0]);
  multi.writeMolecule(mol[1]);
  multi.close();

  // Finally, let's read them back in and check the basic properties match.
  multi.open("multitmp.sdf", FileFormat::Read | FileFormat::MultiMolecule);
  Molecule ref[2];
  EXPECT_TRUE(multi.readMolecule(ref[0]));
  EXPECT_TRUE(multi.readMolecule(ref[1]));
  // Compare some properties and see if they made it all the way back to us.
  for (int i = 0; i < 2; ++i) {
    EXPECT_EQ(mol[i].data("name").toString(), ref[i].data("name").toString());
    EXPECT_EQ(mol[i].atomCount(), ref[i].atomCount());
    EXPECT_EQ(mol[i].bondCount(), ref[i].bondCount());
  }
}

TEST(MdlTest, readSdfData)
{
  MdlFormat multi;
  multi.open(AVOGADRO_DATA "/data/sdf/pubchem3.sdf",
             FileFormat::Read | FileFormat::MultiMolecule);
  Molecule mol[2];
  EXPECT_TRUE(multi.readMolecule(mol[0]));
  EXPECT_TRUE(multi.readMolecule(mol[1]));

  // Check a few of the data parameters in the first few molecules.
  EXPECT_EQ(
    mol[0].data("PUBCHEM_IUPAC_INCHI").toString(),
    "InChI=1S/C9H17NO4/c1-7(11)14-8(5-9(12)13)6-10(2,3)4/h8H,5-6H2,1-4H3");
  EXPECT_EQ(mol[0].data("PUBCHEM_OPENEYE_CAN_SMILES").toString(),
            "CC(=O)OC(CC(=O)[O-])C[N+](C)(C)C");
  EXPECT_EQ(
    mol[1].data("PUBCHEM_IUPAC_INCHI").toString(),
    "InChI=1S/C9H17NO4/c1-7(11)14-8(5-9(12)13)6-10(2,3)4/h8H,5-6H2,1-4H3/p+1");
  EXPECT_EQ(mol[1].data("PUBCHEM_OPENEYE_CAN_SMILES").toString(),
            "CC(=O)OC(CC(=O)O)C[N+](C)(C)C");
}

TEST(MdlTest, readV2000Valence)
{
  // Test that the vvv valence field in V2000 atom lines sets hybridization.
  // The carbene_v2000.mol file has two carbene carbons (atoms 8, 15)
  // with VAL=3, which should be interpreted as SP2 hybridization.
  MdlFormat mdl;
  Molecule molecule;
  bool success = mdl.readFile(
    std::string(AVOGADRO_DATA) + "/data/sdf/carbene_v2000.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(27));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(29));

  // Carbene carbons at indices 8 and 15 should have SP2 hybridization
  Atom carbene1 = molecule.atom(8);
  EXPECT_EQ(carbene1.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(carbene1.hybridization(), SP2);

  Atom carbene2 = molecule.atom(15);
  EXPECT_EQ(carbene2.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(carbene2.hybridization(), SP2);

  // A normal carbon (e.g., atom 0) should not have hybridization set
  Atom normalC = molecule.atom(0);
  EXPECT_EQ(normalC.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(normalC.hybridization(), Avogadro::Core::HybridizationUnknown);
}

TEST(MdlTest, readV3000Valence)
{
  // Test that the VAL= property in V3000 atom lines sets hybridization.
  // The carbene_v3000.mol file has two carbene carbons (atoms 8, 15)
  // with VAL=3, which should be interpreted as SP2 hybridization.
  MdlFormat mdl;
  Molecule molecule;
  bool success = mdl.readFile(
    std::string(AVOGADRO_DATA) + "/data/sdf/carbene_v3000.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(27));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(29));

  // Carbene carbons at indices 8 and 15 should have SP2 hybridization
  Atom carbene1 = molecule.atom(8);
  EXPECT_EQ(carbene1.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(carbene1.hybridization(), SP2);

  Atom carbene2 = molecule.atom(15);
  EXPECT_EQ(carbene2.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(carbene2.hybridization(), SP2);

  // A normal carbon (e.g., atom 0) should not have hybridization set
  Atom normalC = molecule.atom(0);
  EXPECT_EQ(normalC.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(normalC.hybridization(), Avogadro::Core::HybridizationUnknown);
}

namespace {

/**
 * Assert that @a molecule is benzene whose aromatic ring came back kekulized:
 * no bond left at the aromatic order, and the ring alternating three double
 * with three single bonds.
 *
 * Ring bonds are looked up by their endpoints rather than by bond index, so
 * this does not quietly depend on the order the reader happened to add them
 * in. The first six atoms are the ring, in order around it.
 */
void expectKekulizedBenzene(const Molecule& molecule)
{
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(12));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(12));

  int doubleCount = 0;
  int singleCount = 0;
  for (size_t i = 0; i < molecule.bondCount(); ++i) {
    const unsigned char order = molecule.bond(i).order();
    EXPECT_LE(order, static_cast<unsigned char>(2))
      << "bond " << i << " should be single or double after kekulization,"
      << " rather than still carrying the aromatic order";
    if (order == 2)
      ++doubleCount;
    else if (order == 1)
      ++singleCount;
  }
  EXPECT_EQ(doubleCount, 3);
  EXPECT_EQ(singleCount, 9); // Three ring single bonds, plus six C-H.

  int ringDouble = 0;
  for (Avogadro::Index i = 0; i < 6; ++i) {
    const Bond ring = molecule.bond(i, (i + 1) % 6);
    ASSERT_TRUE(ring.isValid()) << "ring bond " << i << " is missing";
    if (ring.order() == 2)
      ++ringDouble;
  }
  EXPECT_EQ(ringDouble, 3); // The ring bonds specifically must alternate.
}

} // namespace

TEST(MdlTest, aromaticBondType4IsKekulized)
{
  // Benzene, its six ring bonds written as MDL bond type 4 (aromatic).
  // Before kekulize() was wired in, type 4 was passed straight to addBond()
  // and became a quadruple bond; now it should come back as alternating
  // single and double bonds, not all one order.
  const std::string molfile =
    "Benzene\n"
    "  Test2D\n"
    "\n"
    " 12 12  0  0  0  0  0  0  0  0999 V2000\n"
    "    1.2000    0.0000    0.0000 C   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "    0.6000    1.0000    0.0000 C   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "   -0.6000    1.0000    0.0000 C   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "   -1.2000    0.0000    0.0000 C   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "   -0.6000   -1.0000    0.0000 C   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "    0.6000   -1.0000    0.0000 C   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "    2.2000    0.0000    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "    1.1000    1.9000    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "   -1.1000    1.9000    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "   -2.2000    0.0000    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "   -1.1000   -1.9000    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "    1.1000   -1.9000    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "  1  2  4  0  0  0  0\n"
    "  2  3  4  0  0  0  0\n"
    "  3  4  4  0  0  0  0\n"
    "  4  5  4  0  0  0  0\n"
    "  5  6  4  0  0  0  0\n"
    "  6  1  4  0  0  0  0\n"
    "  1  7  1  0  0  0  0\n"
    "  2  8  1  0  0  0  0\n"
    "  3  9  1  0  0  0  0\n"
    "  4 10  1  0  0  0  0\n"
    "  5 11  1  0  0  0  0\n"
    "  6 12  1  0  0  0  0\n"
    "M  END\n";

  MdlFormat mdl;
  Molecule molecule;
  ASSERT_TRUE(mdl.readString(molfile, molecule)) << mdl.error();
  expectKekulizedBenzene(molecule);
}

TEST(MdlTest, aromaticBondType4IsKekulizedV3000)
{
  // The same benzene in V3000, whose bond block is parsed by a separate
  // function that had the same bug: order 4 went straight to addBond().
  const std::string molfile = "Benzene\n"
                              "  Test3D\n"
                              "\n"
                              "  0  0  0     0  0            999 V3000\n"
                              "M  V30 BEGIN CTAB\n"
                              "M  V30 COUNTS 12 12 0 0 0\n"
                              "M  V30 BEGIN ATOM\n"
                              "M  V30 1 C 1.2 0.0 0.0 0\n"
                              "M  V30 2 C 0.6 1.0 0.0 0\n"
                              "M  V30 3 C -0.6 1.0 0.0 0\n"
                              "M  V30 4 C -1.2 0.0 0.0 0\n"
                              "M  V30 5 C -0.6 -1.0 0.0 0\n"
                              "M  V30 6 C 0.6 -1.0 0.0 0\n"
                              "M  V30 7 H 2.2 0.0 0.0 0\n"
                              "M  V30 8 H 1.1 1.9 0.0 0\n"
                              "M  V30 9 H -1.1 1.9 0.0 0\n"
                              "M  V30 10 H -2.2 0.0 0.0 0\n"
                              "M  V30 11 H -1.1 -1.9 0.0 0\n"
                              "M  V30 12 H 1.1 -1.9 0.0 0\n"
                              "M  V30 END ATOM\n"
                              "M  V30 BEGIN BOND\n"
                              "M  V30 1 4 1 2\n"
                              "M  V30 2 4 2 3\n"
                              "M  V30 3 4 3 4\n"
                              "M  V30 4 4 4 5\n"
                              "M  V30 5 4 5 6\n"
                              "M  V30 6 4 6 1\n"
                              "M  V30 7 1 1 7\n"
                              "M  V30 8 1 2 8\n"
                              "M  V30 9 1 3 9\n"
                              "M  V30 10 1 4 10\n"
                              "M  V30 11 1 5 11\n"
                              "M  V30 12 1 6 12\n"
                              "M  V30 END BOND\n"
                              "M  V30 END CTAB\n"
                              "M  END\n";

  MdlFormat mdl;
  Molecule molecule;
  ASSERT_TRUE(mdl.readString(molfile, molecule)) << mdl.error();
  expectKekulizedBenzene(molecule);
}

namespace {
// A chloro-bromo-iron triatomic with the element symbols supplied by caller.
std::string v2000Symbols(const char* fe, const char* cl, const char* br,
                         const char* mixed, const char* c)
{
  auto line = [](double x, const char* sym) {
    char buf[96];
    snprintf(buf, sizeof(buf),
             "%10.4f%10.4f%10.4f %-3s 0  0  0  0  0  0  0  0  0  0  0  0\n", x,
             0.0, 0.0, sym);
    return std::string(buf);
  };
  return "Symbols\n  Test3D\n\n  5  0  0  0  0  0  0  0  0  0999 V2000\n" +
         line(0.0, fe) + line(1.0, cl) + line(2.0, br) + line(3.0, mixed) +
         line(4.0, c) + "M  END\n";
}
} // namespace

TEST(MdlTest, upperCaseSymbolsV2000)
{
  const std::string molfile = v2000Symbols("FE", "CL", "BR", "cL", "C");
  MdlFormat mdl;
  Molecule molecule;
  ASSERT_TRUE(mdl.readString(molfile, molecule)) << mdl.error();
  ASSERT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.atom(0).atomicNumber(), 26);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 17);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 35);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 17);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 6);
}

TEST(MdlTest, upperCaseSymbolsV3000)
{
  const std::string molfile = "Symbols\n"
                              "  Test3D\n"
                              "\n"
                              "  0  0  0     0  0            999 V3000\n"
                              "M  V30 BEGIN CTAB\n"
                              "M  V30 COUNTS 5 0 0 0 0\n"
                              "M  V30 BEGIN ATOM\n"
                              "M  V30 1 FE 0.0 0.0 0.0 0\n"
                              "M  V30 2 CL 1.0 0.0 0.0 0\n"
                              "M  V30 3 BR 2.0 0.0 0.0 0\n"
                              "M  V30 4 cL 3.0 0.0 0.0 0\n"
                              "M  V30 5 C 4.0 0.0 0.0 0\n"
                              "M  V30 END ATOM\n"
                              "M  V30 BEGIN BOND\n"
                              "M  V30 END BOND\n"
                              "M  V30 END CTAB\n"
                              "M  END\n";
  MdlFormat mdl;
  Molecule molecule;
  ASSERT_TRUE(mdl.readString(molfile, molecule)) << mdl.error();
  ASSERT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.atom(0).atomicNumber(), 26);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 17);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 35);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 17);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 6);
}

// Under a Turkish LC_CTYPE (e.g. glibc's tr_TR.ISO-8859-9) std::tolower('I')
// is a dotless i, so a locale-dependent normalisation would read "SI" as
// "S\xFD" and lose the silicon. Skipped where no such locale is installed.
TEST(MdlTest, upperCaseSymbolsTurkishLocale)
{
  const char* previous = std::setlocale(LC_CTYPE, nullptr);
  const std::string saved = previous ? previous : "C";
  bool hazard = false;
  for (const char* name :
       { "tr_TR.ISO-8859-9", "tr_TR.ISO8859-9", "tr_TR.iso88599", "tr_TR" }) {
    if (std::setlocale(LC_CTYPE, name) && std::tolower('I') != 'i') {
      hazard = true;
      break;
    }
  }
  if (!hazard) {
    std::setlocale(LC_CTYPE, saved.c_str());
    GTEST_SKIP() << "No locale where tolower('I') != 'i'";
  }

  const std::string molfile = v2000Symbols("SI", "BI", "LI", "IN", "C");
  MdlFormat mdl;
  Molecule molecule;
  const bool ok = mdl.readString(molfile, molecule);
  std::setlocale(LC_CTYPE, saved.c_str());
  ASSERT_TRUE(ok) << mdl.error();
  ASSERT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.atom(0).atomicNumber(), 14);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 83);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 3);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 49);
}

TEST(MdlTest, deuteriumSymbols)
{
  MdlFormat mdl;
  Molecule v2;
  ASSERT_TRUE(mdl.readString(v2000Symbols("D", "d", "T", "t", "H"), v2))
    << mdl.error();
  ASSERT_EQ(v2.atomCount(), 5);
  for (size_t i = 0; i < 5; ++i)
    EXPECT_EQ(v2.atom(i).atomicNumber(), 1);
  EXPECT_EQ(v2.isotope(0), 2);
  EXPECT_EQ(v2.isotope(1), 2);
  EXPECT_EQ(v2.isotope(2), 3);
  EXPECT_EQ(v2.isotope(3), 3);

  const std::string v3 = "D\n  Test3D\n\n"
                         "  0  0  0     0  0            999 V3000\n"
                         "M  V30 BEGIN CTAB\n"
                         "M  V30 COUNTS 2 0 0 0 0\n"
                         "M  V30 BEGIN ATOM\n"
                         "M  V30 1 D 0.0 0.0 0.0 0\n"
                         "M  V30 2 t 1.0 0.0 0.0 0\n"
                         "M  V30 END ATOM\n"
                         "M  V30 BEGIN BOND\n"
                         "M  V30 END BOND\n"
                         "M  V30 END CTAB\n"
                         "M  END\n";
  Molecule v3m;
  ASSERT_TRUE(mdl.readString(v3, v3m)) << mdl.error();
  EXPECT_EQ(v3m.atom(0).atomicNumber(), 1);
  EXPECT_EQ(v3m.isotope(0), 2);
  EXPECT_EQ(v3m.atom(1).atomicNumber(), 1);
  EXPECT_EQ(v3m.isotope(1), 3);
}

TEST(MdlTest, upperCaseSymbolsConformerMatch)
{
  // A second SDF record with the same atoms is folded in as another
  // coordinate set when its elements match the first record. The second
  // record writes its symbols in upper case; it must still match.
  const std::string sdf = v2000Symbols("Fe", "Cl", "Br", "Cl", "C") + "$$$$\n" +
                          v2000Symbols("FE", "CL", "BR", "CL", "C") + "$$$$\n";
  MdlFormat mdl;
  Molecule molecule;
  ASSERT_TRUE(mdl.readString(sdf, molecule)) << mdl.error();
  EXPECT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.coordinate3dCount(), 2);
}

namespace {
// Ethylene as written by GaussView: no version tag on the counts line.
std::string gaussViewEthylene(const std::string& eol, double dz = 0.0)
{
  const std::string z = (dz == 0.0) ? "0.0000" : "0.1000";
  return "Title: ethylene" + eol + eol + "Created by GaussView 6.1.1" + eol +
         "  6  5  0  0  0  0  0  0  0  0  0    0" + eol +
         "    0.0000    0.0000    " + z +
         " C   0  0  0  0  0  0  0  0  0  0  0  0" + eol +
         "    1.3300    0.0000    0.0000 C   0  0  0  0  0  0  0  0  0  0  0  "
         "0" +
         eol +
         "   -0.5600    0.9200    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  "
         "0" +
         eol +
         "   -0.5600   -0.9200    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  "
         "0" +
         eol +
         "    1.8900    0.9200    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  "
         "0" +
         eol +
         "    1.8900   -0.9200    0.0000 H   0  0  0  0  0  0  0  0  0  0  0  "
         "0" +
         eol + "  1  2  2  0  0  0" + eol + "  1  3  1  0  0  0" + eol +
         "  1  4  1  0  0  0" + eol + "  2  5  1  0  0  0" + eol +
         "  2  6  1  0  0  0" + eol + "M  END" + eol;
}
} // namespace

TEST(MdlTest, readWithoutVersionTag)
{
  // A missing version field means V2000, with either line ending.
  for (const std::string eol : { "\n", "\r\n" }) {
    MdlFormat mdl;
    Molecule molecule;
    ASSERT_TRUE(mdl.readString(gaussViewEthylene(eol), molecule))
      << mdl.error();
    EXPECT_EQ(molecule.atomCount(), 6);
    EXPECT_EQ(molecule.bondCount(), 5);
    EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
    EXPECT_EQ(molecule.atom(1).atomicNumber(), 6);
    EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
    EXPECT_EQ(molecule.bond(0).order(), 2);
  }
}

TEST(MdlTest, readShortCountsLine)
{
  // Only the atom and bond counts are required.
  const std::string mol =
    "Short\n\n\n  1  0\n"
    "    0.0000    0.0000    0.0000 He  0  0  0  0  0\nM  END\n";
  MdlFormat mdl;
  Molecule molecule;
  ASSERT_TRUE(mdl.readString(mol, molecule)) << mdl.error();
  EXPECT_EQ(molecule.atomCount(), 1);
  EXPECT_EQ(molecule.atom(0).atomicNumber(), 2);

  Molecule bad;
  EXPECT_FALSE(mdl.readString("Bad\n\n\n  1\n", bad));
}

TEST(MdlTest, readMultiWithoutVersionTag)
{
  // The second record is folded in as a conformer via the same path.
  const std::string sdf = gaussViewEthylene("\n") + "$$$$\n" +
                          gaussViewEthylene("\n", 0.1) + "$$$$\n";
  MdlFormat mdl;
  Molecule molecule;
  ASSERT_TRUE(mdl.readString(sdf, molecule)) << mdl.error();
  EXPECT_EQ(molecule.atomCount(), 6);
  EXPECT_EQ(molecule.coordinate3dCount(), 2);
}

namespace {
// Acetate with a 13C methyl: formal charge, isotope, single and double bonds.
Molecule makeAcetate()
{
  Molecule mol;
  mol.setData("name", std::string("acetate"));
  Atom c1 = mol.addAtom(6);
  c1.setPosition3d(Avogadro::Vector3(0.0, 0.0, 0.0));
  c1.setIsotope(13);
  Atom c2 = mol.addAtom(6);
  c2.setPosition3d(Avogadro::Vector3(1.5, 0.0, 0.0));
  Atom o1 = mol.addAtom(8);
  o1.setPosition3d(Avogadro::Vector3(2.1, 1.1, 0.0));
  Atom o2 = mol.addAtom(8);
  o2.setPosition3d(Avogadro::Vector3(2.1, -1.1, 0.0));
  o2.setFormalCharge(-1);
  mol.addBond(c1, c2, 1);
  mol.addBond(c2, o1, 2);
  mol.addBond(c2, o2, 1);
  return mol;
}

void expectAcetate(const Molecule& mol)
{
  ASSERT_EQ(mol.atomCount(), static_cast<size_t>(4));
  ASSERT_EQ(mol.bondCount(), static_cast<size_t>(3));
  EXPECT_EQ(mol.atom(0).isotope(), 13);
  EXPECT_EQ(mol.atom(1).isotope(), 0);
  EXPECT_EQ(mol.atom(3).formalCharge(), -1);
  EXPECT_EQ(mol.atom(2).formalCharge(), 0);
  EXPECT_EQ(mol.atom(3).atomicNumber(), static_cast<unsigned char>(8));
  EXPECT_NEAR(mol.atom(2).position3d().x(), 2.1, 1e-5);
  EXPECT_NEAR(mol.atom(3).position3d().y(), -1.1, 1e-5);
  int doubles = 0;
  for (size_t i = 0; i < mol.bondCount(); ++i)
    if (mol.bond(i).order() == 2)
      ++doubles;
  EXPECT_EQ(doubles, 1);
}
} // namespace

TEST(MdlTest, writeV2000IsDefault)
{
  Molecule mol = makeAcetate();
  MdlFormat mdl;
  std::string out;
  ASSERT_TRUE(mdl.writeString(out, mol));
  EXPECT_NE(out.find("V2000"), std::string::npos);
  EXPECT_EQ(out.find("V3000"), std::string::npos);
  // isotopes and charges are carried in V2000 property lines
  EXPECT_NE(out.find("M  ISO  1   1  13"), std::string::npos);
  EXPECT_NE(out.find("M  CHG  1   4  -1"), std::string::npos);

  MdlFormat reader;
  Molecule back;
  ASSERT_TRUE(reader.readString(out, back));
  expectAcetate(back);
}

TEST(MdlTest, writeV3000Variant)
{
  Molecule mol = makeAcetate();
  MdlV3000Format mdl;
  EXPECT_FALSE(mdl.supportedOperations() & FileFormat::Read);
  std::string out;
  ASSERT_TRUE(mdl.writeString(out, mol));
  EXPECT_NE(out.find("V3000"), std::string::npos);
  EXPECT_NE(out.find("M  V30 BEGIN CTAB"), std::string::npos);
  EXPECT_NE(out.find("CHG=-1"), std::string::npos);
  EXPECT_NE(out.find("MASS=13"), std::string::npos);
  EXPECT_EQ(out.find("V2000"), std::string::npos);

  MdlFormat reader;
  Molecule back;
  ASSERT_TRUE(reader.readString(out, back));
  expectAcetate(back);
  EXPECT_EQ(back.data("name").toString(), "acetate");
}

TEST(MdlTest, writeV3000Option)
{
  Molecule mol = makeAcetate();
  MdlFormat mdl;
  mdl.setOptions("{ \"v3000\": true }");
  std::string out;
  ASSERT_TRUE(mdl.writeString(out, mol));
  EXPECT_NE(out.find("M  V30 BEGIN CTAB"), std::string::npos);

  MdlFormat off;
  off.setOptions("{ \"v3000\": false }");
  out.clear();
  ASSERT_TRUE(off.writeString(out, mol));
  EXPECT_NE(out.find("V2000"), std::string::npos);
}

TEST(MdlTest, writeV3000KekuleRing)
{
  // benzene: alternating single/double bonds
  Molecule mol;
  for (int i = 0; i < 6; ++i) {
    Atom a = mol.addAtom(6);
    double angle = i * 3.14159265358979 / 3.0;
    a.setPosition3d(
      Avogadro::Vector3(1.4 * std::cos(angle), 1.4 * std::sin(angle), 0.0));
  }
  for (int i = 0; i < 6; ++i)
    mol.addBond(mol.atom(i), mol.atom((i + 1) % 6), (i % 2) ? 1 : 2);
  MdlV3000Format mdl;
  std::string out;
  ASSERT_TRUE(mdl.writeString(out, mol));
  MdlFormat reader;
  Molecule back;
  ASSERT_TRUE(reader.readString(out, back));
  ASSERT_EQ(back.bondCount(), static_cast<size_t>(6));
  int doubles = 0;
  for (size_t i = 0; i < 6; ++i)
    if (back.bond(i).order() == 2)
      ++doubles;
  EXPECT_EQ(doubles, 3);
}

TEST(MdlTest, readV3000AromaticBonds)
{
  // order 4 in a V3000 file is kekulized on read
  std::string v3000 =
    "benzene\n  test\n\n  0  0  0     0  0            999 V3000\n"
    "M  V30 BEGIN CTAB\nM  V30 COUNTS 6 6 0 0 0\nM  V30 BEGIN ATOM\n"
    "M  V30 1 C 1.4 0 0 0\nM  V30 2 C 0.7 1.2 0 0\n"
    "M  V30 3 C -0.7 1.2 0 0\nM  V30 4 C -1.4 0 0 0\n"
    "M  V30 5 C -0.7 -1.2 0 0\nM  V30 6 C 0.7 -1.2 0 0\n"
    "M  V30 END ATOM\nM  V30 BEGIN BOND\n"
    "M  V30 1 4 1 2\nM  V30 2 4 2 3\nM  V30 3 4 3 4\n"
    "M  V30 4 4 4 5\nM  V30 5 4 5 6\nM  V30 6 4 6 1\n"
    "M  V30 END BOND\nM  V30 END CTAB\nM  END\n";
  MdlFormat reader;
  Molecule mol;
  ASSERT_TRUE(reader.readString(v3000, mol));
  int doubles = 0;
  for (size_t i = 0; i < mol.bondCount(); ++i)
    if (mol.bond(i).order() == 2)
      ++doubles;
  EXPECT_EQ(doubles, 3);
}

TEST(MdlTest, writeSdfV3000MultiRecord)
{
  Molecule mol = makeAcetate();
  mol.setData("PUBCHEM_ID", std::string("175"));
  SdfV3000Format sdf;
  EXPECT_FALSE(sdf.supportedOperations() & FileFormat::Read);
  std::ostringstream out;
  ASSERT_TRUE(sdf.write(out, mol));
  ASSERT_TRUE(sdf.write(out, mol));
  const std::string text = out.str();

  size_t records = 0, v30 = 0, data = 0, pos = 0;
  while ((pos = text.find("$$$$", pos)) != std::string::npos) {
    ++records;
    pos += 4;
  }
  for (pos = 0;
       (pos = text.find("M  V30 BEGIN CTAB", pos)) != std::string::npos;
       pos += 4)
    ++v30;
  for (pos = 0; (pos = text.find("> <PUBCHEM_ID>", pos)) != std::string::npos;
       pos += 4)
    ++data;
  EXPECT_EQ(records, static_cast<size_t>(2));
  EXPECT_EQ(v30, static_cast<size_t>(2));
  EXPECT_EQ(data, static_cast<size_t>(2));
  EXPECT_EQ(text.find("V2000"), std::string::npos);

  // the plain SDF writer honours the option for every record too
  SdfFormat plain;
  plain.setOptions("{ \"v3000\": true }");
  std::ostringstream out2;
  ASSERT_TRUE(plain.write(out2, mol));
  ASSERT_TRUE(plain.write(out2, mol));
  EXPECT_EQ(out2.str(), text);
}

TEST(MdlTest, newInstanceKeepsVariant)
{
  MdlV3000Format mdl;
  SdfV3000Format sdf;
  FileFormat* a = mdl.newInstance();
  FileFormat* b = sdf.newInstance();
  EXPECT_EQ(a->identifier(), "Avogadro: MDL V3000");
  EXPECT_EQ(b->identifier(), "Avogadro: SDF V3000");
  delete a;
  delete b;
}
