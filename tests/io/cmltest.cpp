/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/cmlformat.h>

using Avogadro::MatrixX;
using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Molecule;
using Avogadro::Core::Variant;
using Avogadro::Io::CmlFormat;
using namespace std::string_literals;

TEST(CmlTest, readFile)
{
  CmlFormat cml;
  Molecule molecule;
  cml.readFile(std::string(AVOGADRO_DATA) + "/data/cml/ethane.cml", molecule);

  EXPECT_EQ(molecule.data("name").type(), Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");

  EXPECT_EQ(molecule.data("inchi").type(), Variant::String);
  EXPECT_EQ(molecule.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(CmlTest, atoms)
{
  CmlFormat cml;
  Molecule molecule;
  cml.readFile(std::string(AVOGADRO_DATA) + "/data/cml/ethane.cml", molecule);

  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  Atom atom = molecule.atom(0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  atom = molecule.atom(1);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(atom.position3d().x(), 0.751621);
  EXPECT_EQ(atom.position3d().y(), -0.022441);
  EXPECT_EQ(atom.position3d().z(), -0.020839);

  atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.184988);
  EXPECT_EQ(atom.position3d().y(), 0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
}

TEST(CmlTest, bonds)
{
  CmlFormat cml;
  Molecule molecule;
  cml.readFile(std::string(AVOGADRO_DATA) + "/data/cml/ethane.cml", molecule);

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

TEST(CmlTest, readInvalidPeriodicFile)
{
  for (const auto& file : {
         "impossible.cml"s,
         "lin-dep2.cml"s,
         "zero-a.cml"s,
         "zero-alpha.cml"s,
         "zero-b.cml"s,
         "zero-beta.cml"s,
         "zero-c.cml"s,
         "zero-gamma.cml"s,
       }) {
    CmlFormat cml;
    Molecule molecule;
    auto f = std::string(AVOGADRO_DATA) + "/data/cml/singular/" + file;
    EXPECT_FALSE(cml.readFile(f, molecule)) << f;
    EXPECT_EQ(cml.error(),
              "<crystal> does not give linear independent lattice vectors\n"s)
      << f;
  }
}

TEST(CmlTest, fractionalCoords)
{
  std::string cmlStr(
    "<?xml version=\"1.0\"?>"
    "<molecule xmlns=\"http://www.xml-cml.org/schema\">"
    "<crystal>"
    "<scalar title=\"a\" units=\"units:angstrom\">5.3</scalar>"
    "<scalar title=\"b\" units=\"units:angstrom\">2.4</scalar>"
    "<scalar title=\"c\" units=\"units:angstrom\">1.8</scalar>"
    "<scalar title=\"alpha\" units=\"units:degree\">85.000000</scalar>"
    "<scalar title=\"beta\" units=\"units:degree\">90.000000</scalar>"
    "<scalar title=\"gamma\" units=\"units:degree\">105.000000</scalar>"
    "</crystal>"
    "<atomArray>"
    "<atom id=\"a\" elementType=\"H\" "
    "xFract=\"0.5\" yFract=\"0.5\" zFract=\"0.5\"/>"
    "</atomArray>"
    "</molecule>");
  CmlFormat cml;
  Molecule molecule;
  cml.readString(cmlStr, molecule);
  ASSERT_EQ(1, molecule.atomCount());
  Atom atom = molecule.atom(0);
  EXPECT_EQ(1, atom.atomicNumber());
  EXPECT_TRUE(atom.position3d().isApprox(Vector3(static_cast<Real>(2.33942),
                                                 static_cast<Real>(1.24032),
                                                 static_cast<Real>(0.89633)),
                                         1e-5));

  cmlStr.clear();
  cml.writeString(cmlStr, molecule);
  std::cout << cmlStr << std::endl;
  EXPECT_TRUE(cmlStr.find("<scalar title=\"a\" units=\"units:angstrom\">5.3"
                          "</scalar>") != std::string::npos);
  EXPECT_TRUE(cmlStr.find("<scalar title=\"b\" units=\"units:angstrom\">2.4"
                          "</scalar>") != std::string::npos);
  EXPECT_TRUE(cmlStr.find("<scalar title=\"c\" units=\"units:angstrom\">1.8"
                          "</scalar>") != std::string::npos);
  EXPECT_TRUE(cmlStr.find("<scalar title=\"alpha\" units=\"units:degree\">85"
                          "</scalar>") != std::string::npos);
  EXPECT_TRUE(cmlStr.find("<scalar title=\"beta\" units=\"units:degree\">90"
                          "</scalar>") != std::string::npos);
  EXPECT_TRUE(cmlStr.find("<scalar title=\"gamma\" units=\"units:degree\">105"
                          "</scalar>") != std::string::npos);
  EXPECT_TRUE(cmlStr.find("xFract=\"0.5\"") != std::string::npos);
  EXPECT_TRUE(cmlStr.find("yFract=\"0.5\"") != std::string::npos);
  EXPECT_TRUE(cmlStr.find("zFract=\"0.5\"") != std::string::npos);
}

TEST(CmlTest, saveFile)
{
  CmlFormat cml;
  Molecule readMol, writeMol;
  cml.readFile(std::string(AVOGADRO_DATA) + "/data/cml/ethane.cml", readMol);
  cml.writeFile("ethanetmp.cml", readMol);

  // Now read the file back in and check a few key values are still present.
  cml.readFile("ethanetmp.cml", writeMol);
  EXPECT_EQ(writeMol.data("name").toString(), "Ethane");
  EXPECT_EQ(writeMol.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(writeMol.bondCount(), static_cast<size_t>(7));
  Atom atom = writeMol.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.18499);
  EXPECT_EQ(atom.position3d().y(), 0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
  Bond bond = writeMol.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(CmlTest, hdf5Matrix)
{
  CmlFormat cml;
  Molecule molecule;
  cml.readFile(std::string(AVOGADRO_DATA) + "/data/cml/ethane.cml", molecule);
  molecule.setData("name", "ethanol");
  MatrixX matrix(10, 12);
  for (int row = 0; row < matrix.rows(); ++row)
    for (int col = 0; col < matrix.cols(); ++col)
      matrix(row, col) = row + col / static_cast<double>(matrix.cols());
  molecule.setData("matrix", matrix);
  cml.writeFile("ethane.cml", molecule);

  Molecule readMolecule;
  cml.readFile("ethane.cml", readMolecule);
  if (readMolecule.data("matrix").type() == Variant::Matrix) {
    EXPECT_TRUE(readMolecule.data("matrix").toMatrixRef().isApprox(matrix));
  }
  EXPECT_EQ(readMolecule.data("name").toString(), "ethanol"s);
}

TEST(CmlTest, writeString)
{
  CmlFormat cml;
  Molecule molecule;
  EXPECT_EQ(
    cml.readFile(std::string(AVOGADRO_DATA) + "/data/cml/ethane.cml", molecule),
    true);
  std::string file;
  EXPECT_EQ(cml.writeString(file, molecule), true);
}

TEST(CmlTest, readString)
{
  CmlFormat cml;
  Molecule molecule;
  EXPECT_EQ(
    cml.readFile(std::string(AVOGADRO_DATA) + "/data/cml/ethane.cml", molecule),
    true);
  std::string file;
  EXPECT_EQ(cml.writeString(file, molecule), true);
  Molecule moleculeFromString;
  EXPECT_EQ(cml.readString(file, moleculeFromString), true);

  EXPECT_EQ(moleculeFromString.data("name").toString(), "Ethane");
  EXPECT_EQ(moleculeFromString.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(moleculeFromString.bondCount(), static_cast<size_t>(7));
}

namespace {

/** Benzene with its six ring bonds written using @a order, e.g. "A". */
std::string benzeneCml(const std::string& order)
{
  std::string cml("<?xml version=\"1.0\"?>"
                  "<molecule xmlns=\"http://www.xml-cml.org/schema\">"
                  "<atomArray>");
  for (int i = 1; i <= 6; ++i)
    cml += "<atom id=\"a" + std::to_string(i) + "\" elementType=\"C\"/>";
  for (int i = 7; i <= 12; ++i)
    cml += "<atom id=\"a" + std::to_string(i) + "\" elementType=\"H\"/>";
  cml += "</atomArray><bondArray>";
  // The ring, then one C-H per ring carbon.
  for (int i = 1; i <= 6; ++i) {
    const int next = (i == 6) ? 1 : i + 1;
    cml += "<bond atomRefs2=\"a" + std::to_string(i) + " a" +
           std::to_string(next) + "\" order=\"" + order + "\"/>";
  }
  for (int i = 1; i <= 6; ++i)
    cml += "<bond atomRefs2=\"a" + std::to_string(i) + " a" +
           std::to_string(i + 6) + "\" order=\"1\"/>";
  cml += "</bondArray></molecule>";
  return cml;
}

/**
 * Assert that @a molecule is benzene whose aromatic ring came back kekulized:
 * no bond left at the aromatic order, and the ring alternating three double
 * with three single bonds.
 *
 * Ring bonds are looked up by their endpoints rather than by bond index, so
 * this does not quietly depend on the order the reader added them in. The
 * first six atoms are the ring, in order around it.
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

TEST(CmlTest, aromaticBondOrderAIsKekulized)
{
  // Benzene, its six ring bonds written with the CML aromatic order "A".
  // Before kekulize() was wired in, "A" fell through to the single-bond
  // default; now it should come back as alternating single and double
  // bonds, not all single.
  CmlFormat cml;
  Molecule molecule;
  ASSERT_TRUE(cml.readString(benzeneCml("A"), molecule)) << cml.error();
  expectKekulizedBenzene(molecule);
}

TEST(CmlTest, aromaticBondOrderAromaticSpellingIsKekulized)
{
  // The same molecule, but with the multi-character spelling order
  // ="aromatic", which the single-character comparison used to miss. It has
  // to reach exactly the same result as "A", so it gets the same assertions.
  CmlFormat cml;
  Molecule molecule;
  ASSERT_TRUE(cml.readString(benzeneCml("aromatic"), molecule)) << cml.error();
  expectKekulizedBenzene(molecule);
}
