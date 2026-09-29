/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/gaussianfchk.h>

#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::QuantumIO::GaussianFchk;

// does the basic read work
TEST(GaussianFchkTest, basicRead)
{
  GaussianFchk format;
  Molecule molecule;
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/fchk/h2o-restricted.fchk", molecule));
  ASSERT_EQ(format.error(), std::string());

  ASSERT_EQ(molecule.atomCount(), 3);
}

// Regression test: oversized array header should fail gracefully.
TEST(GaussianFchkTest, oversizedArrayRejected)
{
  GaussianFchk format;
  Molecule molecule;

  std::ostringstream out;
  out << "Header line 1\n";
  out << "Header line 2\n";
  out << std::left << std::setw(42) << "Atomic numbers"
      << " I 20000000\n";

  EXPECT_FALSE(format.readString(out.str(), molecule));
  EXPECT_NE(format.error(), std::string());
}

// Regression test: the density matrix allocation is basis x basis, but until
// the size check ran in both directions only the declared element count was
// tied to the size of the file. "Number of basis functions = 5792" plus a
// one-element density block let a 376 byte file reserve a 268 MB matrix -- and
// a second one for the spin density, which is how the fuzz job ran out of
// memory on inputs that were nowhere near that large.
TEST(GaussianFchkTest, densityMatrixMustFillTheLowerTriangle)
{
  // 5792 * 5792 sits just inside the 32M element cap, so nothing above this
  // check would have stopped the allocation.
  const int basis = 5792;

  std::ostringstream out;
  out << "Tiny allocation bomb\n";
  out << "SP        RB3LYP                                            STO-3G\n";
  out << std::left << std::setw(42) << "Number of atoms"
      << " I          1\n";
  out << std::left << std::setw(42) << "Number of basis functions"
      << " I " << basis << "\n";
  out << std::left << std::setw(42) << "Total SCF Density"
      << " R   N=  1\n";
  out << "  1.00000000E-01\n";
  out << std::left << std::setw(42) << "Spin SCF Density"
      << " R   N=  1\n";
  out << "  1.00000000E-01\n";

  GaussianFchk format;
  Molecule molecule;
  EXPECT_FALSE(format.readString(out.str(), molecule));
  // The read has to fail on the size, not merely run out of data after having
  // already allocated the matrix -- that is the whole point of the check.
  EXPECT_NE(format.error().find("Invalid density matrix size"),
            std::string::npos)
    << format.error();
  EXPECT_NE(format.error().find("Invalid spin density matrix size"),
            std::string::npos)
    << format.error();

  // The same header declaring the full lower triangle is not rejected by the
  // size check -- every file Gaussian writes looks like this.
  const size_t lower = static_cast<size_t>(basis) * (basis + 1) / 2;
  std::ostringstream full;
  full << "Header line 1\n";
  full << "Header line 2\n";
  full << std::left << std::setw(42) << "Number of basis functions"
       << " I " << basis << "\n";
  full << std::left << std::setw(42) << "Total SCF Density"
       << " R   N=  " << lower << "\n";

  GaussianFchk accepting;
  Molecule other;
  accepting.readString(full.str(), other);
  EXPECT_EQ(accepting.error().find("Invalid density matrix size"),
            std::string::npos)
    << accepting.error();
}

// Regression test: the shell type is read unchecked from the file, and
// (type + 1) * (type + 2) overflowed an int for values like 64340206 (found
// by the UBSan fuzz job). Unsupported shell types are now rejected up front
// so the atomic-orbital offsets cannot be misaligned either.
TEST(GaussianFchkTest, unsupportedShellTypeRejected)
{
  auto build = [](int shellType) {
    std::ostringstream out;
    out << "Header line 1\n";
    out
      << "SP        RHF                                               STO-3G\n";
    out << std::left << std::setw(42) << "Number of atoms"
        << " I          1\n";
    out << std::left << std::setw(42) << "Atomic numbers"
        << " I   N=           1\n";
    out << "           1\n";
    out << std::left << std::setw(42) << "Current cartesian coordinates"
        << " R   N=           3\n";
    out << "  0.00000000E+00  0.00000000E+00  0.00000000E+00\n";
    out << std::left << std::setw(42) << "Shell types"
        << " I   N=           1\n";
    out << "  " << shellType << "\n";
    out << std::left << std::setw(42) << "Number of primitives per shell"
        << " I   N=           1\n";
    out << "           1\n";
    out << std::left << std::setw(42) << "Shell to atom map"
        << " I   N=           1\n";
    out << "           1\n";
    out << std::left << std::setw(42) << "Primitive exponents"
        << " R   N=           1\n";
    out << "  1.00000000E+00\n";
    out << std::left << std::setw(42) << "Contraction coefficients"
        << " R   N=           1\n";
    out << "  1.00000000E+00\n";
    return out.str();
  };

  // A supported type builds a basis with one shell...
  {
    GaussianFchk format;
    Molecule molecule;
    EXPECT_TRUE(format.readString(build(0), molecule));
    auto* basis =
      dynamic_cast<Avogadro::Core::GaussianSet*>(molecule.basisSet());
    ASSERT_NE(basis, nullptr);
    EXPECT_EQ(basis->atomIndices().size(), 1u);
  }

  // ...while unsupported ones must neither crash nor add any shells.
  for (int bad : { 64340206, 7, -7, 2147483647, -2147483647 - 1 }) {
    GaussianFchk format;
    Molecule molecule;
    format.readString(build(bad), molecule);
    auto* basis =
      dynamic_cast<Avogadro::Core::GaussianSet*>(molecule.basisSet());
    ASSERT_NE(basis, nullptr) << bad;
    EXPECT_TRUE(basis->atomIndices().empty()) << bad;
  }
}
