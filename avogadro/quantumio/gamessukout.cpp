/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2010 Jens Thomas
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "gamessukout.h"
#include <fstream>
#include <iostream>

#include <QtCore/QRegExp>
#include <QtCore/QString>
#include <QtCore/QStringList>

using Eigen::Vector3d;
using std::vector;

namespace Avogadro {
namespace QuantumIO {

using Quantum::S;
using Quantum::SP;
using Quantum::P;
using Quantum::D;
using Quantum::F;
using Quantum::UU;

using Quantum::orbital;

//! Break a string (supplied as the second argument) into tokens, returned
//! in the first argument. Tokens are determined by the delimiters supplied
bool tokenize(std::vector<std::string>& vcr, const char* buf,
              const char* delimstr)
{
  // Not the most efficient way to do this, but this avoids using GPL code
  // from openbabel.
  if (!buf || !delimstr)
    return false;

  QString tmp(buf);
  tmp += "\n"; // for compatibility with old behavior
  vcr.clear();
  QString splitString("[");
  splitString += QString(delimstr);
  splitString += QString("]");
  QRegExp splitter(splitString);
  foreach (const QString& str, tmp.split(splitter, QString::SkipEmptyParts))
    vcr.push_back(str.toStdString());

  return true;
}

//! Removes white space from front and back of string
std::string& Trim(std::string& txt)
{
  // Not the most efficient way to do this, but this avoids using GPL code
  // from openbabel.
  txt = QString::fromStdString(txt).trimmed().toStdString();
  return txt;
}

/**
 * This purloined from: http://www.codeguru.com/forum/showthread.php?t=231054
 */
template <class T>
bool from_string(T& t, const std::string& s,
                 std::ios_base& (*f)(std::ios_base&))
{
  std::istringstream iss(s);
  return !(iss >> f >> t).fail();
}

void GUKBasisSet::outputCoord()
{
  std::cout << "Coordinates:\n";
  for (unsigned int i = 0; i < coordinates.size(); i++) {
    printf("%d: %3s  %10f  %10f  %10f\n", i, atomLabels[i].c_str(),
           coordinates[i][0], coordinates[i][1], coordinates[i][2]);
  }
} // end outputCoord

void GUKBasisSet::outputBasis()
{
  std::cout << "Basis functions" << std::endl;

  int prev;
  for (unsigned int i = 0; i < shellLabels.size(); i++) {
    std::cout << "Atom(" << i << "): " << shellLabels.at(i) << std::endl;
    // std::cout << "shells at(i).size() " << shells.at(i).size() << std::endl;
    for (unsigned int j = 0; j < shells.at(i).size(); j++) {
      // The first indexes are different as they are the indexes held at the
      // end of the last shell or 0 for the first one
      if (i == 0 && j == 0)
        prev = 0;
      else if (j == 0)
        prev = gtoIndicies.at(i - 1).back();
      else
        prev = gtoIndicies.at(i).at(j - 1);
      std::cout << "shell type " << shells.at(i).at(j) << std::endl;
      for (unsigned int k = prev; k < gtoIndicies.at(i).at(j); k++) {
        std::cout << "       e = " << gtoExponents.at(k)
                  << " c = " << gtoCoefficients.at(k) << std::endl;
      }
    }
  }

  std::cout << "Read in nShell " << nShell << std::endl;
  std::cout << "Read in nBasisFunctions " << nBasisFunctions << std::endl;
  std::cout << "Read in nElectrons " << nElectrons << std::endl;

} // end outputBasis

bool GUKBasisSet::labelIndex(std::string label)
{
  for (unsigned int i = 0; i < shellLabels.size(); i++)
    if (shellLabels.at(i) == label)
      return true;
  return false;
} // end labelIndex

orbital GUKBasisSet::shellTypeFromString(std::string label)
{
  /**
   * Return the enum from basis.h for the supplied label as a string
   * basisset.h: enum orbital { S, SP, P, D, D5, F, F7, UU };

   * The label is from the GAMESS-UK basis set label, which is printed as shown
   below:

   * shell   type  prim       exponents      contraction coefficients
   * 1       1s       3        5.533350       1.801737  (    0.700713  )
   *  or
   * 2       2sp      4        3.664980      -0.747384  (   -0.395897  )
   1.709178  (    0.236460  )

   */

  // Could be e.g. 's', 'l', '2sp' or '1s'.
  // We assume that if it is longer then 1 character long, the rest is the label
  if (label.size() > 1) {
    // Remove the shell number
    label = label.substr(1, std::string::npos);
  }

  // Check for sp
  if (label.size() == 2) {
    if (label.compare(0, 2, "sp") == 0)
      return SP;
  }

  if (label.size() == 1) {
    if (label == "l")
      return SP;
    if (label == "s")
      return S;
    if (label == "p")
      return P;
    if (label == "d")
      return D;
  } // end label of length 1

  // if we get here, it's all gone wrong...
  std::cerr << "ERROR: shellTypeFromString with label: " << label << std::endl;
  return UU;
}

GamessukOut::GamessukOut(const QString& qtfilename, GaussianSet* basis)
{
  std::string filename;
  filename = qtfilename.toStdString();
  GamessukOutNoQt(filename, basis);
} // end GamessukOut

GamessukOut::~GamessukOut()
{
} // end ~GamessukOut

void GamessukOut::GamessukOutNoQt(const std::string& filename,
                                  GaussianSet* basis)
{

  bool ok;
  std::ifstream ifs;

  ifs.open(filename.c_str());
  if (!ifs) {
    std::cerr << "Cannot open: " << filename << "\n";
    return;
  }

  // Initialise the basis set object that holds the parsed data before we
  // convert
  // it into Avogadro form
  gukBasis = GUKBasisSet();

  // Now read the file
  ok = parseFile(ifs);

  ifs.close();

  if (ok) {
    // outputParsedData();
    // Create the Avogadro basis set object
    load(basis);
  } else
    std::cerr << "ERROR READING ORBITALS FROM FILE: " << filename << std::endl;

} // end GamessukOutNoQt

void GamessukOut::outputParsedData()
{
  gukBasis.outputCoord();
  gukBasis.outputBasis();
} // end outputParsedData

bool GamessukOut::parseFile(std::ifstream& ifs)
{

  /**
   * Loop through the file, calling routines that read in the data of interest
   * into the GUKBasisSet object
   * Is currently pretty rudimentary - could do with lots of error trapping to
   * check all o.k.
   */

  bool gotMOs = false; // used as return value - indicates if we have valid
                       // orbitals for the coordinates we've read in

  while (ifs.good() && ifs.getline(buffer, BUFF_SIZE)) {

    // First find oriented geometry - use this for single-point calculations
    if (strstr(buffer,
               "         *     atom   atomic                coordinates") !=
        nullptr) {
      readInitialCoordinates(ifs);
    }

    // The basis set definition
    if (strstr(buffer, " atom        shell   type  prim       exponents        "
                       "    contraction coefficients") != nullptr) {
      readBasisSet(ifs);
    }

    // Determine the scftype - can't do uhf yet
    if (strstr(buffer, " * SCF TYPE") != nullptr) {
      tokenize(tokens, buffer, " \t\n");
      if (tokens[3].compare(0, 6, "rhf") != 0) {
        std::cerr << "ERROR: can currently only do rhf!\n";
        return false;
      }
    }

    // The converged geometry
    if (strstr(buffer, "optimization converged") != nullptr) {
      readOptimisedCoordinates(ifs);
      if (gotMOs)
        gotMOs = false; // If we read in some MOs they are now redundant
    }

    // The molecular orbitals
    if (strstr(
          buffer,
          "                                                  eigenvectors") !=
          nullptr ||
        strstr(buffer, "          molecular orbitals") != nullptr) {
      readMOs(ifs);
      gotMOs = true;
    }
  }

  return gotMOs;
}

void GamessukOut::readInitialCoordinates(std::ifstream& ifs)
{
  // string to mark end of the coordinates
  char coordEnd[86] = "         "
                      "********************************************************"
                      "********************";
  double x = 0.0, y = 0.0, z = 0.0;

  // skip five lines
  ifs.getline(buffer, BUFF_SIZE) && ifs.getline(buffer, BUFF_SIZE) &&
    ifs.getline(buffer, BUFF_SIZE) && ifs.getline(buffer, BUFF_SIZE) &&
    ifs.getline(buffer, BUFF_SIZE);

  while (strstr(buffer, coordEnd) == nullptr) {
    // std::cout << "COORD line" << buffer << std::endl;
    // ifs.getline(buffer, BUFF_SIZE);
    tokenize(tokens, buffer, " \t\n");

    if (tokens.size() == 8) {
      // std::cout << "Coord line" << buffer << std::endl;
      gukBasis.atomLabels.push_back(tokens.at(1));

      from_string<double>(x, tokens.at(3), std::dec);
      from_string<double>(y, tokens.at(4), std::dec);
      from_string<double>(z, tokens.at(5), std::dec);
      gukBasis.coordinates.push_back(
        Eigen::Vector3d(x, y, z)); // Want coordinates in Bohr
    }

    ifs.getline(buffer, BUFF_SIZE);
  }
}

void GamessukOut::readBasisSet(std::ifstream& ifs)
{

  // std::cout << "readBasisSet\n";

  bool newAtom = true, gotAtom = false, firstAtom = true;
  std::string atomLabel;
  double exponent, coefficient;
  orbital stype;
  int nshell = -1;
  int lastNshell = -1; // the last shell number - is same as nshell when looping
                       // through a shell
  int lastStype = -1;  // need to keep track of sp shells as we split into s & p

  // For separating sp-shells
  std::vector<double> s_coeff;
  std::vector<double> p_coeff;
  std::vector<double> sp_exponents;

  // skip 2 lines to be just before the first atom label
  ifs.getline(buffer, BUFF_SIZE) && ifs.getline(buffer, BUFF_SIZE);

  // now loop through the basis sets till we hit the end
  while (!ifs.eof()) {
    ifs.getline(buffer, BUFF_SIZE);
    line = buffer;

    if (line.compare(0, 10, " =========") == 0) {
      // End of  basis - add indicies of where the coffecients and exponents of
      // the GTOs for the last shell end
      gukBasis.gtoIndicies.at(gukBasis.shellLabels.size() - 1)
        .push_back(static_cast<unsigned int>(gukBasis.gtoExponents.size()));
      break;
    }

    // Remove blank space
    line = Trim(line);

    // skip blank lines
    if (line.size() == 0)
      continue;

    // Separate into tokens
    if (!tokenize(tokens, line.c_str(), " \t\n") || tokens.size() == 0) {
      // If the string couldn't be tokenised, set tokens[0] to the entire string
      tokens.clear();
      tokens.push_back(line);
    }

    if (tokens.size() == 1) {
      // This means a new atomLabel
      newAtom = true;
      if (firstAtom)
        firstAtom = false;
      else {
        // Check if the last shell was sp - if so add the temp sp data
        // structures
        // to the main ones
        if (lastStype == SP) {
          addSpBasis(s_coeff, p_coeff, sp_exponents);

          // Clear the temp data structures for separating out sp into s & p
          s_coeff.clear();
          p_coeff.clear();
          sp_exponents.clear();
          lastStype = -1;
        } else {
          // Add the index for where the GTO coffecients and exponents for the
          // previous shell start
          gukBasis.gtoIndicies.at(gukBasis.shellLabels.size() - 1)
            .push_back(static_cast<unsigned int>(gukBasis.gtoExponents.size()));
        }

      } // end firstAtom

      // Check if we've already processed an atom of this type
      if (!gukBasis.labelIndex(tokens.at(0))) {
        // std::cout << "Processing atom label: " << tokens.at(0) << std::endl;
        gotAtom = false; // we'll be processing this atom
        gukBasis.shellLabels.push_back(tokens.at(0));
        gukBasis.shells.push_back(std::vector<orbital>());
        gukBasis.gtoIndicies.push_back(std::vector<unsigned int>());
      } else
        gotAtom = true;
      continue;

    } // End new atomLabel

    // if we're not processing an atom we can skip this line
    if (gotAtom)
      continue;

    /* Here we are reading in a line of the format:
        shell   type  prim       exponents      contraction coefficients
        1       1s       3        5.533350       1.801737  (    0.700713  )
         or
        2       2sp      4        3.664980      -0.747384  (   -0.395897  )
       1.709178  (    0.236460  )
      */

    from_string<int>(nshell, tokens.at(0), std::dec);

    if (nshell != lastNshell) {
      // Reading a new shell

      if (!newAtom) {
        // Add the data for the last shell processed

        // First check if last shell was sp & we need to add the data we've
        // gathered to the main structures
        if (lastStype == SP) {

          addSpBasis(s_coeff, p_coeff, sp_exponents);

          // Clear the temp data structures for separating out sp into s & p
          s_coeff.clear();
          p_coeff.clear();
          sp_exponents.clear();
        } else {
          // Add the index for where the primitives for the last shell finish
          gukBasis.gtoIndicies.at(gukBasis.shellLabels.size() - 1)
            .push_back(static_cast<unsigned int>(gukBasis.gtoExponents.size()));

        } // end sp shell

      } // end newAtom

      // need to determine type
      stype = gukBasis.shellTypeFromString(tokens.at(1));
      // std::cout << "Reading new shell of type " << stype << std::endl;

      if (stype != SP) {
        // Add shell to symmetry list and AtomToShellIndex if not sp shell as we
        // do that separately
        gukBasis.shells.at(gukBasis.shellLabels.size() - 1).push_back(stype);
      }

    } // end new shell

    // Now check for coefficients - we take the second lot to match Gaussian
    from_string<double>(exponent, tokens.at(3), std::dec);

    if (stype == SP) {
      if (tokens.size() != 12)
        std::cerr << "PROBLEM READING SP LINE!\n";
      from_string<double>(coefficient, tokens.at(6), std::dec);
      s_coeff.push_back(coefficient);
      from_string<double>(coefficient, tokens.at(10), std::dec);
      p_coeff.push_back(coefficient);
      sp_exponents.push_back(exponent);
    } else {
      // std::cout << "Adding exponent " << exponent << std::endl;
      gukBasis.gtoExponents.push_back(exponent);
      from_string<double>(coefficient, tokens.at(6), std::dec);
      gukBasis.gtoCoefficients.push_back(coefficient);
    } // end type ==  SP

    lastNshell = nshell;
    lastStype = stype;
    newAtom = false;

  } // end while

  // Finished reading the basis data - now just collect some data from the
  // summary - mainly for checking

  ifs.getline(buffer, BUFF_SIZE); // blank

  // nShell
  ifs.getline(buffer, BUFF_SIZE);
  if (strstr(buffer, " total number of shells") == nullptr)
    std::cerr << "Error reading nShell!: " << line << std::endl;
  // reuse nshell from above as temporary variable
  tokenize(tokens, buffer, " \t\n");
  from_string<int>(nshell, tokens.at(4), std::dec);
  gukBasis.nShell = nshell;

  // nBasisFunctions
  ifs.getline(buffer, BUFF_SIZE);
  if (strstr(buffer, " total number of basis") == nullptr)
    std::cerr << "Error reading nBasisFunctions!: " << line << std::endl;
  tokenize(tokens, buffer, " \t\n");
  // reuse nshell from above as temporary variable
  from_string<int>(nshell, tokens.at(5), std::dec);
  gukBasis.nBasisFunctions = nshell;

  // nElectrons
  ifs.getline(buffer, BUFF_SIZE);
  if (strstr(buffer, " number of electrons") == nullptr)
    std::cerr << "Error reading nElectrons!: " << line << std::endl;
  tokenize(tokens, buffer, " \t\n");
  // reuse nshell from above as temporary variable
  from_string<int>(nshell, tokens.at(3), std::dec);
  gukBasis.nElectrons = nshell;

} // end readBasisSet

inline void GamessukOut::addSpBasis(std::vector<double> s_coeff,
                                    std::vector<double> p_coeff,
                                    std::vector<double> sp_exponents)
{

  // Convenience function for adding separated sp basis

  // Add s
  gukBasis.shells.at(gukBasis.shellLabels.size() - 1).push_back(S);

  for (unsigned int i = 0; i < s_coeff.size(); i++) {
    gukBasis.gtoExponents.push_back(sp_exponents[i]);
    gukBasis.gtoCoefficients.push_back(s_coeff[i]);
  }
  gukBasis.gtoIndicies.at(gukBasis.shellLabels.size() - 1)
    .push_back(static_cast<unsigned int>(gukBasis.gtoExponents.size()));

  // Add p
  gukBasis.shells.at(gukBasis.shellLabels.size() - 1).push_back(P);

  for (unsigned int i = 0; i < p_coeff.size(); i++) {
    gukBasis.gtoExponents.push_back(sp_exponents[i]);
    gukBasis.gtoCoefficients.push_back(p_coeff[i]);
  }
  gukBasis.gtoIndicies.at(gukBasis.shellLabels.size() - 1)
    .push_back(static_cast<unsigned int>(gukBasis.gtoExponents.size()));

} // end addSpBasis

void GamessukOut::readOptimisedCoordinates(std::ifstream& ifs)
{

  // std::cout << "readOptimisedCoordinates\n";

  double x, y, z;

  // Nuke the old coordinates
  gukBasis.atomLabels.clear();
  gukBasis.coordinates.clear();

  ifs.getline(buffer, BUFF_SIZE);
  while (!ifs.eof()) {

    // This for some optimize runtypes
    if (strstr(
          buffer,
          "         x              y              z            chg  tag") !=
        nullptr) {
      // std::cout << "start of opt coord\n";
      // Skip 2 lines - should then be at the coordinates
      ifs.getline(buffer, BUFF_SIZE) && ifs.getline(buffer, BUFF_SIZE);

      while (!ifs.eof()) {
        // End of geometry block
        if (strstr(buffer, "  "
                           "==================================================="
                           "=========") != nullptr)
          return;

        tokenize(tokens, buffer, " \t\n");

        from_string<double>(x, tokens.at(0), std::dec);
        from_string<double>(y, tokens.at(1), std::dec);
        from_string<double>(z, tokens.at(2), std::dec);

        gukBasis.coordinates.push_back(Eigen::Vector3d(x, y, z));
        gukBasis.atomLabels.push_back(tokens.at(4));

        ifs.getline(buffer, BUFF_SIZE);
      } // end while
    } else if (strstr(buffer,
                      "atom     znuc       x             y             z") !=
               nullptr) {

      // print "start of opt coord 2"

      // Skip 3 lines - should then be at the coordinates
      ifs.getline(buffer, BUFF_SIZE) && ifs.getline(buffer, BUFF_SIZE) &&
        ifs.getline(buffer, BUFF_SIZE);

      while (!ifs.eof()) {
        // End of geometry block
        if (strstr(buffer, "*************************") != nullptr)
          return;

        tokenize(tokens, buffer, " \t\n");

        gukBasis.atomLabels.push_back(tokens.at(0));
        from_string<double>(x, tokens.at(3), std::dec);
        from_string<double>(y, tokens.at(4), std::dec);
        from_string<double>(z, tokens.at(5), std::dec);

        gukBasis.coordinates.push_back(Eigen::Vector3d(x, y, z));

        ifs.getline(buffer, BUFF_SIZE);
      } // end of while
    }

    ifs.getline(buffer, BUFF_SIZE);
  } // end of read loop

} // end readOptimisedCoordinates

void GamessukOut::readMOs(std::ifstream& ifs)
{
  /*
      Read the Molecular Orbitals as printed out by util1.m subroutine prev
    */

  int orbitalsRead, orbitalsRead1;

  // Nuke any old set - fix when look at alpha & beta
  gukBasis.moVectors.clear();

  // Skip 3 lines to be just before first header
  ifs.getline(buffer, BUFF_SIZE) && ifs.getline(buffer, BUFF_SIZE) &&
    ifs.getline(buffer, BUFF_SIZE);

  orbitalsRead1 = readMOVectors(ifs);
  orbitalsRead = orbitalsRead1;
  while (orbitalsRead == orbitalsRead1 || orbitalsRead != 0)
    orbitalsRead = readMOVectors(ifs);

} // end readMos

int GamessukOut::readMOVectors(std::ifstream& ifs)
{
  /*
       Loop through a series of columns of printed MO vectors & return the
       number of orbitals read in
    */

  unsigned int norbitals, norbitalsRead;
  double energy;

  ifs.getline(buffer, BUFF_SIZE);
  // std::cout << "HeaderLine " << buffer << std::endl;

  // Check we're not at the end
  if (strstr(buffer, "end of") != 0)
    return 0;

  tokenize(tokens, buffer, " \t\n");
  // How many orbital columns:
  norbitals = static_cast<unsigned int>(tokens.size());

  for (unsigned int i = 0; i < tokens.size(); i++) {
    from_string<double>(energy, tokens.at(i), std::dec);
    // std::cout << "adding e " << energy << std::endl;
    gukBasis.moEnergies.push_back(energy);
  }

  // Add the lists to hold this set of coefficients
  // How many were read in previously:
  norbitalsRead = static_cast<unsigned int>(gukBasis.moVectors.size());

  // Create the arrays to hold the coefficients for each orbital
  for (unsigned int i = 0; i < norbitals; i++)
    gukBasis.moVectors.push_back(std::vector<double>());

  // skip 5 lines to just before where first set of orbitals are printed
  ifs.getline(buffer, BUFF_SIZE) && ifs.getline(buffer, BUFF_SIZE) &&
    ifs.getline(buffer, BUFF_SIZE) && ifs.getline(buffer, BUFF_SIZE) &&
    ifs.getline(buffer, BUFF_SIZE);

  // loop nBasisFunctions times to read in up to norbitals coefficients
  for (int i = 0; i < gukBasis.nBasisFunctions; i++) {
    ifs.getline(buffer, BUFF_SIZE);
    // std::cout << "MO line " << buffer << std::endl;

    tokenize(tokens, buffer, " \t\n");

    for (unsigned int j = 0; j < norbitals; j++) {
      // reuse variable energy to hold coefficient
      from_string<double>(energy, tokens.at(j + 4), std::dec);
      gukBasis.moVectors.at(norbitalsRead + j).push_back(energy);
      // std::cout << "Adding " << energy << " to vector " << norbitalsRead+j <<
      // std::endl;
    }
  }

  // skip 2 lines to where the next set of headers are printed
  ifs.getline(buffer, BUFF_SIZE);
  ifs.getline(buffer, BUFF_SIZE);

  // If we are printed out after an optimisation under the control of "iprint
  // vectors",
  // the next line with be filled with " =================" if we've finished
  if (strstr(buffer, " ===============================") != 0)
    return 0;

  return norbitals;

} // end readMOVectors

void GamessukOut::addBasisForLabel(unsigned int atomIndex, std::string label,
                                   GaussianSet* basis)
{
  /*
      Add the basis functions for the atom label
     */

  unsigned int s;
  int prev;
  for (unsigned int i = 0; i < gukBasis.shellLabels.size(); i++) {
    if (gukBasis.shellLabels.at(i) != label)
      continue;

    for (unsigned int j = 0; j < gukBasis.shells.at(i).size(); j++) {
      s = basis->addBasis(atomIndex, gukBasis.shells.at(i).at(j));

      // The first indexes are different as they are the indexes held at the end
      // of the last shell or
      // 0 for the first one
      if (i == 0 && j == 0)
        prev = 0;
      else if (j == 0)
        prev = gukBasis.gtoIndicies.at(i - 1).back();
      else
        prev = gukBasis.gtoIndicies.at(i).at(j - 1);

      for (unsigned int k = prev; k < gukBasis.gtoIndicies.at(i).at(j); k++) {
        basis->addGTO(s, gukBasis.gtoCoefficients.at(k),
                      gukBasis.gtoExponents.at(k));
      }
    }
  }
  return;

} // end addBasisForLabel

void GamessukOut::load(GaussianSet* basis)
{
  /*
      We will only have read in a basis set for atoms of each type
      Loop through the list of all the atoms & add the basis functions for each
     individual atom

    */

  basis->setNumElectrons(gukBasis.nElectrons);

  // Add the basis for each atom
  for (unsigned int i = 0; i < gukBasis.atomLabels.size(); i++) {
    basis->addAtom(gukBasis.coordinates.at(i));
    addBasisForLabel(i, gukBasis.atomLabels.at(i), basis);
  }

  // Now to load in the MO coefficients
  // This currently a dirty hack - basisset addMO just expects a long vector of
  // doubles, which
  // it then converts into a square matrix.
  // For this test, we convert our vector of vectors to a single vector and fill
  // the remaining
  // virtual orbitals with zeros.

  std::vector<double> MOs;
  unsigned int moEnd,
    nBasis = static_cast<unsigned int>(gukBasis.nBasisFunctions);

  for (unsigned int i = 0; i < nBasis; i++) {
    if (i >= gukBasis.moVectors.size()) {
      // std::cout << "Adding blank vectors for non-printed MOs " << i <<
      // std::endl;
      moEnd = static_cast<unsigned int>(MOs.size()) + nBasis;
      for (unsigned int j = static_cast<unsigned int>(MOs.size()); j < moEnd;
           j++)
        MOs.push_back(0.0);
    } else {
      // std::cout << "Adding actual vector " << i << std::endl;
      MOs.insert(MOs.end(), gukBasis.moVectors.at(i).begin(),
                 gukBasis.moVectors.at(i).end());
    }
  }

  // Need to multiply by -1 to bring into accordance with Gaussian.
  // for( unsigned int i=0; i <MOs.size(); i++ ) MOs.at(i)=MOs.at(i)*-1;

  basis->addMOs(MOs);

  // basis->initCalculation();

} // end load

} // End Namespace
}
