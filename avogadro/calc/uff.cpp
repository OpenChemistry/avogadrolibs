/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "uff.h"
#include "uffdata.h"

#include <Eigen/src/Core/util/Meta.h>
#include <avogadro/core/angleiterator.h>
#include <avogadro/core/angletools.h>
#include <avogadro/core/array.h>
#include <avogadro/core/dihedraliterator.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

namespace Avogadro::Calc {

using namespace Core;
using Eigen::Vector3d;

enum Coordination
{
  Resonant = 0,             // conjugated / aromatic
  Linear = 1,               // sp linear
  Trigonal = 2,             // sp2 planar
  Tetrahedral = 3,          // sp3 tetrahedral
  SquarePlanar = 4,         // square planar
  TrigonalBipyramidal = 5,  // trigonal bipyramidal
  Octahedral = 6,           // octahedral
  TrigonalBipentagonal = 7, // trigonal bipentagonal
  Other = 8                 // including higher coordination
};

class UFFBond // track the bond parameters
{
public:
  Index _atom1;
  Index _atom2;
  Real _r0;
  Real _kb;
};

class UFFAngle
{
public:
  Index _atom1;
  Index _atom2;
  Index _atom3;
  Real _theta0;
  Real _kijk;
  Real _c0;
  Real _c1;
  Real _c2;
  Coordination coordination;
};

class UFFTorsion
{
public:
  Index _atom1;
  Index _atom2;
  Index _atom3;
  Index _atom4;
  Real _cos_phi0;
  Real _ijkl;
  short _n; // periodicity
};

class UFFOOP
{
public:
  Index _atom1; // central atom
  Index _atom2;
  Index _atom3;
  Index _atom4;
  Real _c0;
  Real _c1;
  Real _c2;
  Real _koop;
};

class UFFVdW
{
public:
  Index _atom1;
  Index _atom2;
  Real _depth;
  Real _x;
};

class UFFPrivate // track the particular calculations for a molecule
{
public:
  std::vector<int> m_atomTypes; // entry row in uffparams
  std::vector<UFFBond> m_bonds;
  std::vector<UFFAngle> m_angles;
  std::vector<UFFOOP> m_oops;
  std::vector<UFFTorsion> m_torsions;
  std::vector<UFFVdW> m_vdws;
  Core::Molecule* m_molecule;
  Core::UnitCell* m_cell;

  UFFPrivate(Core::Molecule* mol = nullptr) : m_molecule(mol)
  {
    if (mol == nullptr || mol->atomCount() < 2) {
      return; // nothing to do
    }

    setAtomTypes();
    setBonds();
    setAngles();
    setOOPs();
    setTorsions();
    setVdWs();

    m_cell = mol->unitCell(); // could be nullptr
  }

  void setAtomTypes()
  {
    // set up the calculations including atom types and parameters
    // loop through atoms to get the atom types
    m_atomTypes.reserve(m_molecule->atomCount());
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      const Core::Atom& atom = m_molecule->atom(i);
      int atomicNumber = atom.atomicNumber();
      int atomType = -1;
      for (int j = 0; j < 126; ++j) {
        if (uffparams[j].element == atomicNumber) {
          atomType = j;
          // not guaranteed - only the first type for this element
          // we can peek ahead to see if there are any more for this element
          if (j < 125 && uffparams[j + 1].element == atomicNumber) {
            // there are multiple types for this element
            const Array<Bond> bonds = m_molecule->bonds(i);
            if (atomicNumber == 1) {
              // hydrogen has two types, so count the bonds
              if (bonds.size() == 1) {
                atomType = j; // hydrogen with one bond
                break;
              } else { // hydrogen with more than one bond = bridging type
                atomType = j + 1;
                break;
              }
            }

            // remaining elements, we want the coordination number
            // and possibly formal charge
            [[maybe_unused]] int charge = m_molecule->formalCharge(i);
            // UFF fortunately only has square planar as special cases
            // so if it's more than 4 bonds, we just use that type
            if (bonds.size() > 4) {
              // check the atom type symbols
              char coord = '4' + (bonds.size() - 4);
              if (uffparams[j].label[2] == coord) {
                atomType = j;
                break;
              } else {
                // check the next one
                if (uffparams[j + 1].label[2] == coord) {
                  atomType = j + 1;
                  break;
                }
              }
            } else {
              // count double and triple bonds
              int doubleBonds = 0;
              int tripleBonds = 0;
              for (const Bond bond : bonds) {
                unsigned char order = bond.order();
                if (order == 2) {
                  ++doubleBonds;
                } else if (order == 3) {
                  ++tripleBonds;
                }
              }
              char coord = '3';
              if (tripleBonds > 0 || doubleBonds > 1)
                coord = '1'; // sp linear
              else if (doubleBonds == 1)
                coord = '2'; // sp2 trigonal
              else if (doubleBonds == 0 && tripleBonds == 0)
                coord = '3'; // sp3 tetrahedral

              // check the atom type symbols
              if (uffparams[j].label[2] == coord) {
                atomType = j;
                break;
              } else {
                // bump up until we find one
                while (j < 125 && uffparams[j].label[2] != coord) {
                  ++j;
                }
                atomType = j;
                break;
              }
            }
            break;
          }

          // nope it's the only one for this element
          // we're done
          break;
        }
      }
      m_atomTypes.push_back(atomType);
    }
    // we need to do one more pass to set aromatic / resonance types
    // i.e., if an sp2 atom has neighbors, mark them as resonant
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      const Core::Atom& atom = m_molecule->atom(i);
      int atomicNumber = atom.atomicNumber();
      // carbon, nitrogen, oxygen and sulfur sp2 atoms
      if (atomicNumber == 6 || atomicNumber == 7 || atomicNumber == 8 ||
          atomicNumber == 16) {

        const char symbolChar = uffparams[m_atomTypes[i]].label[2];

        // we might have an aromatic / resonant N, O, or S
        // e.g., furan, thiophene .. we also mark amide N
        // if it's an sp3 carbon, skip it
        if (atomicNumber == 6 && symbolChar == '3')
          continue;

        // check the neighbors
        const std::vector<Index>& neighbors = m_molecule->graph().neighbors(i);

        // we can skip carbonyl oxygen (i.e., only one neighbor)
        if ((atomicNumber == 8 || atomicNumber == 16) && neighbors.size() == 1)
          continue;

        bool resonant = false;
        for (Index j : neighbors) {
          auto symbolLabel = uffparams[m_atomTypes[j]].label;
          if (symbolLabel.size() < 3)
            continue; // not a resonant type

          if (symbolLabel[2] == '2' || symbolLabel[2] == 'R') {
            resonant = true;
            break;
          }
        }
        if (resonant) {
          // set the resonant type
          if (atomicNumber == 7 && symbolChar == '3')
            m_atomTypes[i] = m_atomTypes[i] + 1; // N_R after N_3
          else if (atomicNumber == 8 && symbolChar == '3')
            m_atomTypes[i] = m_atomTypes[i] + 2; // O_R after O_3 and O_3_z
          else if (atomicNumber == 16 && symbolChar == '3') {
            // loop until we find 'R' .. might be a few different S types
            while (uffparams[m_atomTypes[i]].label[2] != 'R')
              ++m_atomTypes[i];
          } else
            m_atomTypes[i] = m_atomTypes[i] - 1; // C_R before C_2
        }
      }
    }
  }

  // calculate the ideal bond distance between two atoms
  // used in a few places
  Real calculateRij(Index atom1, Index atom2)
  {
    Real ri = uffparams[m_atomTypes[atom1]].r1;
    Real rj = uffparams[m_atomTypes[atom2]].r1;
    Real r0 = ri + rj;
    // bond order correction
    Bond bond = m_molecule->bond(atom1, atom2);
    Real order = static_cast<Real>(bond.order());
    // check if it's a resonant / aromatic bond
    auto symbol1 = uffparams[m_atomTypes[atom1]].label;
    auto symbol2 = uffparams[m_atomTypes[atom2]].label;
    if (symbol1.size() > 2 && symbol1[2] == 'R' && symbol2.size() > 2 &&
        symbol2[2] == 'R') {
      order = 1.5;
      // tweak for amide
      if ((symbol1[0] == 'N' && symbol2[0] == 'C') ||
          (symbol1[0] == 'C' && symbol2[0] == 'N'))
        order = 1.41;
    }
    Real rbo = -0.1332 * r0 * log(order);

    // electronegativity correction
    Real chi1 = uffparams[m_atomTypes[atom1]].Xi;
    Real chi2 = uffparams[m_atomTypes[atom2]].Xi;
    Real ren =
      ri * rj * pow((sqrt(chi1) - sqrt(chi2)), 2) / (chi1 * ri + chi2 * rj);

    // UFF publication has an error (electronegativity correction):
    // https://towhee.sourceforge.net/forcefields/uff.html
    return r0 + rbo - ren;
  }

  void setBonds()
  {
    // loop through the bonds
    for (Index i = 0; i < m_molecule->bondCount(); ++i) {
      const Core::Bond& bond = m_molecule->bond(i);
      Index atom1 = bond.atom1().index();
      Index atom2 = bond.atom2().index();
      UFFBond b;
      b._atom1 = atom1;
      b._atom2 = atom2;

      b._r0 = calculateRij(atom1, atom2);
      Real z1 = uffparams[m_atomTypes[atom1]].Z1;
      Real z2 = uffparams[m_atomTypes[atom2]].Z1;
      b._kb = 664.12 * z1 * z2 / pow((b._r0), 3);
      m_bonds.push_back(b);

      /*
      std::cout << " bond " << atom1 << " "
                << uffparams[m_atomTypes[atom1]].label << " " << atom2 << " "
                << uffparams[m_atomTypes[atom2]].label << " " << b._r0 << " "
                << b._kb << std::endl;
                */
    }
  }

  void setAngles()
  {
    AngleIterator ai(m_molecule);
    auto angle = ai.begin();
    while (angle != ai.end()) {
      Index i = std::get<0>(angle);
      Index j = std::get<1>(angle);
      Index k = std::get<2>(angle);
      UFFAngle a;
      a._atom1 = i;
      a._atom2 = j;
      a._atom3 = k;

      Real theta0 = uffparams[m_atomTypes[j]].theta0 * DEG_TO_RAD;
      a._theta0 = theta0 * RAD_TO_DEG; // store in degrees for consistency

      // calculate the kijk
      Real rij = calculateRij(i, j);
      Real rjk = calculateRij(j, k);

      /*
      std::cout << " Angle " << i << " " << j << " " << k << " " << rij << " "
                << rjk << " " << theta0 << std::endl;
                */

      Real rik = sqrt(rij * rij + rjk * rjk - 2 * rij * rjk * cos(theta0));
      Real Zi = uffparams[m_atomTypes[i]].Z1;
      Real Zk = uffparams[m_atomTypes[k]].Z1;
      Real cosTheta0 = cos(theta0);
      Real cosTheta0Sq = cosTheta0 * cosTheta0;
      // see https://towhee.sourceforge.net/forcefields/uff.html
      // e.g., original paper had some typos
      a._kijk = 664.12 / (rij * rjk) * (Zi * Zk) / (pow(rik, 5)) * rij * rjk;
      a._kijk *= (3 * rij * rjk * (1 - cosTheta0Sq) - rik * rik * cosTheta0);

      // calculate the c0, c1, c2 terms
      // based on coordination of the central atom
      std::string label = uffparams[m_atomTypes[j]].label;
      auto neighbors = m_molecule->graph().neighbors(j);
      a._c0 = 0.0;
      a._c1 = 0.0;
      a._c2 = 0.0;

      if (label.size() < 3 || neighbors.size() == 1 || label[2] == '1') {
        // linear
        a.coordination = Linear;
        a._c0 = 1.0;
      } else if ((label[2] == '2' || label[2] == 'R') &&
                 neighbors.size() == 3) {
        a.coordination = Trigonal;
        a._kijk = a._kijk / 9.0; // divide by n**2
        a._c0 = 3.0;
      } else if (label[2] == '4') {
        a.coordination = SquarePlanar;
        a._kijk = a._kijk / 16.0;
        a._c0 = 4.0;
      } else if (label[2] == '5') {
        // TODO
        a.coordination = TrigonalBipyramidal;
      } else if (label[2] == '6') {
        a.coordination = Octahedral;
        a._kijk = a._kijk / 16.0;
        a._c0 = 4.0;
      } else if (neighbors.size() > 6) {
        // TODO - trigonal bipentagonal and higher coordination
        // (e.g., as a repulsion between the other atoms)
        a.coordination = Other;
      } else {
        a.coordination = Tetrahedral;
        Real sinTheta0 = sin(theta0);
        a._c2 = 1.0 / (4.0 * sinTheta0 * sinTheta0);
        a._c1 = -4.0 * a._c2 * cosTheta0;
        a._c0 = a._c2 * (2.0 * cosTheta0 * cosTheta0 + 1.0);
      }

      m_angles.push_back(a);
      angle = ++ai;
    }
  }

  void setOOPs()
  {
    // loop through atoms checking for cases with 3 neighbors
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      auto neighbors = m_molecule->graph().neighbors(i);
      if (neighbors.size() != 3)
        continue;

      // also only for certain elements
      const Core::Atom& atom = m_molecule->atom(i);
      int atomicNumber = atom.atomicNumber();
      switch (atomicNumber) {
        case 6:  // carbon
        case 7:  // nitrogen
        case 8:  // oxygen
        case 15: // phos.
        case 33: // as
        case 51: // sb
        case 83: // bi
          break;
        default: // no inversion term for this element
          continue;
      }

      UFFOOP oop;
      oop._atom1 = i;
      oop._atom2 = neighbors[0];
      oop._atom3 = neighbors[1];
      oop._atom4 = neighbors[2];

      std::string symbol = uffparams[m_atomTypes[i]].label;
      if (symbol == "N_R" || symbol == "N_2" || symbol == "N_R" ||
          symbol == "O_2" || symbol == "O_R") {
        oop._c0 = 1.0;
        oop._c1 = -1.0;
        oop._c2 = 0.0;
        oop._koop = 6.0;
      } else if (symbol == "P_3+3" || symbol == "As3+3" || symbol == "Sb3+3" ||
                 symbol == "Bi3+3") {

        Real phi;
        switch (atomicNumber) {
          case 15: // P
            phi = 84.4339 * DEG_TO_RAD;
            break;
          case 33: // As
            phi = 86.9735 * DEG_TO_RAD;
            break;
          case 51: // Sb
            phi = 87.7047 * DEG_TO_RAD;
            break;
          case 83: // Bi
          default:
            phi = 90.0;
        }
        oop._c1 = -4.0 * cos(phi);
        oop._c2 = 1.0;
        oop._c0 = -1.0 * oop._c1 * cos(phi) + oop._c2 * cos(2.0 * phi);
        oop._koop = 22.0;
      } else if (symbol == "C_2" || symbol == "C_R") {
        oop._c0 = 1.0;
        oop._c1 = -1.0;
        oop._c2 = 0.0;
        oop._koop = 6.0;
        // check if one of the other atoms is "O_2"
        if (uffparams[m_atomTypes[neighbors[0]]].label == "O_2" ||
            uffparams[m_atomTypes[neighbors[1]]].label == "O_2" ||
            uffparams[m_atomTypes[neighbors[2]]].label == "O_2") {
          oop._koop = 50.0;
        }
      } else {
        continue;
      }

      m_oops.push_back(oop);
    }
  }

  void setTorsions()
  {
    DihedralIterator di(m_molecule);
    auto dihedral = di.begin();
    while (dihedral != di.end()) {
      Index i = std::get<0>(dihedral);
      Index j = std::get<1>(dihedral);
      Index k = std::get<2>(dihedral);
      Index l = std::get<3>(dihedral);

      // check the bond order of j-k
      // (if it's not rotatable, we can skip this one)
      Bond bond = m_molecule->bond(j, k);
      if (bond.order() != 1) {
        dihedral = ++di;
        continue;
      }

      UFFTorsion t;
      t._atom1 = i;
      t._atom2 = j;
      t._atom3 = k;
      t._atom4 = l;

      // default is for sp3-sp3
      Real order = static_cast<Real>(bond.order());

      auto symbol1 = uffparams[m_atomTypes[j]].label;
      auto symbol2 = uffparams[m_atomTypes[k]].label;

      // TODO: a bunch of special cases
      if (symbol1.size() < 3 || symbol2.size() < 3 || symbol1[2] == '3' ||
          symbol2[2] == '3') {
        // default is sp3-sp3
        t._n = 3;
        Real Vi_j = uffparams[m_atomTypes[j]].Vi;
        Real Vi_k = uffparams[m_atomTypes[k]].Vi;
        Real phi0 = 60.0;

        // handle some special cases
        // e.g. a pair of group 6 sp3 atoms
        auto atomicNumberJ = m_molecule->atom(j).atomicNumber();
        auto atomicNumberK = m_molecule->atom(k).atomicNumber();
        switch (atomicNumberJ) {
          case 8: // oxygen
            t._n = 2;
            phi0 = 90.0; // hydrogen peroxide H-O-O-H
            Vi_j = 2.0;
            break;
          case 16: // sulfur
          case 34: // selenium
          case 52: // tellurium
          case 84: // polonium
            Vi_j = 6.8;
            t._n = 2;
            phi0 = 90.0;
          default:
            break;
        }
        switch (atomicNumberK) {
          case 8: // oxygen
            t._n = 2;
            phi0 = 90.0; // hydrogen peroxide H-O-O-H
            Vi_k = 2.0;
            break;
          case 16: // sulfur
          case 34: // selenium
          case 52: // tellurium
          case 84: // polonium
            Vi_k = 6.8;
            t._n = 2;
            phi0 = 90.0;
          default:
            break;
        }

        t._cos_phi0 = cos(t._n * phi0 * DEG_TO_RAD);
        // geometric mean of the two V1 parameters
        t._ijkl = 0.5 * sqrt(Vi_j * Vi_k);
      } else if (symbol1[2] == 'R' && symbol2[2] == 'R') {
        order = 1.5;
        // tweak for amide
        if ((symbol1[0] == 'N' && symbol2[0] == 'C') ||
            (symbol1[0] == 'C' && symbol2[0] == 'N'))
          order = 1.41;
        t._n = 2;
        t._cos_phi0 = cos(t._n * 180.0 * DEG_TO_RAD);
        t._ijkl = 5.0 * sqrt(uffparams[m_atomTypes[j]].Uj *
                             uffparams[m_atomTypes[k]].Uj);
        t._ijkl *= 0.5 * (1.0 + 4.18 * log(order));
      } else if ((symbol1[2] == '2' && symbol2[2] == '3') ||
                 (symbol1[2] == '3' && symbol2[2] == '2')) {
        // sp2-sp3
        t._cos_phi0 = cos(0.0 * DEG_TO_RAD);
        t._n = 6;
        t._ijkl = 0.5;

        // exceptions for Oxygen, Sulfur, Selenium, Tellurium, Polonium
        auto atomicNumberJ = m_molecule->atom(j).atomicNumber();
        auto atomicNumberK = m_molecule->atom(k).atomicNumber();
        if (atomicNumberJ == 8 || atomicNumberK == 8 || atomicNumberJ == 16 ||
            atomicNumberK == 16 || atomicNumberJ == 34 || atomicNumberK == 34 ||
            atomicNumberJ == 52 || atomicNumberK == 52 || atomicNumberJ == 84 ||
            atomicNumberK == 84) {
          t._n = 2;
          t._cos_phi0 = cos(90.0 * DEG_TO_RAD);
        }

      } else {
        dihedral = ++di;
        continue;
      }

      m_torsions.push_back(t);
      dihedral = ++di;
    }
  }

  // check if atoms i and j are 1-2 or 1-3 connected
  // fairly fast because we're only checking neighbors
  bool areConnected(Index i, Index j)
  {
    const std::vector<Index>& neighbors = m_molecule->graph().neighbors(i);
    const std::vector<Index>& neighbors2 = m_molecule->graph().neighbors(j);
    for (Index k : neighbors) {
      if (k == j)
        return true;
      for (Index l : neighbors2) {
        if (l == k)
          return true;
      }
    }
    return false;
  }

  void setVdWs()
  {
    // we do a double-loop through the atoms
    // and check for 1-2 or 1-3 with areConnected
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      for (Index j = i + 1; j < m_molecule->atomCount(); ++j) {
        if (!areConnected(i, j)) {
          UFFVdW v;
          v._atom1 = i;
          v._atom2 = j;

          v._depth =
            sqrt(uffparams[m_atomTypes[i]].D1 * uffparams[m_atomTypes[j]].D1);
          v._x =
            sqrt(uffparams[m_atomTypes[i]].x1 * uffparams[m_atomTypes[j]].x1);
          m_vdws.push_back(v);
        }
      }
    }
  }

  Real bondEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;

    for (const UFFBond& bond : m_bonds) {
      Index i = bond._atom1;
      Index j = bond._atom2;
      Real r0 = bond._r0;
      Real kb = bond._kb;

      Real dx = x[3 * i] - x[3 * j];
      Real dy = x[3 * i + 1] - x[3 * j + 1];
      Real dz = x[3 * i + 2] - x[3 * j + 2];
      Real r = std::hypot(dx, dy, dz);
      Real dr = r - r0;

      /*
      std::cout << " Bond " << i << " " << j << " " << r0 << " " << r << " "
                << dr << std::endl;
                */

      // the 0.5 * kb is already in the kb to save a multiplication
      energy += kb * dr * dr;
    }
    return energy;
  }

  Real angleEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    for (const UFFAngle& angle : m_angles) {
      Index i = angle._atom1;
      Index j = angle._atom2;
      Index k = angle._atom3;
      Real theta0 = angle._theta0 * DEG_TO_RAD;
      Real kijk = angle._kijk;

      Real dx1 = x[3 * i] - x[3 * j];
      Real dy1 = x[3 * i + 1] - x[3 * j + 1];
      Real dz1 = x[3 * i + 2] - x[3 * j + 2];
      Real dx2 = x[3 * k] - x[3 * j];
      Real dy2 = x[3 * k + 1] - x[3 * j + 1];
      Real dz2 = x[3 * k + 2] - x[3 * j + 2];
      Real r1 = std::hypot(dx1, dy1, dz1);
      Real r2 = std::hypot(dx2, dy2, dz2);
      Real dot = dx1 * dx2 + dy1 * dy2 + dz1 * dz2;
      Real theta = acos(dot / (r1 * r2));

      /*
            std::cout << " Angle " << angle.coordination << " " << i << " " << j
         << " " << k << " " << r1 << " "
                      << r2 << " " << theta * RAD_TO_DEG << " " << theta0 *
         RAD_TO_DEG
                      << std::endl;
      */

      // TODO - migrate special cases from Open Babel
      Coordination coord = angle.coordination;
      Real c0 = angle._c0;
      Real c1 = angle._c1;
      Real c2 = angle._c2;
      switch (coord) {
        case Linear:
          // fixed typo in UFF paper (it's 1+ cos(theta) not 1 - cos(theta))
          energy += kijk * (1 + cos(c0 * theta));
          break;
        case Trigonal:
        case Resonant:
        case SquarePlanar:
        case Octahedral:
          // c0 contains n for these cases
          // and kijk is already divided by n**2
          // i.e., if the angle is less than approx theta0, energy goes up
          // exponentially
          energy +=
            kijk * (1 - cos(c0 * theta)) + exp(-20.0 * (theta - theta0 + 0.25));

          break;
        case Tetrahedral: {
          Real cosTheta = cos(theta);
          // use cos 2t = (2cos^2 - 1)
          energy +=
            kijk * (c0 + c1 * cosTheta + c2 * (2 * cosTheta * cosTheta - 1));
          break;
        }
        case TrigonalBipyramidal:
        case TrigonalBipentagonal:
        case Other:
        default:
          // just use a harmonic potential
          // but these should actually be set up as VdW repulsions
          // so this shouldn't ever happen
          energy += kijk * (theta - theta0) * (theta - theta0);
      }
    }

    return energy;
  }

  Real oopEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    for (const UFFOOP& oop : m_oops) {
      // for UFF - I is defined as the central atom
      Index i = oop._atom1;
      Index j = oop._atom2;
      Index k = oop._atom3;
      Index l = oop._atom4;

      Real koop = oop._koop;
      Real c0 = oop._c0;
      Real c1 = oop._c1;
      Real c2 = oop._c2;

      Vector3d vi(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      Vector3d vj(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      Vector3d vk(x[3 * k], x[3 * k + 1], x[3 * k + 2]);
      Vector3d vl(x[3 * l], x[3 * l + 1], x[3 * l + 2]);

      // use outOfPlaneAngle() from angletools.h
      Real angle = outOfPlaneAngle(vi, vj, vk, vl) * DEG_TO_RAD;
      energy += koop * (c0 + c1 * cos(angle) + c2 * cos(2 * angle));
    }

    return energy;
  }

  Real torsionEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    for (const UFFTorsion& torsion : m_torsions) {
      Index i = torsion._atom1;
      Index j = torsion._atom2;
      Index k = torsion._atom3;
      Index l = torsion._atom4;

      Vector3d vi(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      Vector3d vj(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      Vector3d vk(x[3 * k], x[3 * k + 1], x[3 * k + 2]);
      Vector3d vl(x[3 * l], x[3 * l + 1], x[3 * l + 2]);

      Real phi = calculateDihedral(vi, vj, vk, vl) * DEG_TO_RAD;

      Real cosPhi = cos(torsion._n * phi);
      Real cosPhi0 = torsion._cos_phi0;
      Real kijkl = torsion._ijkl;

      // 0.5 * kijkl is already in the kijkl to save a multiplication
      energy += kijkl * (1.0 - cosPhi0 * cosPhi);
    }

    return energy;
  }

  Real vdwEnergies(const Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    for (const UFFVdW& vdw : m_vdws) {
      Index i = vdw._atom1;
      Index j = vdw._atom2;
      Real depth = vdw._depth;
      Real xij = vdw._x;
      Real x6 = xij * xij * xij * xij * xij * xij;
      Real x12 = x6 * x6;

      Vector3 atom_i(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      Vector3 atom_j(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      // if the cell is nullptr, we can't do periodic boundary conditions
      Real r2;
      if (m_cell == nullptr) {
        r2 = (atom_i - atom_j).squaredNorm();
      } else {
        r2 = m_cell->distanceSquared(atom_i, atom_j);
      }

      // we don't need a square root since 6 and 12 are even powers
      Real r6 = r2 * r2 * r2;
      Real r12 = r6 * r6;
      energy += depth * (x12 / r12 - 2 * x6 / r6);
    }
    return energy;
  }

  void bondGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    for (const UFFBond& bond : m_bonds) {
      Index i = bond._atom1;
      Index j = bond._atom2;
      Real r0 = bond._r0;
      Real kb = bond._kb;

      Real dx = x[3 * i] - x[3 * j];
      Real dy = x[3 * i + 1] - x[3 * j + 1];
      Real dz = x[3 * i + 2] - x[3 * j + 2];

      Real r = std::hypot(dx, dy, dz);
      Real dr = r - r0;
      Real f = 2.0 * kb * dr / r;
      grad[3 * i] += f * dx;
      grad[3 * i + 1] += f * dy;
      grad[3 * i + 2] += f * dz;

      grad[3 * j] -= f * dx;
      grad[3 * j + 1] -= f * dy;
      grad[3 * j + 2] -= f * dz;
    }
  }

  void angleGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    // j is the central atom (i-j-k)
    for (const UFFAngle& angle : m_angles) {
      Index i = angle._atom1;
      Index j = angle._atom2;
      Index k = angle._atom3;
      Real theta0 = angle._theta0 * DEG_TO_RAD;
      Real kijk = angle._kijk;

      const Vector3d vi(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      const Vector3d vj(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      const Vector3d vk(x[3 * k], x[3 * k + 1], x[3 * k + 2]);

      const Vector3d ij = vi - vj;
      const Vector3d kj = vk - vj;

      Real rij = ij.norm();
      Real rkj = kj.norm();

      // check if these are near-zero
      if (rij < 1e-3 || rkj < 1e-3)
        continue; // skip this angle

      Real dot = ij.dot(kj);
      Vector3d ij_cross_kj = ij.cross(kj);
      Real crossNorm = ij_cross_kj.norm();

      // check for near-zero cross product
      if (!std::isfinite(crossNorm) || crossNorm < 1e-6)
        continue; // skip this angle

      Real theta = atan2(crossNorm, dot);
      // clamp the angle to -pi to pi
      if (theta < -M_PI)
        theta += 2 * M_PI;
      else if (theta > M_PI)
        theta -= 2 * M_PI;

      /*
            std::cout << " AngleGrad " << i << " " << j << " " << k << " "
                      << theta0 * RAD_TO_DEG << " " << theta * RAD_TO_DEG << " "
                      << dtheta * RAD_TO_DEG << " " << kijk << std::endl;
                      std::cout << " Norms " << rij << " " << rkj << " " << rki
         << std::endl;
      */

      // dE / dtheta is a bit annoying with UFF
      // because there are a bunch of special cases
      Real f = 0.0;
      Real c0 = angle._c0;
      Real c1 = angle._c1;
      Real c2 = angle._c2;
      switch (angle.coordination) {
        case Linear:
          // fixed typo in UFF paper (it's 1+ cos(theta) not 1 - cos(theta))
          // energy += kijk * (1 + cos(c0 * theta));
          f = -kijk * c0 * sin(c0 * theta);
          break;
        case Trigonal:
        case Resonant:
        case SquarePlanar:
        case Octahedral:
          // c0 contains n for these cases
          // and kijk is already divided by n**2
          // i.e., if the angle is less than approx theta0, energy goes up
          // exponentially
          // energy +=
          // kijk * (1 - cos(c0 * theta)) + exp(-20.0 * (theta - theta0 +
          // 0.25));
          f = kijk * c0 * sin(c0 * theta) -
              20.0 * exp(-20.0 * (theta - theta0 + 0.25));

          break;
        case Tetrahedral: {
          Real cosTheta = cos(theta);
          Real sinTheta = sin(theta);
          // use cos 2t = (2cos^2 - 1)
          // use sin 2t = 2sin(t)cos(t)
          // energy +=
          // kijk * (c0 + c1 * cosTheta + c2 * (2 * cosTheta * cosTheta - 1));
          f = -kijk * (c1 * sinTheta + c2 * 2 * (2 * cosTheta * sinTheta));
          break;
        }
        case TrigonalBipyramidal:
        case TrigonalBipentagonal:
        case Other:
        default:
          // energy += kijk * (theta - theta0) * (theta - theta0);
          f = 2.0 * kijk * (theta - theta0) * sin(theta);
          break;
      }

      // check for nan
      if (std::isnan(f))
        continue;

      // Use the cross product to get the gradients
      Vector3d n = ij_cross_kj / crossNorm;

      // Gradients of the cross products
      Vector3d grad_cross_i = (kj.cross(n)).stableNormalized();
      Vector3d grad_cross_k = (n.cross(ij)).stableNormalized();
      Vector3d grad_cross_j = -(grad_cross_i + grad_cross_k);

      // Gradients of the dot product
      Vector3d grad_dot_i = kj;
      Vector3d grad_dot_k = ij;
      Vector3d grad_dot_j = -(kj + ij);

      // Final gradient using atan2 derivative: d/dx(atan2(y,x)) = (x*dy/dx -
      // y*dx/dx)/(x^2 + y^2)
      Real denom = crossNorm * crossNorm + dot * dot;
      Vector3d grad_i =
        f * (grad_cross_i * dot - crossNorm * grad_dot_i) / denom;
      Vector3d grad_j =
        f * (grad_cross_j * dot - crossNorm * grad_dot_j) / denom;
      Vector3d grad_k =
        f * (grad_cross_k * dot - crossNorm * grad_dot_k) / denom;

      // Add the gradients to the total gradients for each atom
      grad[3 * i] += grad_i[0];
      grad[3 * i + 1] += grad_i[1];
      grad[3 * i + 2] += grad_i[2];

      grad[3 * j] += grad_j[0];
      grad[3 * j + 1] += grad_j[1];
      grad[3 * j + 2] += grad_j[2];

      grad[3 * k] += grad_k[0];
      grad[3 * k + 1] += grad_k[1];
      grad[3 * k + 2] += grad_k[2];
    }
  }

  void oopGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    for (const UFFOOP& oop : m_oops) {
      // for UFF - I is defined as the central atom
      Index i = oop._atom1;
      Index j = oop._atom2;
      Index k = oop._atom3;
      Index l = oop._atom4;

      Real koop = oop._koop;
      [[maybe_unused]] Real c0 = oop._c0;
      Real c1 = oop._c1;
      Real c2 = oop._c2;

      Vector3d vi(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      Vector3d vj(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      Vector3d vk(x[3 * k], x[3 * k + 1], x[3 * k + 2]);
      Vector3d vl(x[3 * l], x[3 * l + 1], x[3 * l + 2]);

      // use outOfPlaneAngle() from angletools.h
      Real angle = outOfPlaneAngle(vi, vj, vk, vl) * DEG_TO_RAD;
      Real sinAngle = sin(angle);
      // dE / dangle
      Real dE = koop * (-c1 * sinAngle - 2.0 * c2 * sin(2.0 * angle));

      // check for nan
      if (std::isnan(dE))
        continue;

      // Get the bond vectors
      Vector3d ij = vj - vi;
      Vector3d ik = vk - vi;
      Vector3d il = vl - vi;

      Real rij = ij.norm();
      Real rik = ik.norm();
      Real ril = il.norm();
      // check if the bond vectors are near zero
      if (rij < 1e-3 || rik < 1e-3 || ril < 1e-3)
        continue; // skip this oop
      // normalize the bond vectors
      ij = ij / rij;
      ik = ik / rik;
      il = il / ril;

      // we also need the angle between the bonds (i.e., j-i-k)
      Real cosTheta = ij.dot(ik) / (rij * rik);
      // clamp the cosTheta to -1 to 1
      cosTheta = std::clamp(cosTheta, -1.0, 1.0);
      Real theta = acos(cosTheta);
      Real sinTheta = sin(theta);

      // get the cross products
      [[maybe_unused]] Eigen::Vector3d ij_cross_ik =
        ij.cross(ik).stableNormalized();
      Eigen::Vector3d ik_cross_il = ik.cross(il).stableNormalized();
      Eigen::Vector3d ij_cross_il = ij.cross(il).stableNormalized();

      // some common factors
      [[maybe_unused]] Real numerator = cosTheta * sinAngle / sinTheta;

      // get the forces on the atoms
      Real dj0 =
        -dE *
        (ik_cross_il[0] - ij[0] + (ik[0] * cosTheta * sinAngle / sinTheta)) /
        (rij * sinTheta);
      Real dj1 =
        -dE *
        (ik_cross_il[1] - ij[1] + (ik[1] * cosTheta * sinAngle / sinTheta)) /
        (rij * sinTheta);
      Real dj2 =
        -dE *
        (ik_cross_il[2] - ij[2] + (ik[2] * cosTheta * sinAngle / sinTheta)) /
        (rij * sinTheta);
      grad[3 * j] += dj0;
      grad[3 * j + 1] += dj1;
      grad[3 * j + 2] += dj2;

      Real dk0 =
        -dE *
        (ij_cross_il[0] - ik[0] + (ij[0] * cosTheta * sinAngle / sinTheta)) /
        (rik * sinTheta);
      Real dk1 =
        -dE *
        (ij_cross_il[1] - ik[1] + (ij[1] * cosTheta * sinAngle / sinTheta)) /
        (rik * sinTheta);
      Real dk2 =
        -dE *
        (ij_cross_il[2] - ik[2] + (ij[2] * cosTheta * sinAngle / sinTheta)) /
        (rik * sinTheta);
      grad[3 * k] += dk0;
      grad[3 * k + 1] += dk1;
      grad[3 * k + 2] += dk2;

      Real dl0 = -dE * (-ij_cross_il[0] / sinTheta - il[0] * sinAngle) / ril;
      Real dl1 = -dE * (-ij_cross_il[1] / sinTheta - il[1] * sinAngle) / ril;
      Real dl2 = -dE * (-ij_cross_il[2] / sinTheta - il[2] * sinAngle) / ril;
      grad[3 * l] += dl0;
      grad[3 * l + 1] += dl1;
      grad[3 * l + 2] += dl2;

      // i is the central atom, so add the other forces
      grad[3 * i] -= dj0 + dk0 + dl0;
      grad[3 * i + 1] -= dj1 + dk1 + dl1;
      grad[3 * i + 2] -= dj2 + dk2 + dl2;
    }
  }

  void torsionGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    for (const UFFTorsion& torsion : m_torsions) {
      Index i = torsion._atom1;
      Index j = torsion._atom2;
      Index k = torsion._atom3;
      Index l = torsion._atom4;

      Vector3d vi(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      Vector3d vj(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      Vector3d vk(x[3 * k], x[3 * k + 1], x[3 * k + 2]);
      Vector3d vl(x[3 * l], x[3 * l + 1], x[3 * l + 2]);

      // get the bond vectors
      Vector3d ij = vj - vi;
      Vector3d jk = vk - vj;
      Vector3d kl = vl - vk;

      Real rij = ij.norm();
      Real rjk = jk.norm();
      Real rkl = kl.norm();

      // check if the bond vectors are near zero
      if (rij < 1e-3 || rjk < 1e-3 || rkl < 1e-3) {
        continue; // skip this torsion
      }

      Real phi = calculateDihedral(vi, vj, vk, vl) * DEG_TO_RAD;
      Real sinPhi = sin(phi);
      Real cosPhi = cos(phi);
      Real cosPhi0 = torsion._cos_phi0;
      Real kijkl = torsion._ijkl;
      // dE / dphi
      Real dE = kijkl * torsion._n * sin(torsion._n * phi) * cosPhi0;

      // skip this torsion
      if (std::abs(sinPhi) < 1e-6 || std::isnan(dE))
        continue;

      // Using the BallView / Open Babel formula
      // http://dx.doi.org/10.22028/D291-25896 (Appendix A)
      // Thanks to Andreas Moll
      // for the derivation of the gradients

      // get the unit vectors
      Vector3d n1 = ij / rij;
      Vector3d n2 = jk / rjk;
      Vector3d n3 = kl / rkl;

      // get the angles between ijk and jkl
      Vector3d n1_cross_n2 = n1.cross(n2);
      Vector3d n2_cross_n3 = n2.cross(n3);

      // check for near-zero cross products
      if (n1_cross_n2.norm() < 1e-6 || n2_cross_n3.norm() < 1e-6) {
        continue; // skip this torsion
      }

      Real sinAngleIJK = n1_cross_n2.norm();
      Real sinAngleJKL = n2_cross_n3.norm();
      Real cosAngleIJK = n1.dot(n2);
      Real cosAngleJKL = n2.dot(n3);

      // get the gradient components
      Vector3d grad_i = -n1_cross_n2 / (rij * sinAngleIJK * sinAngleIJK);
      Vector3d grad_l = n2_cross_n3 / (rkl * sinAngleJKL * sinAngleJKL);

      // grad_j and grad_k are a bit more complicated

      // clamp the cosines to -1 to 1
      cosAngleIJK = std::clamp(cosAngleIJK, -1.0, 1.0);
      cosAngleJKL = std::clamp(cosAngleJKL, -1.0, 1.0);

      Real fraction1 = (rij / rjk) * (-cosAngleIJK);
      Real fraction2 = (rkl / rjk) * (-cosAngleJKL);
      Vector3d grad_j = grad_i * (fraction1 - 1) - grad_l * (fraction2);
      Vector3d grad_k = -(grad_i + grad_l + grad_j);

      // add the gradients to the total gradients for each atom
      grad[3 * i] += dE * grad_i[0];
      grad[3 * i + 1] += dE * grad_i[1];
      grad[3 * i + 2] += dE * grad_i[2];

      grad[3 * j] += dE * grad_j[0];
      grad[3 * j + 1] += dE * grad_j[1];
      grad[3 * j + 2] += dE * grad_j[2];

      grad[3 * k] += dE * grad_k[0];
      grad[3 * k + 1] += dE * grad_k[1];
      grad[3 * k + 2] += dE * grad_k[2];

      grad[3 * l] += dE * grad_l[0];
      grad[3 * l + 1] += dE * grad_l[1];
      grad[3 * l + 2] += dE * grad_l[2];
    }
  }

  void vdwGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    for (const UFFVdW& vdw : m_vdws) {
      Index i = vdw._atom1;
      Index j = vdw._atom2;
      Real depth = vdw._depth;
      Real xij = vdw._x;

      // dE / dr for a Lennard-Jones potential
      // E = depth * (x^12 / r^12 - 2 * x^6 / r^6)
      // dE / dr = -12 * depth * x^12 / r^13 + 12 * depth * x^6 / r^7
      //         = -12 * depth * x^6 / r^7 * (x^6 / r^6 - 1)

      // TODO: handle unit cells and periodic boundary conditions
      Vector3 atom_i(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      Vector3 atom_j(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      Vector3 r = atom_i - atom_j;
      if (m_cell != nullptr) {
        r = m_cell->minimumImage(r);
      }
      Real r2 = r.squaredNorm();

      Real dx = r[0];
      Real dy = r[1];
      Real dz = r[2];

      Real r6 = r2 * r2 * r2;
      Real r7 = r6 * sqrt(r2);
      Real x6 = xij * xij * xij * xij * xij * xij;
      Real dE = 12 * depth * x6 / r7 * (1 - x6 / r6);

      grad[3 * i] += dE * dx;
      grad[3 * i + 1] += dE * dy;
      grad[3 * i + 2] += dE * dz;

      grad[3 * j] -= dE * dx;
      grad[3 * j + 1] -= dE * dy;
      grad[3 * j + 2] -= dE * dz;
    }
  }
};

UFF::UFF() : d(nullptr)
{
  // defined for 1-102
  for (unsigned int i = 0; i <= 102; ++i) {
    m_elements.set(i);
  }
}

UFF::~UFF() {}

void UFF::setMolecule(Core::Molecule* mol)
{
  m_molecule = mol;

  if (mol == nullptr) {
    return; // nothing to do
  }

  int numAtoms = mol->atomCount();
  if (numAtoms < 2)
    return; // nothing to do for single atoms

  // start with assigning atom types
  if (d != nullptr)
    delete d;

  d = new UFFPrivate(mol);
}

Real UFF::value(const Eigen::VectorXd& x)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return 0.0;
  if (m_molecule->atomCount() < 2)
    return 0.0; // no bonds

  Real energy = 0.0;

  // bond component
  energy += d->bondEnergies(x);
  // angle component
  energy += d->angleEnergies(x);
  // torsion component
  energy += d->torsionEnergies(x);
  // TODO: out-of-plane component
  // energy += d->oopEnergies(x);
  // van der Waals component
  energy += d->vdwEnergies(x);
  // UFF doesn't have electrostatics

  // Add constraint energies
  energy += constraintEnergies(x);

  return energy;
}

Real UFF::bondEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 2)
    return energy; // no bonds

  energy = d->bondEnergies(x);
  return energy;
}

Real UFF::angleEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 3)
    return energy; // no angle

  energy = d->angleEnergies(x);
  return energy;
}

Real UFF::oopEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 4)
    return energy; // no oop

  energy = d->oopEnergies(x);
  return energy;
}

Real UFF::torsionEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 4)
    return energy; // no torsion

  energy = d->torsionEnergies(x);
  return energy;
}

Real UFF::vdwEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return energy; // nothing to do
  if (m_molecule->atomCount() < 2)
    return energy; // nothing to do

  energy = d->vdwEnergies(x);
  return energy;
}

void UFF::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  // clear the gradients
  grad.setZero();

  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return; // nothing to do
  if (m_molecule->atomCount() < 2)
    return; // no bonds

  // bond gradients
  d->bondGradient(x, grad);
  // angle gradients
  d->angleGradient(x, grad);
  // torsion gradients
  d->torsionGradient(x, grad);
  // TODO: out-of-plane gradients
  // d->oopGradient(x, grad);
  // van der Waals gradients
  d->vdwGradient(x, grad);
  // UFF doesn't have electrostatics so we're done

  // handle any constraints
  cleanGradients(grad);
  constraintGradients(x, grad);
}

void UFF::bondGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 2)
    return; // no bonds

  d->bondGradient(x, grad);
}

void UFF::angleGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 3)
    return; // no bonds

  d->angleGradient(x, grad);
}

void UFF::oopGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 4)
    return; // no bonds

  d->oopGradient(x, grad);
}

void UFF::torsionGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 4)
    return; // no bonds

  d->torsionGradient(x, grad);
}

void UFF::vdwGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return; // nothing to do
  if (m_molecule->atomCount() < 2)
    return; // no bonds

  d->vdwGradient(x, grad);
}

} // namespace Avogadro::Calc
