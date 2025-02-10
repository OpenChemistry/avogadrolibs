/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "uff.h"
#include "uffdata.h"

#include <avogadro/core/angleiterator.h>
#include <avogadro/core/angletools.h>
#include <avogadro/core/array.h>
#include <avogadro/core/dihedraliterator.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

namespace Avogadro::Calc {

using namespace Core;

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
            int charge = m_molecule->formalCharge(i);
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
                while (j < 125 && uffparams[j + 1].label[2] != coord) {
                  ++j;
                }
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

        const char symbol = uffparams[m_atomTypes[i]].label[2];
        // we allow N next to another sp2 to be resonant (e.g. amide)
        if (atomicNumber != 7 && symbol != '2')
          continue;

        // check the neighbors
        const std::vector<Index>& neighbors = m_molecule->graph().neighbors(i);
        bool resonant = false;
        for (Index j : neighbors) {
          auto symbol = uffparams[m_atomTypes[j]].label;
          if (symbol.size() < 3)
            continue; // not a resonant type

          if (symbol[2] == '2' || symbol[2] == 'R') {
            resonant = true;
            break;
          }
        }
        if (resonant) {
          // set the resonant type
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

      Real theta0 = uffparams[m_atomTypes[j]].theta0;
      a._theta0 = theta0;

      // calculate the kijk
      Real rij = calculateRij(i, j);
      Real rjk = calculateRij(j, k);

      // std::cout << " Angle " << i << " " << j << " " << k << " " << rij << "
      // "
      //           << rjk << " " << theta0 << std::endl;

      Real rik = sqrt(rij * rij + rjk * rjk - 2 * rij * rjk * cos(theta0));
      Real Zi = uffparams[m_atomTypes[i]].Z1;
      Real Zk = uffparams[m_atomTypes[k]].Z1;
      Real cosTheta0 = cos(theta0);
      Real cosTheta0Sq = cosTheta0 * cosTheta0;
      // see https://towhee.sourceforge.net/forcefields/uff.html
      // e.g., original paper had some typos
      a._kijk = 664.12 / (rij * rjk) * (Zi * Zk) / (pow(rik, 5)) * rij * rjk;
      a._kijk *= (3 * rij * rjk * (1 - cosTheta0Sq) - rik * rik * cosTheta0);

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
        t._cos_phi0 = cos(t._n * 60.0 * DEG_TO_RAD);
        // geometric mean of the two V1 parameters
        t._ijkl = 0.5 * sqrt(uffparams[m_atomTypes[j]].Vi *
                             uffparams[m_atomTypes[k]].Vi);
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
      Real r = sqrt(dx * dx + dy * dy + dz * dz);
      Real dr = r - r0;
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
      Real r1 = sqrt(dx1 * dx1 + dy1 * dy1 + dz1 * dz1);
      Real r2 = sqrt(dx2 * dx2 + dy2 * dy2 + dz2 * dz2);
      Real dot = dx1 * dx2 + dy1 * dy2 + dz1 * dz2;
      Real theta = acos(dot / (r1 * r2));
      Real dtheta = theta - theta0;
      // hah, if only UFF used harmonic angles
      energy += 0.5 * kijk * dtheta * dtheta;
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

      Eigen::Vector3d vi(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      Eigen::Vector3d vj(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      Eigen::Vector3d vk(x[3 * k], x[3 * k + 1], x[3 * k + 2]);
      Eigen::Vector3d vl(x[3 * l], x[3 * l + 1], x[3 * l + 2]);

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

      Eigen::Vector3d vi(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      Eigen::Vector3d vj(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      Eigen::Vector3d vk(x[3 * k], x[3 * k + 1], x[3 * k + 2]);
      Eigen::Vector3d vl(x[3 * l], x[3 * l + 1], x[3 * l + 2]);

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

      Real dx = x[3 * i] - x[3 * j];
      Real dy = x[3 * i + 1] - x[3 * j + 1];
      Real dz = x[3 * i + 2] - x[3 * j + 2];
      // we don't need a square root since 6 and 12 are even powers
      Real r2 = (dx * dx + dy * dy + dz * dz);
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

      Real r = sqrt(dx * dx + dy * dy + dz * dz);
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
    for (const UFFAngle& angle : m_angles) {
      Index i = angle._atom1;
      Index j = angle._atom2;
      Index k = angle._atom3;
      Real theta0 = angle._theta0 * DEG_TO_RAD;
      Real kijk = angle._kijk;

      const Eigen::Vector3d vi(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      const Eigen::Vector3d vj(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
      const Eigen::Vector3d vk(x[3 * k], x[3 * k + 1], x[3 * k + 2]);

      const Eigen::Vector3d ij = vi - vj;
      const Eigen::Vector3d kj = vk - vj;
      const Eigen::Vector3d ki = vk - vi;

      Real rij = ij.norm();
      Real rkj = kj.norm();
      Real rki = ki.norm();

      Real dot = ij.dot(kj);
      Real theta = acos(dot / (rij * rkj));
      Real dtheta = theta - theta0;

      //      std::cout << " Angle " << i << " " << j << " " << k << " "
      //                << theta0 * RAD_TO_DEG << " " << theta * RAD_TO_DEG << "
      //                "
      //                << dtheta * RAD_TO_DEG << std::endl;

      // dE / dtheta
      Real f = 2 * kijk * dtheta;

      // check for nan
      if (std::isnan(f))
        continue;

      // dtheta (using cross products)
      // .. we're using ij x ki to get a perpendicular
      // .. then cross with ij or kj to move those atoms

      Eigen::Vector3d ij_cross_ki = ij.cross(ki) / (rij * rki);
      Eigen::Vector3d ijki_cross_ij = ij_cross_ki.cross(ij) / (rij);

      grad[3 * i] += f * ijki_cross_ij[0];
      grad[3 * i + 1] += f * ijki_cross_ij[1];
      grad[3 * i + 2] += f * ijki_cross_ij[2];

      Eigen::Vector3d ijki_cross_kj = ij_cross_ki.cross(kj) / (rkj);

      // std::cout << " Cross norms " << ij_cross_ki.norm() << " "
      //           << ijki_cross_ij.norm() << " " << ijki_cross_kj.norm() <<
      //           std::endl;

      grad[3 * k] += f * ijki_cross_kj[0];
      grad[3 * k + 1] += f * ijki_cross_kj[1];
      grad[3 * k + 2] += f * ijki_cross_kj[2];

      // the central atom
      grad[3 * j] -= f * (ijki_cross_ij[0] + ijki_cross_kj[0]);
      grad[3 * j + 1] -= f * (ijki_cross_ij[1] + ijki_cross_kj[1]);
      grad[3 * j + 2] -= f * (ijki_cross_ij[2] + ijki_cross_kj[2]);
    }
  }

  void oopGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad) {}

  void torsionGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad) {}

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
      //         = 12 * depth * x^6 / r^7 * (x^6 / r^6 - 1)

      Real dx = x[3 * i] - x[3 * j];
      Real dy = x[3 * i + 1] - x[3 * j + 1];
      Real dz = x[3 * i + 2] - x[3 * j + 2];
      Real r2 = dx * dx + dy * dy + dz * dz;
      Real r6 = r2 * r2 * r2;
      Real r7 = r6 * sqrt(r2);
      Real x6 = xij * xij * xij * xij * xij * xij;
      Real dE = 12 * depth * x6 / r7 * (x6 / r6 - 1);

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
  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
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
  // out-of-plane component
  energy += d->oopEnergies(x);
  // van der Waals component
  energy += d->vdwEnergies(x);
  // UFF doesn't have electrostatics
  return energy;
}

Real UFF::bondEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return energy; // nothing to do
  if (m_molecule->atomCount() < 2)
    return energy; // no bonds

  energy = d->bondEnergies(x);
  return energy;
}

Real UFF::angleEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return energy; // nothing to do
  if (m_molecule->atomCount() < 3)
    return energy; // no angle

  energy = d->angleEnergies(x);
  return energy;
}

Real UFF::oopEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return energy; // nothing to do
  if (m_molecule->atomCount() < 4)
    return energy; // no oop

  energy = d->oopEnergies(x);
  return energy;
}

Real UFF::torsionEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return energy; // nothing to do
  if (m_molecule->atomCount() < 4)
    return energy; // no torsion

  energy = d->torsionEnergies(x);
  return energy;
}

Real UFF::vdwEnergy(const Eigen::VectorXd& x)
{
  Real energy = 0.0;

  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return energy; // nothing to do
  if (m_molecule->atomCount() < 2)
    return energy; // nothing to do

  energy = d->vdwEnergies(x);
  return energy;
}

/*
// TODO - for now use numeric gradients

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
  // out-of-plane gradients
  d->oopGradient(x, grad);
  // van der Waals gradients
  d->vdwGradient(x, grad);
  // UFF doesn't have electrostatics so we're done

  // handle any constraints
  cleanGradients(grad);
}

*/

void UFF::bondGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return; // nothing to do
  if (m_molecule->atomCount() < 2)
    return; // no bonds

  d->bondGradient(x, grad);
}

void UFF::angleGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return; // nothing to do
  if (m_molecule->atomCount() < 3)
    return; // no bonds

  d->angleGradient(x, grad);
}

void UFF::oopGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return; // nothing to do
  if (m_molecule->atomCount() < 4)
    return; // no bonds

  d->oopGradient(x, grad);
}

void UFF::torsionGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return; // nothing to do
  if (m_molecule->atomCount() < 4)
    return; // no bonds

  d->torsionGradient(x, grad);
}

void UFF::vdwGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule || !d || x.size() != 3 * m_molecule->atomCount())
    return; // nothing to do
  if (m_molecule->atomCount() < 2)
    return; // no bonds

  d->vdwGradient(x, grad);
}

} // namespace Avogadro::Calc
