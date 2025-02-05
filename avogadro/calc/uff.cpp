/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "uff.h"
#include "uffdata.h"

#include <avogadro/core/array.h>
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
  Index m_atom1;
  Index m_atom2;
  Real m_r0;
  Real m_kb;
};

class UFFAngle
{
public:
  Index m_atom1;
  Index m_atom2;
  Index m_atom3;
  Real m_theta0;
  Real m_kijk;
  int coordination;
};

class UFFTorsion
{
public:
  Index m_atom1;
  Index m_atom2;
  Index m_atom3;
  Index m_atom4;
  Real m_phi0;
  Real m_klmn;
};

class UFFOOP
{
public:
  Index m_atom1;
  Index m_atom2;
  Index m_atom3;
  Index m_atom4;
  Real m_phi0;
  Real m_kop;
};

class UFFVdW
{
public:
  Index m_atom1;
  Index m_atom2;
  Real m_epsilon;
  Real m_r0;
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

    // output the atom types for debugging
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      std::cout << "Atom " << i << " type " << m_atomTypes[i] << std::endl;
    }
  }

  void setBonds()
  {
    // loop through the bonds
    for (Index i = 0; i < m_molecule->bondCount(); ++i) {
      const Core::Bond& bond = m_molecule->bond(i);
      Index atom1 = bond.atom1().index();
      Index atom2 = bond.atom2().index();
      UFFBond b;
      b.m_atom1 = atom1;
      b.m_atom2 = atom2;

      Real ri = uffparams[m_atomTypes[atom1]].r1;
      Real rj = uffparams[m_atomTypes[atom2]].r1;
      Real r0 = ri + rj;
      // bond order correction
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

      b.m_r0 = r0 + rbo + ren;
      Real z1 = uffparams[m_atomTypes[atom1]].Z1;
      Real z2 = uffparams[m_atomTypes[atom2]].Z1;
      b.m_kb = 664.12 * z1 * z2 / pow((b.m_r0), 3);
      m_bonds.push_back(b);
    }
  }

  void setAngles()
  {
    // TODO
  }

  void setOOPs()
  {
    // TODO
  }

  void setTorsions()
  {
    // TODO
  }

  void setVdWs()
  {
    // TODO
  }

  Real bondEnergies(const ::Eigen::VectorXd& x)
  {
    Real energy = 0.0;

    for (const UFFBond& bond : m_bonds) {
      Index i = bond.m_atom1;
      Index j = bond.m_atom2;
      Real r0 = bond.m_r0;
      Real kb = bond.m_kb;

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

  Real angleEnergies(const ::Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    for (const UFFAngle& angle : m_angles) {
      Index i = angle.m_atom1;
      Index j = angle.m_atom2;
      Index k = angle.m_atom3;
      Real theta0 = angle.m_theta0;
      Real kijk = angle.m_kijk;

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

  Real oopEnergies(const ::Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    return energy;
  }

  Real torsionEnergies(const ::Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    return energy;
  }

  Real vdwEnergies(const ::Eigen::VectorXd& x)
  {
    Real energy = 0.0;
    return energy;
  }

  void bondGradient(const ::Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    for (const UFFBond& bond : m_bonds) {
      Index i = bond.m_atom1;
      Index j = bond.m_atom2;
      Real r0 = bond.m_r0;
      Real kb = bond.m_kb;

      std::cout << "Bond " << i << " " << j << " r0 " << r0 << " kb " << kb
                << std::endl;

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

  void angleGradient(const ::Eigen::VectorXd& x, Eigen::VectorXd& grad) {}

  void oopGradient(const ::Eigen::VectorXd& x, Eigen::VectorXd& grad) {}

  void torsionGradient(const ::Eigen::VectorXd& x, Eigen::VectorXd& grad) {}

  void vdwGradient(const ::Eigen::VectorXd& x, Eigen::VectorXd& grad)
  {
    for (const UFFVdW& vdw : m_vdws) {
      Index i = vdw.m_atom1;
      Index j = vdw.m_atom2;

      // use a 6-12 Lennard-Jones potential
      Real epsilon = vdw.m_epsilon;
      Real r0 = vdw.m_r0;
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
  // out-of-plane component (TODO)
  energy += d->oopEnergies(x);
  // van der Waals component
  energy += d->vdwEnergies(x);
  // UFF doesn't have electrostatics
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
  // out-of-plane gradients (TODO)
  d->oopGradient(x, grad);
  // van der Waals gradients
  d->vdwGradient(x, grad);
  // UFF doesn't have electrostatics

  // handle any constraints
  cleanGradients(grad);
}

} // namespace Avogadro::Calc
