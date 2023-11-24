/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_SLATERSET_H
#define AVOGADRO_CORE_SLATERSET_H

#include "basisset.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

#include <vector>

namespace Avogadro {
namespace Core {

/**
 * @class SlaterSet slaterset.h
 * @brief SlaterSet Class
 * @author Marcus D. Hanwell
 *
 * The SlaterSet class has a transparent data structure for storing the basis
 * sets output by many quantum mechanical codes. It has a certain hierarchy
 * where shells are built up from n primitives, in this case Slater Type
 * Orbitals (STOs). Each shell has a type (S, P, D, F, etc) and is composed of
 * one or more STOs. Each STO has a contraction coefficient, c, and an exponent,
 * a.
 *
 * When calculating Molecular Orbitals (MOs) each orthogonal shell has an
 * independent coefficient. That is the S type orbitals have one coefficient,
 * the P type orbitals have three coefficients (Px, Py and Pz), the D type
 * orbitals have five (or six if cartesian types) coefficients, and so on.
 */

struct SlaterShell;

class AVOGADROCORE_EXPORT SlaterSet : public BasisSet
{
public:
  /**
   * Constructor.
   */
  SlaterSet();

  /**
   * Destructor.
   */
  ~SlaterSet() override;

  /**
   * Clone.
   */
  SlaterSet* clone() const override { return new SlaterSet(*this); }

  /**
   * Enumeration of the Slater orbital types.
   */
  enum slater
  {
    S,
    PX,
    PY,
    PZ,
    X2,
    XZ,
    Z2,
    YZ,
    XY,
    UU
  };

  /**
   * Add a basis to the basis set.
   * @param i Index of the atom to add the Basis too.
   * @return The index of the added Basis.
   */
  bool addSlaterIndices(const std::vector<int>& i);

  /**
   * Add the symmetry types for the orbitals.
   * @param t Vector containing the types of symmetry using the slater enum.
   */
  bool addSlaterTypes(const std::vector<int>& t);

  /**
   * Add a STO to the supplied basis.
   * @param zetas The exponents of the STOs
   * @return True if successful.
   */
  bool addZetas(const std::vector<double>& zetas);

  /**
   * The PQNs for the orbitals.
   */
  bool addPQNs(const std::vector<int>& pqns);

  /**
   * The overlap matrix.
   * @param m Matrix containing the overlap matrix for the basis.
   */
  bool addOverlapMatrix(const Eigen::MatrixXd& m);

  /**
   * Add Eigen Vectors to the SlaterSet.
   * @param e Matrix of the eigen vectors for the SlaterSet.
   */
  bool addEigenVectors(const Eigen::MatrixXd& e);

  /**
   * Add the density matrix to the SlaterSet.
   * @param d Density matrix for the SlaterSet.
   */
  bool addDensityMatrix(const Eigen::MatrixXd& d);

  /**
   * @return The number of molecular orbitals in the BasisSet.
   */
  unsigned int molecularOrbitalCount(ElectronType type = Paired) override;

  /**
   * @return True of the basis set is valid, false otherwise.
   * Default is true, if false then the basis set is likely unusable.
   */
  bool isValid() override { return true; }

  /**
   * Initialize the calculation, this must normally be done before anything.
   */
  void initCalculation();

  /**
   * Accessors for the various properties of the GaussianSet.
   */
  std::vector<int>& slaterIndices() { return m_slaterIndices; }
  std::vector<int>& slaterTypes() { return m_slaterTypes; }
  std::vector<double>& zetas() { return m_zetas; }
  std::vector<double>& factors() { return m_factors; }
  std::vector<int>& PQNs() { return m_PQNs; }
  MatrixX& normalizedMatrix() { return m_normalized; }
  MatrixX& densityMatrix() { return m_density; }

  void outputAll();

private:
  std::vector<int> m_slaterIndices;
  std::vector<int> m_slaterTypes;
  std::vector<double> m_zetas;
  std::vector<int> m_pqns, m_PQNs;

  std::vector<double> m_factors;
  MatrixX m_overlap;
  MatrixX m_eigenVectors;
  MatrixX m_density;
  MatrixX m_normalized;
  bool m_initialized;

  unsigned int factorial(unsigned int n);
};

} // End Core namespace
} // End Avogadro namespace

#endif
