/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_EEQMODEL_H
#define AVOGADRO_CALC_EEQMODEL_H

#include "avogadrocalcexport.h"

#include <avogadro/calc/chargemodel.h>

#include <cstddef>

namespace Avogadro::Calc {

/**
 * @class EEQModel eeqmodel.h <avogadro/calc/eeqmodel.h>
 * @brief Electronegativity equilibration (EEQ 2019) partial charges
 *
 * The charge model used by DFT-D4: a coordination-number dependent
 * electronegativity equilibration with Gaussian charge distributions,
 * parameterized for elements 1-103. The total charge of the molecule
 * (Core::Molecule::totalCharge()) is conserved.
 *
 * E. Caldeweyher, S. Ehlert, A. Hansen, H. Neugebauer, S. Spicher,
 * C. Bannwarth and S. Grimme, J. Chem. Phys. 2019, 150, 154122,
 * DOI 10.1063/1.5090222
 *
 * The implementation and parameters are ported from grimme-lab/multicharge
 * (Apache-2.0); see eeqdata.h.
 *
 * Scope: this is the molecular (finite system) model only. Periodic (Ewald)
 * EEQ is not implemented, so a molecule with a unit cell is treated as an
 * isolated cluster of the atoms in the cell, ignoring periodic images.
 *
 * Systems larger than maxAtoms() are refused: the dense bordered matrix needs
 * O(N^2) memory and the solve is O(N^3), which exhausts memory (notably in
 * WebAssembly builds) long before it is useful.
 *
 * On failure (unsupported element, too many atoms, a non-finite solution) an
 * error is recorded with appendError() and a zero charge for each atom is
 * returned.
 *
 * Internally the model works in Bohr, Hartree and elementary charges;
 * positions are converted from Angstrom.
 */
class AVOGADROCALC_EXPORT EEQModel : public ChargeModel
{
public:
  EEQModel() = default;
  ~EEQModel() override = default;

  ChargeModel* newInstance() const override { return new EEQModel; }

  std::string identifier() const override { return "eeq"; }

  std::string name() const override { return "EEQ (DFT-D4)"; }

  /** @return the elements with parameters, Z = 1 to 103 */
  Core::Molecule::ElementMask elements() const override;

  /** @return an N x 1 matrix of partial charges (e) */
  MatrixX partialCharges(Core::Molecule& mol) const override;

  MatrixX partialCharges(const Core::Molecule& mol) const override;

  /** @return the largest number of atoms the model will accept */
  static constexpr std::size_t maxAtoms() { return 4000; }
};

} // namespace Avogadro::Calc

#endif // AVOGADRO_CALC_EEQMODEL_H
