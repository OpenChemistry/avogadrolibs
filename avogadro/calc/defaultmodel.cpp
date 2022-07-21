/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "defaultmodel.h"

#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>

namespace Avogadro {

using Core::Molecule;

namespace Calc {

DefaultModel::DefaultModel(const std::string& id)
  : m_identifier(id), ChargeModel()
{
  // we don't know which elements are in the molecule
  // but we can just say all of them are okay
  // (because this method should work for any molecule)
  m_elements.set();
}

DefaultModel::~DefaultModel() {}

MatrixX DefaultModel::partialCharges(Core::Molecule& mol) const
{
  return mol.partialCharges(m_identifier);
}

} // namespace Calc
} // namespace Avogadro
