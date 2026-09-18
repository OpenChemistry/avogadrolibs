/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_LAYERMANAGER_H
#define AVOGADRO_CORE_LAYERMANAGER_H

#include "avogadrocoreexport.h"

#include "layer.h"
#include "moleculeinfo.h"

#include <map>
#include <memory>
#include <string>

namespace Avogadro::Core {

class Molecule;

/**
 * @class LayerManager layermanager.h <avogadro/core/layermanager.h>
 * @brief
 */
class AVOGADROCORE_EXPORT LayerManager
{
public:
  /** @return active molecule Layer */
  static Layer& getMoleculeLayer();

  /** @return Layer from @p mol and creates MoleculeInfo if not exists */
  static Layer& getMoleculeLayer(const Molecule* mol);

  /** @return the MoleculeInfo from active molecule */
  static std::shared_ptr<MoleculeInfo> getMoleculeInfo();

  /** @return the MoleculeInfo from @p mol */
  static std::shared_ptr<MoleculeInfo> getMoleculeInfo(const Molecule* mol);

  /** @return the layer quantity from activeMolecule */
  static size_t layerCount();

protected:
  /**
   * @return the layer state of the active molecule, or nullptr when there is
   * no active molecule.
   */
  static std::shared_ptr<MoleculeInfo> activeMoleculeInfo();

  /** @return the layer state of @p mol, or nullptr when @p mol is null. */
  static std::shared_ptr<MoleculeInfo> findMoleculeInfo(const Molecule* mol);

  /**
   * The molecule the layer GUI and the render plugins currently act on.
   *
   * Layer state itself is owned by each Molecule, so this is only a cursor,
   * not a registry: nothing here keeps a molecule or its layers alive.
   */
  static const Molecule* m_activeMolecule;
};

} // namespace Avogadro::Core

#endif
