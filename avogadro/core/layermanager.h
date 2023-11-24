/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_LAYERMANAGER_H
#define AVOGADRO_CORE_LAYERMANAGER_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include "array.h"
#include "layer.h"

#include <cassert>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace Avogadro {
namespace Core {

class Molecule;

/**
 * @class LayerData layermanager.h <avogadro/core/layermanager.h>
 * @brief Interface to store layer data structure.
 */
struct LayerData
{
  LayerData(std::string save = "") { deserialize(save); }

  /** save custom data, base save should never be called */
  virtual std::string serialize() { return ""; }

  /** load the saved @p save data and wait to know the class type to recreate it
   */
  virtual void deserialize(std::string save) { m_save = save; }

  virtual ~LayerData() = default;

  /** get the saved data */
  std::string getSave() const { return m_save; }

protected:
  std::string boolToString(bool b) { return b ? "true" : "false"; }
  bool stringToBool(std::string b) { return b == "true"; }
  std::string m_save;
};

/**
 * @class MoleculeInfo layermanager.h <avogadro/core/layermanager.h>
 * @brief All layer dependent data. Original molecule @p mol, is layer hidden
 * @p visible, accepts edits @p locked, and key-value data like @p enable,
 * and custom data @p settings.
 */
struct MoleculeInfo
{
  const Molecule* mol;
  std::vector<bool> visible;
  std::vector<bool> locked;
  std::map<std::string, std::vector<bool>> enable;
  std::map<std::string, Core::Array<LayerData*>> settings;
  Layer layer;
  std::set<std::string> loaded;

  MoleculeInfo(const Molecule* m) : mol(m)
  {
    locked.push_back(false);
    visible.push_back(true);
  }

  void clear()
  {
    visible.clear();
    locked.clear();
    enable.clear();
    layer.clear();
  }
};
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

  /** @return Layer from @p original and links @p original MoleculeInfo to @p
   * copy */
  static Layer& getMoleculeLayer(const Molecule* original,
                                 const Molecule* copy);

  /** @return the MoleculeInfo from active molecule */
  static std::shared_ptr<MoleculeInfo> getMoleculeInfo();

  /** @return the MoleculeInfo from @p mol */
  static std::shared_ptr<MoleculeInfo> getMoleculeInfo(const Molecule* mol);

  /** remove all data related to @p mol */
  static void deleteMolecule(const Molecule* mol);

  /** @return the layer quantity from activeMolecule */
  static size_t layerCount();

protected:
  static const Molecule* m_activeMolecule;
  static std::map<const Molecule*, std::shared_ptr<MoleculeInfo>> m_molToInfo;
};

} // namespace Core
} // namespace Avogadro

#endif
