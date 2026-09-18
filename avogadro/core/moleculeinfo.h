/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_MOLECULEINFO_H
#define AVOGADRO_CORE_MOLECULEINFO_H

#include "avogadrocoreexport.h"

#include "array.h"
#include "layer.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace Avogadro::Core {

/**
 * @class LayerData moleculeinfo.h <avogadro/core/moleculeinfo.h>
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

  virtual LayerData* clone() { return new LayerData(serialize()); };

  /** get the saved data */
  std::string getSave() const { return m_save; }

protected:
  std::string boolToString(bool b) { return b ? "true" : "false"; }
  bool stringToBool(std::string b) { return b == "true"; }
  std::string m_save;
};

/**
 * @class MoleculeInfo moleculeinfo.h <avogadro/core/moleculeinfo.h>
 * @brief All layer dependent data for one molecule: which layers are hidden
 * (@p visible) or refuse edits (@p locked), per-plugin key-value data
 * (@p enable), and per-plugin custom data (@p settings).
 *
 * Owned by the Molecule it belongs to, and shared with any undo command that
 * needs it to outlive a single operation.
 */
struct MoleculeInfo
{
  std::vector<bool> visible;
  std::vector<bool> locked;
  std::map<std::string, std::vector<bool>> enable;
  std::map<std::string, Core::Array<LayerData*>> settings;
  Layer layer;
  std::set<std::string> loaded;

  MoleculeInfo()
  {
    locked.push_back(false);
    visible.push_back(true);
  }

  /**
   * Copy every layer property except @p settings and @p loaded.
   *
   * settings holds raw LayerData pointers whose ownership is not yet resolved,
   * so copying them would alias one allocation between two molecules. Plugins
   * recreate their settings on demand through
   * PluginLayerManager::getSetting(), and @p loaded only records which plugins
   * have deserialized theirs, so it goes with them.
   */
  MoleculeInfo(const MoleculeInfo& other)
    : visible(other.visible), locked(other.locked), enable(other.enable),
      layer(other.layer)
  {
  }

  MoleculeInfo& operator=(const MoleculeInfo& other)
  {
    if (this != &other) {
      visible = other.visible;
      locked = other.locked;
      enable = other.enable;
      layer = other.layer;
    }
    return *this;
  }

  MoleculeInfo(MoleculeInfo&&) = default;
  MoleculeInfo& operator=(MoleculeInfo&&) = default;
  ~MoleculeInfo() = default;

  void clear()
  {
    visible.clear();
    locked.clear();
    enable.clear();
    layer.clear();
  }
};

} // namespace Avogadro::Core

#endif
