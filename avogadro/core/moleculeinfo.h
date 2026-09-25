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
#include <memory>
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

/** Owning handle to a layer's per-plugin data. */
using LayerDataPtr = std::shared_ptr<LayerData>;

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
  std::map<std::string, Core::Array<LayerDataPtr>> settings;
  Layer layer;
  std::set<std::string> loaded;

  MoleculeInfo()
  {
    locked.push_back(false);
    visible.push_back(true);
  }

  /**
   * Copy every layer property, cloning the per-plugin settings.
   *
   * Each molecule owns its own settings objects rather than sharing them:
   * layers are per molecule, so editing a copy's settings must not reach back
   * into the molecule it was copied from.
   */
  MoleculeInfo(const MoleculeInfo& other)
    : visible(other.visible), locked(other.locked), enable(other.enable),
      settings(cloneSettings(other.settings)), layer(other.layer),
      loaded(other.loaded)
  {
  }

  MoleculeInfo& operator=(const MoleculeInfo& other)
  {
    if (this != &other) {
      visible = other.visible;
      locked = other.locked;
      enable = other.enable;
      settings = cloneSettings(other.settings);
      layer = other.layer;
      loaded = other.loaded;
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
    settings.clear();
    layer.clear();
    loaded.clear();
  }

private:
  static std::map<std::string, Core::Array<LayerDataPtr>> cloneSettings(
    const std::map<std::string, Core::Array<LayerDataPtr>>& source)
  {
    std::map<std::string, Core::Array<LayerDataPtr>> copy;
    for (const auto& entry : source) {
      Core::Array<LayerDataPtr> cloned;
      cloned.reserve(entry.second.size());
      for (const auto& data : entry.second)
        cloned.push_back(data ? LayerDataPtr(data->clone()) : nullptr);
      copy[entry.first] = cloned;
    }
    return copy;
  }
};

} // namespace Avogadro::Core

#endif
