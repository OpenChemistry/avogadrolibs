/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_LAYERMANAGER_H
#define AVOGADRO_CORE_LAYERMANAGER_H

#include "avogadrocore.h"

#include "layer.h"

#include <cassert>
#include <map>
#include <memory>
#include <vector>

namespace Avogadro {
namespace Core {

class Molecule;
struct LayerData
{
  LayerData(std::string save = "") { load(save); }
  virtual std::string save()
  {
    assert(true);
    return "";
  }
  virtual void load(std::string save) { m_save = save; }
  virtual ~LayerData() = default;

  std::string getSave() const { return m_save; }

protected:
  std::string boolToString(bool b) { return b ? "true" : "false"; }
  bool stringToBool(std::string b) { return b == "true"; }
  std::string m_save;
};

struct MoleculeInfo
{
  const Molecule* mol;
  std::vector<bool> visible;
  std::vector<bool> locked;
  std::map<std::string, std::vector<bool>> enable;
  std::map<std::string, std::vector<LayerData*>> settings;
  Layer layer;

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

class AVOGADROCORE_EXPORT LayerManager
{
public:
  // active Layer
  static Layer& getMoleculeLayer();
  static Layer& getMoleculeLayer(const Molecule* mol);
  static Layer& getMoleculeLayer(const Molecule* original,
                                 const Molecule* copy);

  static std::shared_ptr<MoleculeInfo> getMoleculeInfo();
  static std::shared_ptr<MoleculeInfo> getMoleculeInfo(const Molecule* mol);

  static void deleteMolecule(const Molecule* mol);
  static size_t layerCount();

protected:
  static const Molecule* m_activeMolecule;
  static std::map<const Molecule*, std::shared_ptr<MoleculeInfo>> m_molToInfo;
};

} // namespace Core
} // namespace Avogadro

#endif
