/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_LAYERMANAGER_H
#define AVOGADRO_CORE_LAYERMANAGER_H

#include "avogadrocore.h"

#include "array.h"
#include "layer.h"

#include <memory>

namespace Avogadro {
namespace Core {

class Molecule;

struct MoleculeInfo
{
  const Molecule* mol;
  std::vector<bool> visible;
  std::vector<bool> locked;
  std::map<std::string, std::vector<bool>> enable;
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
  LayerManager();
  LayerManager(const std::string& name);

  // active Layer
  static Core::Layer& getMoleculeLayer();
  static Core::Layer& getMoleculeLayer(const Core::Molecule* mol);
  static std::shared_ptr<MoleculeInfo> getMoleculeInfo();
  static std::shared_ptr<MoleculeInfo> getMoleculeInfo(
    const Core::Molecule* mol);
  static void deleteMolecule(const Core::Molecule* mol);
  static Core::Layer& getMoleculeLayer(const Core::Molecule* original,
                                       const Core::Molecule* copy);
  static bool activeLayerLocked();

  bool isEnabled() const;
  bool isActiveLayerEnabled() const;
  void setEnabled(bool enable);
  bool atomEnabled(Index atom) const;
  bool bondEnabled(Index atom1, Index atom2) const;
  size_t layerCount() const;

protected:
  bool visible(size_t layer) const;
  bool locked(size_t layer) const;
  void flipVisible(size_t layer);
  void flipLocked(size_t layer);
  void addMolecule(const Molecule* mol);
  Core::Array<std::pair<size_t, std::string>> activeMoleculeNames() const;

  static const Molecule* m_activeMolecule;
  static std::map<const Molecule*, std::shared_ptr<MoleculeInfo>> m_molToInfo;
  std::string m_name;
};

} // namespace Core
} // namespace Avogadro

#endif
