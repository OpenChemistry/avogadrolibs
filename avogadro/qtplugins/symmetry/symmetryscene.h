/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SYMMETRYSCENE_H
#define AVOGADRO_QTPLUGINS_SYMMETRYSCENE_H

#include <avogadro/qtgui/sceneplugin.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render the symmetry elements
 */
class SymmetryScene : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit SymmetryScene(QObject* parent = nullptr);
  ~SymmetryScene() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  void processEditable(const QtGui::RWMolecule& molecule,
                       Rendering::GroupNode& node) override;

  QString name() const override { return tr("Symmetry Elements"); }

  QString description() const override
  {
    return tr("Render symmetry elements.");
  }

  bool isEnabled() const override;

  bool isActiveLayerEnabled() const override;

  void setEnabled(bool enable) override;

private:
  bool m_enabled;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SYMMETRYSCENE_H
