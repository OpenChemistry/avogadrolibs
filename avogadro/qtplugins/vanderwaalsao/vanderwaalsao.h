/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VANDERWAALSAO_H
#define AVOGADRO_QTPLUGINS_VANDERWAALSAO_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render the molecule as Van der Waals spheres with ambient occlusion.
 * @author Tim Vandermeersch
 */
class VanDerWaalsAO : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit VanDerWaalsAO(QObject* parent = nullptr);
  ~VanDerWaalsAO() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Van der Waals (AO)", "ambient occlusion"); }

  QString description() const override
  {
    return tr("Simple display of VdW spheres with ambient occlusion.");
  }

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

private:
  std::string m_name = "Van der Waals (AO)";
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_VANDERWAALSAO_H
