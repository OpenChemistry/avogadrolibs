/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VANDERWAALS_H
#define AVOGADRO_QTPLUGINS_VANDERWAALS_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render the molecule as Van der Waals spheres.
 * @author Marcus D. Hanwell
 */
class VanDerWaals : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit VanDerWaals(QObject* parent = nullptr);
  ~VanDerWaals() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr(m_name.c_str()); }

  QString description() const override
  {
    return tr("Simple display of VdW spheres.");
  }

private:
  std::string m_name = "Van der Waals";
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_VANDERWAALS_H
