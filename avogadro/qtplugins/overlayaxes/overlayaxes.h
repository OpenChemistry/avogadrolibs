/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OVERLAYAXES_H
#define AVOGADRO_QTPLUGINS_OVERLAYAXES_H

#include <avogadro/qtgui/sceneplugin.h>

#include <avogadro/rendering/groupnode.h>

#include <map>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render reference axes in the corner of the display.
 */
class OverlayAxes : public Avogadro::QtGui::ScenePlugin
{
  Q_OBJECT
public:
  explicit OverlayAxes(QObject* parent = nullptr);
  ~OverlayAxes() override;

  QString name() const override { return tr("Reference Axes"); }
  QString description() const override
  {
    return tr("Render reference axes in the corner of the display.");
  }

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

private:
  std::string m_name = "Reference Axes";

  class RenderImpl;
  RenderImpl* const m_render;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OVERLAYAXES_H
