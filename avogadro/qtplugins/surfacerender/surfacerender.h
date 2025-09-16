/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_MESHES_H
#define AVOGADRO_QTPLUGINS_MESHES_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render one or more triangular meshes.
 * @author Marcus D. Hanwell
 */
class SurfaceRender : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit SurfaceRender(QObject* parent = nullptr);
  ~SurfaceRender() override;

  void process(const QtGui::Molecule& mol, Rendering::GroupNode& node) override;

  QString name() const override { return tr("Surfaces"); }

  QString description() const override
  {
    return tr("Render molecular surfaces.");
  }

  QWidget* setupWidget() override;
  bool hasSetupWidget() const override { return true; }

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

  enum Style
  {
    Surface = 0,
    Wireframe = 1,
    Volume = 2
  };

private slots:
  void setColor1(const QColor& color);
  void setColor2(const QColor& color);
  void setOpacity(int opacity);
  void setStyle(int style);
  void setLineWidth(double width);

private:
  std::string m_name = "Surfaces";

  QWidget* m_setupWidget;
  unsigned char m_opacity;
  Vector3ub m_color1;
  Vector3ub m_color2;
  unsigned char m_style;
  float m_lineWidth;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MESHES_H
