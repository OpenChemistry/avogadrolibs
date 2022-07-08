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
class Meshes : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Meshes(QObject* parent = nullptr);
  ~Meshes() override;

  void process(const QtGui::Molecule& mol, Rendering::GroupNode& node) override;

  QString name() const override { return tr("Meshes"); }

  QString description() const override { return tr("Render polygon meshes."); }

  QWidget* setupWidget() override;

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

private slots:
  void setColor1(const QColor& color);
  void setColor2(const QColor& color);
  void setOpacity(int opacity);

private:
  std::string m_name = "Meshes";

  QWidget* m_setupWidget;
  unsigned char m_opacity;
  Vector3ub m_color1;
  Vector3ub m_color2;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MESHES_H
