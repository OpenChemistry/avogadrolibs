/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VOLUMES_H
#define AVOGADRO_QTPLUGINS_VOLUMES_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render one or more voumetric data sets.
 * @author Geoffrey Hutchison and Perminder
 */
class Volumes : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Volumes(QObject* parent = nullptr);
  ~Volumes() override;

  void process(const QtGui::Molecule& mol, Rendering::GroupNode& node) override;

  QString name() const override { return tr("Volumes"); }

  QString description() const override { return tr("Render volumetric clouds."); }

  QWidget* setupWidget() override;

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

private slots:
  void setColor1(const QColor& color);
  void setColor2(const QColor& color);

private:
  std::string m_name = "Volumes";

  QWidget* m_setupWidget;
  unsigned char m_opacity;
  Vector3ub m_color1;
  Vector3ub m_color2;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MESHES_H