/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CRYSTALSCENE_H
#define AVOGADRO_QTPLUGINS_CRYSTALSCENE_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/sceneplugin.h>

#include <QtGui/QColor>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render the unit cell boundaries.
 */
class CrystalScene : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit CrystalScene(QObject* parent = nullptr);
  ~CrystalScene() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Crystal Lattice"); }

  QString description() const override
  {
    return tr("Render the unit cell boundaries.");
  }

  QWidget* setupWidget() override;

private slots:
  void setColor(const QColor& color);
  void setLineWidth(double width);
  void setMultiColor(bool multiColor);

private:
  std::string m_name = "Crystal Lattice";

  QWidget* m_setupWidget;
  float m_lineWidth;
  Vector3ub m_color;
  bool m_multiColor;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CRYSTALSCENE_H
