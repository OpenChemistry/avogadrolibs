/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_FORCE_H
#define AVOGADRO_QTPLUGINS_FORCE_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/sceneplugin.h>

#include <QtGui/QColor>

namespace Avogadro::QtPlugins {

/**
 * @brief Render a molecule in the wireframe style.
 */
class Force : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Force(QObject* parent = nullptr);
  ~Force() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Force"); }

  QString description() const override
  {
    return tr(
      "Render the force field visualizations for the atoms of the molecule.");
  }

  QWidget* setupWidget() override;
  bool hasSetupWidget() const override { return true; }

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

private slots:
  void setColor(const QColor& color);
  void setLength(double scale);
  void setArrowWidth(double width);

private:
  std::string m_name = "Force";

  QWidget* m_setupWidget;
  float m_length;
  float m_arrowWidth;
  Vector3ub m_color;
};

} // namespace Avogadro::QtPlugins
// end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_FORCE_H
