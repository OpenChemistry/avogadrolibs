/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_BALLANDSTICK_H
#define AVOGADRO_QTPLUGINS_BALLANDSTICK_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro::QtPlugins {

/**
 * @brief Render a molecule in the ball and stick style.
 * @author Allison Vacanti
 */
class BallAndStick : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit BallAndStick(QObject* parent = nullptr);
  ~BallAndStick() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Ball and Stick"); }

  QString description() const override
  {
    return tr("Render atoms as spheres and bonds as cylinders.");
  }

  QWidget* setupWidget() override;
  bool hasSetupWidget() const override { return true; }

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::True;
  }

public slots:
  void atomRadiusChanged(int value);
  void bondRadiusChanged(int value);
  void multiBonds(bool show);
  void showHydrogens(bool show);
  void opacityChanged(int value);

private:
  Rendering::GroupNode* m_group;
  std::string m_name = "Ball and Stick";
  float m_atomScale = 0.3f;
  float m_bondRadius = 0.1f;
  float m_opacity = 1.0f;
};

} // end namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_BALLANDSTICK_H
