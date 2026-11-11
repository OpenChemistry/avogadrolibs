/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_BALLANDSTICK_H
#define AVOGADRO_QTPLUGINS_BALLANDSTICK_H

#include <avogadro/core/avogadrocore.h>
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

  /**
   * Move the existing spheres and cylinders to the new atom positions.
   * Returns false (so the caller rebuilds) unless @p node is the node of the
   * last process() call, still holding what it built, for the same molecule
   * with the same numbers of atoms and bonds.
   */
  bool updateCoordinates(const QtGui::Molecule& molecule,
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
  // What the last process() built, checked by updateCoordinates().
  const QtGui::Molecule* m_molecule = nullptr;
  Index m_atomCount = 0;
  Index m_bondCount = 0;
  std::string m_name = "Ball and Stick";
  float m_atomScale = 0.3f;
  float m_bondRadius = 0.1f;
  float m_opacity = 1.0f;
};

} // end namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_BALLANDSTICK_H
