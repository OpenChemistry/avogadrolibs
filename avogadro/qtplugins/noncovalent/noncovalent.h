/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_NONCOVALENT_H
#define AVOGADRO_QTPLUGINS_NONCOVALENT_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Predict some non-covalent interactions, like hydrogen bonds.
 * @author Aritz Erkiaga
 */
class NonCovalent : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit NonCovalent(QObject* parent = nullptr);
  ~NonCovalent() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Non-Covalent"); }

  QString description() const override
  {
    return tr("Render a few non-covalent interactions.");
  }
  
  QWidget* setupWidget() override;

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

public slots:
  void setAngleTolerance(float angleTolerance, Index index);
  void setMaximumDistance(float maximumDistance, Index index);
  void setLineWidth(float width, Index index);

private:
  const std::string m_name = "Non-Covalent";
  
  const std::array<QString, 3> INTERACTION_NAMES = {
	tr("Hydrogen"), tr("Halogen"), tr("Chalcogen")
  };
  
  std::array<double, 3> m_angleTolerancesDegrees;
  std::array<double, 3> m_maximumDistances;
  std::array<Vector3ub, 3> m_lineColors;
  std::array<float, 3> m_lineWidths;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_NONCOVALENT_H
