/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ATOMPAIRBONDS_H
#define AVOGADRO_QTPLUGINS_ATOMPAIRBONDS_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Predict atom-pair interactions, like hydrogen bonds.
 * @author Aritz Erkiaga
 */
class AtomPairBonds : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit AtomPairBonds(QObject* parent = nullptr);
  ~AtomPairBonds() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Atom-Pair Bonds"); }

  QString description() const override
  {
    return tr("Render atom-pair interactions.");
  }
  
  QWidget* setupWidget() override;

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

public:
  void setAngleTolerance(float angleTolerance);
  void setMaximumDistance(float maximumDistance);

private:
  std::string m_name = "Atom-Pair Bonds";
  
  double m_angleToleranceDegrees;
  double m_maximumDistance;
  std::array<Vector3ub, 1> m_lineColors;
  std::array<int, 1> m_lineWidths;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_ATOMPAIRBONDS_H
