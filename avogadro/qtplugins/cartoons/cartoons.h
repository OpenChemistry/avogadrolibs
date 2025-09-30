/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CARTOONS_H
#define AVOGADRO_QTPLUGINS_CARTOONS_H

#include <avogadro/qtgui/sceneplugin.h>
#include <list>
#include <map>

namespace Avogadro::QtPlugins {

struct BackboneResidue;
using AtomsPairList = std::list<BackboneResidue>;

class Cartoons : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Cartoons(QObject* parent = 0);
  ~Cartoons() override = default;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override
  {
    return tr("Cartoons", "protein ribbon / cartoon rendering");
  }

  QString description() const override
  {
    return tr("Display of biomolecule ribbons / cartoons.");
  }

  QWidget* setupWidget() override;
  bool hasSetupWidget() const override { return true; }

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::True;
  }

public slots:
  // straights line between alpha carbons
  void showBackbone(bool show);
  // A flat line is displayed along the main backbone trace.
  void showTrace(bool show);
  // same as trace but with a circle volume (like a pipeline)
  void showTube(bool show);
  // same as trace but a flat plane
  void showRibbon(bool show);
  // the classic
  void showSimpleCartoon(bool show);
  // the classic + sheets and helix
  void showCartoon(bool show);
  // same as tube but instead of creating a b-spline (cuadratic bezier, segments
  // of 3) we crea a big N-bezier line
  void showRope(bool show);

private:
  Rendering::GroupNode* m_group;
  std::string m_name = "Cartoons";

  std::map<size_t, AtomsPairList> getBackboneByResidues(
    const QtGui::Molecule& molecule, size_t layer);
  std::map<size_t, AtomsPairList> getBackboneManually(
    const QtGui::Molecule& molecule, size_t layer);
};
} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_CARTOONS_H
