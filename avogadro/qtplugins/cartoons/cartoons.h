/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CARTOONS_H
#define AVOGADRO_QTPLUGINS_CARTOONS_H

#include <avogadro/qtgui/sceneplugin.h>
#include <list>
#include <map>

namespace Avogadro {
namespace QtPlugins {

struct BackboneResidue;
typedef std::list<BackboneResidue> AtomsPairList;

class Cartoons : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Cartoons(QObject* parent = 0);
  ~Cartoons() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr(m_name.c_str()); }

  QString description() const override
  {
    return tr("Simple display of Cartoons family.");
  }

  QWidget* setupWidget() override;

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

  static std::string getName() { return "Cartoons"; }

private:
  Rendering::GroupNode* m_group;
  std::string m_name = getName();

  std::map<size_t, AtomsPairList> getBackboneByResidues(
    const QtGui::Molecule& molecule, size_t layer);
  std::map<size_t, AtomsPairList> getBackboneManually(
    const QtGui::Molecule& molecule, size_t layer);
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CARTOONS_H
