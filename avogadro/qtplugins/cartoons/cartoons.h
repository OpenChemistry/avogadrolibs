/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CARTOONS_H
#define AVOGADRO_QTPLUGINS_CARTOONS_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

class Cartoons : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Cartoons(QObject* parent = 0);
  ~Cartoons() override;

  void process(const Core::Molecule& molecule,
               Rendering::GroupNode& node) override;

  void processEditable(const QtGui::RWMolecule& molecule,
                       Rendering::GroupNode& node) override;

  QString name() const override { return tr("Cartoons"); }

  QString description() const override
  {
    return tr("Simple display of Cartoons family.");
  }

  bool isEnabled() const override;

  void setEnabled(bool enable) override;

  QWidget* setupWidget() override;

private slots:
  // straights line between alpha carbons
  void showBackbone(bool show);
  // A flat line is displayed along the main backbone trace.
  void showTrace(bool show);
  // same as trace but with a circle volume (like a pipeline)
  void showTube(bool show);
  // same as trace but a flat plane
  void showRibbon(bool show);
  // the classic
  void showCartoon(bool show);
  // In this representation a tube follows the center points of local axes as
  // defined by helixorient.
  void showRope(bool show);

private:
  bool m_enabled;

  Rendering::GroupNode* m_group;

  QWidget* m_setupWidget;
  bool m_showBackbone;
  bool m_showTrace;
  bool m_showTube;
  bool m_showRibbon;
  bool m_showCartoon;
  bool m_showRope;
  typedef void (Cartoons::*JumpTable)(bool);
  JumpTable m_jumpTable[6];
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CARTOONS_H
