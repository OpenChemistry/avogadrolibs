/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_AUTOOPT_H
#define AVOGADRO_QTPLUGINS_AUTOOPT_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/primitive.h>

#include <QtCore/QPoint>
#include <QtCore/QTimer>
#include <QtWidgets/QAbstractButton>

namespace Avogadro {

namespace Calc {
class EnergyCalculator;
}

namespace QtPlugins {

class AutoOptWidget;

/**
 * @class AutoOpt autoopt.h
 * <avogadro/qtplugins/autoopt/autoopt.h>
 * @brief Optimize the geometry of a molecule while manipulating it.
 * @author Geoff Hutchison
 * Based on the Manipulator class by @author Allison Vacanti
 */
class AutoOpt : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit AutoOpt(QObject* parent_ = nullptr);
  ~AutoOpt() override;

  QString name() const override { return tr("Auto Optimize tool"); }
  QString description() const override
  {
    return tr("Interactive optimization of molecular geometry");
  }
  unsigned char priority() const override { return 50; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;

  void setIcon(bool darkTheme = false) override;

  void setMolecule(QtGui::Molecule* mol) override;

  void setEditMolecule(QtGui::RWMolecule* mol) override { m_molecule = mol; }

  void setGLRenderer(Rendering::GLRenderer* renderer) override
  {
    m_renderer = renderer;
  }

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseMoveEvent(QMouseEvent* e) override;
  QUndoCommand* keyPressEvent(QKeyEvent* e) override;

  void draw(Rendering::GroupNode& node) override;

public slots:
  void startStop();
  void start();
  void stop();
  void methodChanged(const QString& method);
  void moleculeChanged(unsigned int changes);

  void optimizeStep();

private:
  /**
   * Update the currently pressed buttons, accounting for modifier keys.
   * \todo Account for modifier keys.
   */
  void updatePressedButtons(QMouseEvent*, bool release);

  Real calculateEnergy();

  void resetObject() { m_object = Rendering::Identifier(); }
  void translate(Vector3 delta, bool moveSelected = true);
  void rotate(Vector3 delta, Vector3 centroid, bool moveSelected = true);
  void axisRotate(Vector3 delta, Vector3 centroid, bool moveSelected = true);
  void tilt(Vector3 delta, Vector3 centroid);

  QAction* m_activateAction;
  QtGui::RWMolecule* m_molecule;
  Rendering::GLRenderer* m_renderer;
  Rendering::Identifier m_object;
  QPoint m_lastMousePosition;
  Vector3f m_lastMouse3D;
  Qt::MouseButtons m_pressedButtons;

  Calc::EnergyCalculator* m_method = nullptr;
  Real m_energy;
  Real m_deltaE;

  mutable QWidget* m_toolWidget;

  bool m_running = false;
  qint64 m_oneStepTime = 0;
  QTimer m_timer;

  enum ToolAction
  {
    Nothing = 0,
    Rotation,
    Translation,
    ZoomTilt,
    Zoom
  };
  ToolAction m_currentAction;

  std::string m_currentMethod;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_AUTOOPT_H
