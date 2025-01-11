/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_MANIPULATOR_H
#define AVOGADRO_QTPLUGINS_MANIPULATOR_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/primitive.h>

#include <QtCore/QPoint>
#include <QtCore/Qt> // for Qt:: namespace
#include <QtWidgets/QAbstractButton>

namespace Avogadro {
namespace QtPlugins {

class ManipulateWidget;

/**
 * @class Manipulator manipulator.h
 * <avogadro/qtplugins/manipulator/manipulator.h>
 * @brief The Manipulator class manipulates a molecule's geometry.
 * @author Allison Vacanti
 */
class Manipulator : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit Manipulator(QObject* parent_ = nullptr);
  ~Manipulator() override;

  QString name() const override { return tr("Manipulate tool"); }
  QString description() const override { return tr("Manipulate tool"); }
  unsigned char priority() const override { return 30; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;

  void setIcon(bool darkTheme = false) override;

  void setMolecule(QtGui::Molecule* mol) override
  {
    if (mol)
      m_molecule = mol->undoMolecule();
  }

  void setEditMolecule(QtGui::RWMolecule* mol) override { m_molecule = mol; }

  void setGLRenderer(Rendering::GLRenderer* renderer) override
  {
    m_renderer = renderer;
  }

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseMoveEvent(QMouseEvent* e) override;
  QUndoCommand* keyPressEvent(QKeyEvent* e) override;

public slots:
  void buttonClicked(QAbstractButton* button);

private:
  /**
   * Update the currently pressed buttons, accounting for modifier keys.
   * \todo Account for modifier keys.
   */
  void updatePressedButtons(QMouseEvent*, bool release);

  void resetObject() { m_object = Rendering::Identifier(); }
  void translate(Vector3 delta, bool moveSelected = true);
  void rotate(Vector3 delta, Vector3 centroid, bool moveSelected = true);
  void tilt(Vector3 delta, Vector3 centroid);

  QAction* m_activateAction;
  QtGui::RWMolecule* m_molecule;
  Rendering::GLRenderer* m_renderer;
  Rendering::Identifier m_object;
  QPoint m_lastMousePosition;
  Vector3f m_lastMouse3D;
  Qt::MouseButtons m_pressedButtons;
  ManipulateWidget* m_toolWidget;

  enum ToolAction
  {
    Nothing = 0,
    Rotation,
    Translation,
    ZoomTilt,
    Zoom
  };
  ToolAction m_currentAction;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTOPENGL_MANIPULATOR_H
