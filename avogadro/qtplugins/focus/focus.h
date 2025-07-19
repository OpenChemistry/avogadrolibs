/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_FOCUS_H
#define AVOGADRO_QTPLUGINS_FOCUS_H

#include <Eigen/Geometry>
#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/rendering/scene.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The Focus class is an extension to center the camera in the best
 * fit panel or the default camera position
 */
class Focus : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Focus(QObject* parent_ = nullptr);
  ~Focus() override;

  QString name() const override { return tr("Focus"); }
  QString description() const override
  {
    return tr("Focus the view on specific features.");
  }
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  void setCamera(Rendering::Camera* camera) override;
  void setScene(Rendering::Scene* scene) override;
  void setActiveWidget(QWidget* widget) override;

signals:
  void updateRequested();

private slots:
  void focusSelection();
  void unfocus();

private:
  QtGui::Molecule* m_molecule;
  Rendering::Camera* m_camera;
  Rendering::Scene* m_scene;
  QWidget* m_glWidget;
  QAction* m_focusSelectionAction;
  QAction* m_unfocusAction;

  void newFocus(Eigen::Vector3f point, float distance);
};

} // namespace QtPlugins
} // namespace Avogadro

#endif
