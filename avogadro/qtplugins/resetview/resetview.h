/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_RESETVIEW_H
#define AVOGADRO_QTPLUGINS_RESETVIEW_H

#include <Eigen/Geometry>
#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The ResetView class is an extension to center the camera in the best
 * fit panel or the default camera position
 */
class ResetView : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit ResetView(QObject* parent_ = nullptr);
  ~ResetView() override;

  QString name() const override { return tr("Reset view"); }
  QString description() const override
  {
    return tr("Manipulate the view camera.");
  }
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  void setCamera(Rendering::Camera* camera) override;
  void setActiveWidget(QWidget* widget) override;

signals:
  void updateRequested();

private slots:
  void centerView();
  void alignToAxes();

private:
  QtGui::Molecule* m_molecule;
  Rendering::Camera* m_camera;
  QAction* m_centerAction;
  QAction* m_viewToAxesAction;
  QWidget* m_glWidget;

  static const float DELTA_TIME;
  static const int TOTAL_FRAMES;

  bool defaultChecks();
  void animationCamera(const Eigen::Affine3f& goal, bool animate = true);
  void animationCameraDefault(bool animate = true);
};

} // namespace QtPlugins
} // namespace Avogadro

#endif
