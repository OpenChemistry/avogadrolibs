/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_POVRAY_H
#define AVOGADRO_QTPLUGINS_POVRAY_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The POVRay class performs POVRay operations on demand.
 */
class POVRay : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit POVRay(QObject* p = nullptr);
  ~POVRay() override;

  QString name() const override { return tr("POVRay"); }

  QString description() const override
  {
    return tr("Render the scene using POV-Ray.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction* action) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  void setScene(Rendering::Scene* scene) override;
  void setCamera(Rendering::Camera* camera) override;

private slots:
  void render();

private:
  QtGui::Molecule* m_molecule;
  Rendering::Scene* m_scene;
  Rendering::Camera* m_camera;

  QAction* m_action;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_POVRAY_H
