/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_GLTF_H
#define AVOGADRO_QTPLUGINS_GLTF_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro::QtPlugins {

/**
 * @brief The GLTF class exports the scene as a glTF binary (.glb) file.
 */
class GLTF : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit GLTF(QObject* p = nullptr);
  ~GLTF() override;

  QString name() const override { return tr("GLTF"); }

  QString description() const override
  {
    return tr("Export the scene as a glTF binary (.glb) file.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction* action) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  void setScene(Rendering::Scene* scene) override;
  void setCamera(Rendering::Camera* camera) override;

private slots:
  void exportScene();

private:
  QtGui::Molecule* m_molecule;
  Rendering::Scene* m_scene;
  Rendering::Camera* m_camera;

  QAction* m_action;
};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_GLTF_H
