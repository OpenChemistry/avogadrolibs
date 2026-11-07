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

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

  /** How the bonds between different elements are coloured. */
  enum class CylinderColoring
  {
    Split,   ///< two single-colour halves meeting at the midpoint
    Gradient ///< one tube with the colour blended along it
  };

  /**
   * Export the scene to @p fileName, without asking the user anything. The
   * file is written to a temporary file and moved into place only if the
   * export succeeds, so a failure never removes or truncates an existing file.
   * @return false on failure, with the reason (translated) in @p error.
   */
  bool exportTo(const QString& fileName, CylinderColoring coloring,
                QString* error);

  /** The remembered choice (QSettings "gltf/cylinderColoring"). */
  static CylinderColoring rememberedColoring();

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  void setScene(Rendering::Scene* scene) override;
  void setCamera(Rendering::Camera* camera) override;

private slots:
  void exportScene();

private:
  void registerExportCommand();

  QtGui::Molecule* m_molecule;
  Rendering::Scene* m_scene;
  Rendering::Camera* m_camera;

  QAction* m_action;
};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_GLTF_H
