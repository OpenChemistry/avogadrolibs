/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_COMMAND_H
#define AVOGADRO_QTPLUGINS_COMMAND_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMap>
#include <QtCore/QMultiHash>
#include <QtCore/QPointer>
#include <QtCore/QVariantMap>

#include <memory>

#include <avogadro/qtgui/molecule.h>

class QAction;
class QDialog;
class QTemporaryDir;

namespace Avogadro {
namespace Io {
class FileFormat;
}

namespace Rendering {
class Camera;
class Scene;
} // namespace Rendering

namespace QtGui {
class InterfaceScript;
class InterfaceWidget;
class TimedProgressDialog;
} // namespace QtGui

namespace QtPlugins {

/**
 * @brief The Command class implements the extension interface for
 * external (script) Commands
 * @author Geoffrey R. Hutchison
 */
class Command : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Command(QObject* parent = nullptr);
  ~Command() override;

  QString name() const override { return tr("Command scripts"); }

  QString description() const override
  {
    return tr("Run external script commands");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

  void setCamera(Rendering::Camera* camera) override;

  void setScene(Rendering::Scene* scene) override;

  /**
   * Write @p scene as a glTF binary (.glb) file for a script that asked for it
   * with `input-scene = "glb"`.
   *
   * The file stays in Avogadro's own frame and units (angstroms): it is not
   * centered or scaled, so its vertices line up with the CJSON coordinates and
   * with the camera matrices the script receives.
   * @return false (after a warning on the console) if either pointer is null
   * or the file could not be written completely.
   */
  static bool writeSceneGlb(Rendering::Scene* scene, Rendering::Camera* camera,
                            const QString& fileName);

public slots:
  /**
   * Scan for new scripts in the command directories.
   */
  void refreshScripts();

  void run();

  bool readMolecule(QtGui::Molecule& mol) override;

  void processFinished();

  /**
   * Handle a feature registered by PackageManager.
   */
  void registerFeature(const QString& type, const QString& packageDir,
                       const QString& command, const QString& identifier,
                       const QVariantMap& metadata);

  /**
   * Handle a feature removed by PackageManager.
   */
  void unregisterFeature(const QString& type, const QString& packageDir,
                         const QString& command, const QString& identifier);

private slots:
  /**
   * Show a progress report from the running script.
   * @param message Status text, or empty to leave the label alone.
   * @param value The current step, or -1 if the script did not supply one.
   * @param maximum The total number of steps, or -1 if not supplied.
   */
  void updateProgress(const QString& message, int value, int maximum);

  /**
   * Kill the running script after the user hits Cancel.
   */
  void cancelCommand();

  void menuActivated();
  void configurePython();
  void moleculeChanged(unsigned int change);

private:
  /**
   * Translate one menu level so it matches the built-in (translated) menus.
   */
  QString translateMenuLabel(const QString& label) const;

  /**
   * Translate every level of a menu path with translateMenuLabel().
   */
  QStringList translateMenuPath(const QStringList& path) const;

  /**
   * Tear down the progress dialog and running script after a command that
   * never started, reporting @p errors to the terminal and the user.
   */
  void commandFailed(const QStringList& errors);

  /**
   * Close and destroy the progress dialog, if there is one. Disconnects it
   * first: QProgressDialog::close() emits canceled(), which would otherwise
   * re-enter cancelCommand() and tear down state the caller still holds.
   */
  void closeProgressDialog();

  /**
   * Delete the temporary directory holding the scene file handed to the
   * running script, if any.
   */
  void releaseSceneFile();

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  // The active view's camera, owned by the renderer; null until a view exists.
  Rendering::Camera* m_camera = nullptr;
  // The active view's scene, owned by its renderer; null until a view exists.
  // Like m_camera it is only read on the GUI thread, during run().
  Rendering::Scene* m_scene = nullptr;
  // Holds scene.glb for the running script; removed when the run ends.
  std::unique_ptr<QTemporaryDir> m_sceneDir;
  // Launch-time molecule for the async script; QPointer detects deletion.
  QPointer<QtGui::Molecule> m_runningMolecule;
  // keyed on script file path or package feature key
  QMap<QString, QtGui::InterfaceWidget*> m_dialogs;
  QDialog* m_currentDialog;
  QtGui::InterfaceWidget* m_currentInterface;
  QtGui::InterfaceScript* m_currentScript;
  QtGui::TimedProgressDialog* m_progress;

  QMultiHash<QString, QAction*> m_packageActions;

  const Io::FileFormat* m_outputFormat;
  QString m_outputFileName;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_COMMAND_H
