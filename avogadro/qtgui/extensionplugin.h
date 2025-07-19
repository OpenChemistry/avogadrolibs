/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_EXTENSIONPLUGIN_H
#define AVOGADRO_QTGUI_EXTENSIONPLUGIN_H

#include "avogadroqtguiexport.h"

#include <avogadro/qtplugins/pluginfactory.h>

#include <QtCore/QObject>

class QAction;

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace Rendering {
class Camera;
class Scene;
} // namespace Rendering

namespace Io {
class FileFormat;
}

namespace QtGui {

/**
 * @class ExtensionPlugin extensionplugin.h <avogadro/qtgui/extensionplugin.h>
 * @brief The base class for extension plugin factories in Avogadro.
 * @author Marcus D. Hanwell
 */
class AVOGADROQTGUI_EXPORT ExtensionPlugin : public QObject
{
  Q_OBJECT

public:
  explicit ExtensionPlugin(QObject* parent = nullptr);
  ~ExtensionPlugin() override;

  /**
   * The name of the extension plugin, will be displayed in the user interface.
   */
  virtual QString name() const = 0;

  /**
   * A description of the extension plugin, may be displayed in the user
   * interface.
   */
  virtual QString description() const = 0;

  /**
   * @return The QActions for this extension (should be at least one).
   */
  virtual QList<QAction*> actions() const = 0;

  /**
   * @return The menu path of the supplied action. This can be empty if the
   * action was not recognized, or contain two or more strings (top level, plus
   * name, e.g. File, &Open).
   */
  virtual QStringList menuPath(QAction* action = nullptr) const = 0;

  /**
   * @return A list of file format readers/writers.
   *
   * The caller takes ownership of the objects in the returned list.
   */
  virtual QList<Io::FileFormat*> fileFormats() const;

  /**
   * If the extension plugin has script commands, this method
   * should be implemented to emit the registerCommand signals.
   */
  virtual void registerCommands() {}

public slots:
  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(QtGui::Molecule* mol) = 0;

  /**
   * Call this slot when the moleculeReady signal indicated that a molecule is
   * ready to be read. The @p molecule will have the data read into it. The slot
   * will @return true if a molecule was successfully read in.
   */
  virtual bool readMolecule(QtGui::Molecule& mol);

  /**
   * Called when the current scene changes.
   */
  virtual void setScene(Rendering::Scene* scene);

  /**
   * Called when the active camera for the view changes.
   */
  virtual void setCamera(Rendering::Camera* camera);

  /**
   * Called when the active widget changes. This must be used carefully, and
   * should check that the widget has been cast if used.
   */
  virtual void setActiveWidget(QWidget* widget);

  /**
   * Called by the app to handle a command registered by the extension.
   * (e.g., "renderMovie" or "generateSurface", etc.)
   *
   * The app will turn the command into a string and pass it to the extension.
   * and any options will go from a JSON dictionary to a QVariantMap.
   *
   * @return true if the command was handled, false otherwise.
   */
  virtual bool handleCommand(const QString& command,
                             const QVariantMap& options);

signals:
  /**
   * Signal that the extension has a new molecule that is ready to be loaded.
   * The application must call readMolecule in order to actually read the
   * molecule(s).
   */
  void moleculeReady(int numberOfMolecules);

  /**
   * Signal that the extension has file formats that are ready to be registered.
   * If emitted the application should call fileFormats to get the formats the
   * extension is registering.
   */
  void fileFormatsReady();

  /**
   * Signal to request a particular tool is set as the active tool. This is
   * useful when loading a structure outside of the normal file API and setting
   * "Navigator" to active instead of "Editor" (the default).
   */
  void requestActiveTool(QString toolName);

  /**
   * Request a specific display type (or types) are made active.
   * This can be useful when loading a specific type of data that
   * would be most readily viewed with a specialized view.
   */
  void requestActiveDisplayTypes(QStringList displayTypes);

  /**
   * Register a new command with the application. The command will be available
   * through scripting (e.g., "renderMovie" or "generateSurface", etc.)
   *
   * @param command The name of the command to register.
   * @param description A description of the command.
   *
   * @sa handleCommand
   */
  void registerCommand(QString command, QString description);
};

/**
 * @class ExtensionPluginFactory extensionplugin.h
 * <avogadro/qtgui/extensionplugin.h>
 * @brief The base class for extension plugin factories in Avogadro.
 * @author Marcus D. Hanwell
 */
class AVOGADROQTGUI_EXPORT ExtensionPluginFactory
  : public QtPlugins::PluginFactory<ExtensionPlugin>
{
public:
  ~ExtensionPluginFactory() override;
};

} // namespace QtGui
} // namespace Avogadro

Q_DECLARE_INTERFACE(Avogadro::QtGui::ExtensionPluginFactory,
                    "org.openchemistry.avogadro.ExtensionPluginFactory")

#endif // AVOGADRO_QTGUI_EXTENSIONPLUGIN_H
