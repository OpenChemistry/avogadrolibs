/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_PACKAGEMANAGER_H
#define AVOGADRO_QTGUI_PACKAGEMANAGER_H

#include "avogadroqtguiexport.h"

#include <QtCore/QJsonObject>
#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>

namespace Avogadro {
namespace QtGui {

/**
 * @brief Singleton that manages pyproject.toml-based plugin packages.
 *
 * Packages are registered once (at download time or manually) and cached in
 * QSettings. On startup, loadRegisteredPackages() replays the cached
 * registrations as featureRegistered() signals so that consumer plugins
 * (Command, ScriptCharges, Forcefield, etc.) can create their actions and
 * models without re-parsing TOML or calling scripts.
 *
 * During a session, registerPackage() can be called at any time (e.g. after
 * the plugin downloader installs a new package) and signals fire immediately.
 */
class AVOGADROQTGUI_EXPORT PackageManager : public QObject
{
  Q_OBJECT
public:
  static PackageManager* instance();

  struct PackageInfo
  {
    QString name;        ///< from [project.name]
    QString version;     ///< from [project.version]
    QString directory;   ///< absolute path to the package directory
    QString command;     ///< entry point from [project.scripts]
    QString description; ///< from [project.description]
  };

  /** Known feature-type strings (TOML table names under [tool.avogadro]). */
  static QStringList featureTypes();

  /**
   * Build a stable key for one package-provided feature.
   * Consumers can use this as a map key to track registrations and removals.
   * Components must not be empty.
   */
  static QString packageFeatureKey(const QString& packageDir,
                                   const QString& command,
                                   const QString& identifier);

  /**
   * Load package user-options from JSON or TOML (selected by extension).
   * Returns an empty object on error.
   */
  static QJsonObject loadOptionsFromFile(const QString& userOptionsPath);

  /**
   * Merge package user-options into @p opts. Keys from the file override
   * existing values in @p opts.
   */
  static void mergeOptionsFromFile(QJsonObject& opts,
                                   const QString& userOptionsPath);

  // --- Installed environments ---

  /**
   * Absolute path to @p command as installed in the pixi environment of
   * @p packageDir (@c .pixi/envs/default), or an empty string if the package
   * has no pixi environment with that command in it.
   *
   * Package commands are run with @c "pixi run --as-is", which is shorthand
   * for @c --no-install @c --frozen and so will never create a missing
   * environment. Callers must therefore check this rather than merely
   * checking that the pixi executable exists.
   */
  static QString pixiScriptPath(const QString& packageDir,
                                const QString& command);

  /**
   * Absolute path to @p command as installed in the virtual environment of
   * @p packageDir (@c .venv), or an empty string if there is none. This is
   * the fallback for packages that were pip-installed because pixi was not
   * available when they were set up.
   */
  static QString venvScriptPath(const QString& packageDir,
                                const QString& command);

  /** How to launch a package command. */
  struct CommandLine
  {
    QString program;        ///< empty if no environment can run the command
    QStringList prefixArgs; ///< arguments preceding the command's own
  };

  /**
   * Resolve how to run @p command from @p packageDir, so that every caller
   * applies the same backend policy.
   *
   * Prefers the package's pixi environment and falls back to the console
   * script pip installed into @c .venv. Having the pixi executable is not on
   * its own enough to choose pixi, because @c "pixi run --as-is" is shorthand
   * for @c --no-install @c --frozen and will not create a missing
   * environment: a package installed before pixi was available has to keep
   * running from @c .venv until it is installed again.
   *
   * @return a CommandLine whose @c program is empty when neither environment
   *         provides @p command.
   */
  static CommandLine resolveCommandLine(const QString& packageDir,
                                        const QString& command);

  /**
   * Run the package script with @c --user-options and parse the JSON output.
   * Uses pixi (preferred) or the venv-installed script as fallback.
   * Returns an empty object on error.
   */
  static QJsonObject loadOptionsFromScript(const QString& packageDir,
                                           const QString& command,
                                           const QString& identifier);

  /**
   * Whether a feature's @c user-options value asks for options to be built
   * fresh by the script rather than read from a file. Such options are
   * generated per invocation, so callers must not cache the resulting GUI.
   */
  static bool isDynamicUserOptions(const QString& userOptionsValue);

  /**
   * Resolve user-options for a package feature. If @p userOptionsValue is
   * dynamic (see isDynamicUserOptions()), runs the script with
   * @c --user-options via loadOptionsFromScript(). Otherwise treats it as a
   * relative file path and loads via loadOptionsFromFile().
   * Returns an empty object on error or if @p userOptionsValue is empty.
   */
  static QJsonObject resolveUserOptions(const QString& userOptionsValue,
                                        const QString& packageDir,
                                        const QString& command,
                                        const QString& identifier);

  // --- Installation ---

  /**
   * Asynchronously run pixi (preferred) or pip install in each directory,
   * then call registerPackage() for each.
   * Emits packagesInstalled() when the background thread finishes.
   * Safe to call from the main thread.
   */
  void installPackages(const QStringList& packageDirs);

  /**
   * Delete the @c .venv directory of @p packageDir once its pixi environment
   * can run @p command, so that a package migrated to pixi does not keep a
   * stale pip-installed tree around. Nothing will ever update that tree, and
   * it would silently serve outdated code if the pixi environment were later
   * removed.
   *
   * Does nothing if there is no @c .venv, or if the pixi environment does not
   * provide @p command — a half-finished install must never leave the package
   * with no way to run at all.
   *
   * @return true if a @c .venv directory was removed.
   */
  static bool removeSupersededVenv(const QString& packageDir,
                                   const QString& command);

  // --- Registration ---

  /**
   * Parse pyproject.toml in @p packageDir, cache the result in QSettings,
   * and emit featureRegistered() for every feature found.
   * @return true on success.
   */
  bool registerPackage(const QString& packageDir);

  /**
   * Remove a package and all its feature registrations from the cache.
   * Emits featureRemoved() for each feature that was registered.
   */
  bool unregisterPackage(const QString& packageName);

  // --- Startup ---

  /**
   * Load all previously-registered packages from QSettings and emit
   * featureRegistered() for each cached feature.
   * Call this once after all consumer plugins have connected.
   */
  void loadRegisteredPackages(const QString& typeFilter = QString());

  // --- Directory scanning ---

  /**
   * Scan @p directoryPath for subdirectories that contain a pyproject.toml.
   * Each discovered package is compared against the cached hash of its
   * pyproject.toml; new or modified packages are returned as a list of
   * absolute directory paths. The caller is responsible for calling
   * registerPackage() on any directories it wants to install.
   * @return list of package directories that are new or have been modified.
   */
  QStringList scanDirectory(const QString& directoryPath);

  // --- Queries ---

  QStringList registeredPackages() const;
  PackageInfo packageInfo(const QString& packageName) const;

  /**
   * Return the distinct feature-type strings (e.g. "menu-commands",
   * "file-formats") for a registered package, read from the QSettings cache.
   */
  QStringList packageFeatureTypes(const QString& packageName) const;

signals:
  /**
   * Emitted after installPackages() finishes installing and registering
   * all requested packages.
   */
  void packagesInstalled();

  /**
   * Emitted for each feature found in a package.
   *
   * @param type       One of the featureTypes() strings, e.g.
   *                   "menu-commands", "electrostatic-models", etc.
   * @param packageDir Absolute path to the package directory.
   * @param command    Entry-point name from [project.scripts].
   * @param identifier The feature's unique identifier.
   * @param metadata   Remaining TOML sub-table fields as a QVariantMap.
   */
  void featureRegistered(const QString& type, const QString& packageDir,
                         const QString& command, const QString& identifier,
                         const QVariantMap& metadata);

  /**
   * Emitted when a feature is removed (so consumers can clean up).
   *
   * @param type       One of the featureTypes() strings.
   * @param packageDir Absolute path to the package directory.
   * @param command    Entry-point name from [project.scripts].
   * @param identifier The feature's unique identifier.
   */
  void featureRemoved(const QString& type, const QString& packageDir,
                      const QString& command, const QString& identifier);

private:
  explicit PackageManager(QObject* parent = nullptr);

  /** Internal representation of a single feature entry. */
  struct FeatureEntry
  {
    QString type;
    QString identifier;
    QVariantMap metadata;
  };

  /**
   * Parse pyproject.toml at @p packageDir/pyproject.toml.
   * Populates @p info and @p features on success.
   */
  bool parsePackage(const QString& packageDir, PackageInfo& info,
                    QList<FeatureEntry>& features);

  /** Emit featureRegistered() for every entry in @p features. */
  void emitFeatures(const PackageInfo& info,
                    const QList<FeatureEntry>& features);

  // JSON serialisation for QSettings cache
  static QJsonObject featureEntryToJson(const FeatureEntry& entry);
  static FeatureEntry featureEntryFromJson(const QJsonObject& obj);

  // QSettings helpers
  void saveToCache(const PackageInfo& info,
                   const QList<FeatureEntry>& features);
  void removeFromCache(const QString& packageName);
  bool loadFromCache(const QString& packageName, PackageInfo& info,
                     QList<FeatureEntry>& features);
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_PACKAGEMANAGER_H
