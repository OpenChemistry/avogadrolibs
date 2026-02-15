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
  void loadRegisteredPackages();

  // --- Queries ---

  QStringList registeredPackages() const;
  PackageInfo packageInfo(const QString& packageName) const;

signals:
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
   */
  void featureRemoved(const QString& type, const QString& identifier);

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
