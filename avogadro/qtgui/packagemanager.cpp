/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "packagemanager.h"

#include <QtCore/QDateTime>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QSettings>
#include <QtCore/QTimeZone>

// tomlplusplus — single header in thirdparty/
#include <toml.hpp>

namespace Avogadro::QtGui {

PackageManager::PackageManager(QObject* parent) : QObject(parent) {}

PackageManager* PackageManager::instance()
{
  static PackageManager instance;
  return &instance;
}

QStringList PackageManager::featureTypes()
{
  return { QStringLiteral("menu-commands"),
           QStringLiteral("electrostatic-models"),
           QStringLiteral("energy-models"), QStringLiteral("file-formats"),
           QStringLiteral("input-generators") };
}

// ---------------------------------------------------------------------------
// TOML → QVariant helpers
// ---------------------------------------------------------------------------

static QVariant tomlNodeToVariant(const toml::node& node);

static QVariantMap tomlTableToVariantMap(const toml::table& tbl)
{
  QVariantMap map;
  for (auto&& [key, val] : tbl) {
    map.insert(QString::fromStdString(std::string(key.str())),
               tomlNodeToVariant(val));
  }
  return map;
}

static QVariantList tomlArrayToVariantList(const toml::array& arr)
{
  QVariantList list;
  for (auto&& val : arr) {
    list.append(tomlNodeToVariant(val));
  }
  return list;
}

static QVariant tomlNodeToVariant(const toml::node& node)
{
  if (node.is_string())
    return QString::fromStdString(std::string(node.as_string()->get()));
  if (node.is_integer())
    return static_cast<qlonglong>(node.as_integer()->get());
  if (node.is_floating_point())
    return node.as_floating_point()->get();
  if (node.is_boolean())
    return node.as_boolean()->get();
  if (node.is_table())
    return tomlTableToVariantMap(*node.as_table());
  if (node.is_array())
    return tomlArrayToVariantList(*node.as_array());
  if (node.is_date()) {
    auto d = node.as_date()->get();
    return QDate(d.year, d.month, d.day);
  }
  if (node.is_time()) {
    auto t = node.as_time()->get();
    return QTime(t.hour, t.minute, t.second, t.nanosecond / 1000000);
  }
  if (node.is_date_time()) {
    auto dt = node.as_date_time()->get();
    QDate date(dt.date.year, dt.date.month, dt.date.day);
    QTime time(dt.time.hour, dt.time.minute, dt.time.second,
               dt.time.nanosecond / 1000000);
    if (dt.offset)
      return QDateTime(date, time, QTimeZone(dt.offset->minutes * 60));
    return QDateTime(date, time);
  }
  return {};
}

// ---------------------------------------------------------------------------
// QSettings serialisation helpers (features stored as JSON)
// ---------------------------------------------------------------------------

QJsonObject PackageManager::featureEntryToJson(const FeatureEntry& entry)
{
  QJsonObject obj;
  obj[QStringLiteral("type")] = entry.type;
  obj[QStringLiteral("identifier")] = entry.identifier;
  obj[QStringLiteral("metadata")] = QJsonObject::fromVariantMap(entry.metadata);
  return obj;
}

PackageManager::FeatureEntry PackageManager::featureEntryFromJson(
  const QJsonObject& obj)
{
  FeatureEntry entry;
  entry.type = obj[QStringLiteral("type")].toString();
  entry.identifier = obj[QStringLiteral("identifier")].toString();
  entry.metadata = obj[QStringLiteral("metadata")].toObject().toVariantMap();
  return entry;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

bool PackageManager::registerPackage(const QString& packageDir)
{
  PackageInfo info;
  QList<FeatureEntry> features;

  if (!parsePackage(packageDir, info, features))
    return false;

  // If already registered, remove old features first
  if (registeredPackages().contains(info.name))
    unregisterPackage(info.name);

  saveToCache(info, features);
  emitFeatures(info, features);
  return true;
}

bool PackageManager::unregisterPackage(const QString& packageName)
{
  PackageInfo info;
  QList<FeatureEntry> features;

  if (!loadFromCache(packageName, info, features))
    return false;

  // Notify consumers so they can clean up
  for (const auto& f : features)
    emit featureRemoved(f.type, f.identifier);

  removeFromCache(packageName);
  return true;
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

void PackageManager::loadRegisteredPackages()
{
  QSettings settings;
  settings.beginGroup(QStringLiteral("packages"));
  const QStringList names = settings.childGroups();
  settings.endGroup();

  for (const QString& name : names) {
    PackageInfo info;
    QList<FeatureEntry> features;
    if (loadFromCache(name, info, features))
      emitFeatures(info, features);
  }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

QStringList PackageManager::registeredPackages() const
{
  QSettings settings;
  settings.beginGroup(QStringLiteral("packages"));
  QStringList names = settings.childGroups();
  settings.endGroup();
  return names;
}

PackageManager::PackageInfo PackageManager::packageInfo(
  const QString& packageName) const
{
  PackageInfo info;
  QSettings settings;
  QString prefix = QStringLiteral("packages/") + packageName + '/';
  info.name = packageName;
  info.version = settings.value(prefix + "version").toString();
  info.directory = settings.value(prefix + "directory").toString();
  info.command = settings.value(prefix + "command").toString();
  // not really crucial
  info.description = settings.value(prefix + "description").toString();
  return info;
}

// ---------------------------------------------------------------------------
// TOML parsing
// ---------------------------------------------------------------------------

bool PackageManager::parsePackage(const QString& packageDir, PackageInfo& info,
                                  QList<FeatureEntry>& features)
{
  QString tomlPath = packageDir + QStringLiteral("/pyproject.toml");
  QFileInfo fi(tomlPath);
  if (!fi.exists() || !fi.isReadable()) {
    qWarning() << "PackageManager: pyproject.toml not found in" << packageDir;
    return false;
  }

  toml::table root;
  try {
    QFile tomlFile(tomlPath);
    if (!tomlFile.open(QIODevice::ReadOnly | QIODevice::Text))
      return false;
    QByteArray content = tomlFile.readAll();
    root = toml::parse(std::string_view(content.constData(), content.size()));
  } catch (const toml::parse_error& err) {
    qWarning() << "PackageManager: TOML parse error in" << tomlPath << ":"
               << err.what();
    return false;
  }

  // --- [project] ---
  auto* project = root["project"].as_table();
  if (!project) {
    qWarning() << "PackageManager: missing [project] table in" << tomlPath;
    return false;
  }

  info.directory = QDir(packageDir).absolutePath();

  if (auto* v = (*project)["name"].as_string())
    info.name = QString::fromStdString(std::string(v->get()));
  if (auto* v = (*project)["version"].as_string())
    info.version = QString::fromStdString(std::string(v->get()));
  // not really crucial
  if (auto* v = (*project)["description"].as_string())
    info.description = QString::fromStdString(std::string(v->get()));

  if (info.name.isEmpty()) {
    qWarning() << "PackageManager: [project.name] is required in" << tomlPath;
    return false;
  }

  // --- [project.scripts] → find the avogadro- entry point ---
  if (auto* scripts = (*project)["scripts"].as_table()) {
    for (auto&& [key, val] : *scripts) {
      QString k = QString::fromStdString(std::string(key.str()));
      if (k.startsWith(QStringLiteral("avogadro-"))) {
        if (info.command.isEmpty())
          info.command = k;
        // in principle we should break, but check for multiple entries
        // and warn about them
        else
          qWarning() << "PackageManager: multiple avogadro-* entry points in"
                     << tomlPath;
      }
    }
  }
  if (info.command.isEmpty()) {
    qWarning() << "PackageManager: no avogadro-* entry in [project.scripts]"
               << "in" << tomlPath;
    return false;
  }

  // --- [tool.avogadro.*] feature arrays ---
  auto* toolAvogadro = root["tool"]["avogadro"].as_table();
  if (!toolAvogadro) {
    qWarning() << "PackageManager: missing [tool.avogadro] in" << tomlPath;
    return false;
  }

  const QStringList types = featureTypes();
  for (const QString& type : types) {
    auto* arr = (*toolAvogadro)[type.toStdString()].as_array();
    if (!arr)
      continue;

    for (auto&& element : *arr) {
      auto* table = element.as_table();
      if (!table)
        continue;

      FeatureEntry entry;
      entry.type = type;

      // Extract identifier (required)
      if (auto* id = (*table)["identifier"].as_string()) {
        entry.identifier = QString::fromStdString(std::string(id->get()));
      } else {
        qWarning() << "PackageManager: feature in" << type
                   << "missing identifier, skipping";
        continue;
      }

      // Convert the entire table to metadata (identifier is kept for
      // convenience)
      entry.metadata = tomlTableToVariantMap(*table);
      features.append(entry);
    }
  }

  return true;
}

// ---------------------------------------------------------------------------
// Signal emission
// ---------------------------------------------------------------------------

void PackageManager::emitFeatures(const PackageInfo& info,
                                  const QList<FeatureEntry>& features)
{
  for (const auto& f : features) {
    emit featureRegistered(f.type, info.directory, info.command, f.identifier,
                           f.metadata);
  }
}

// ---------------------------------------------------------------------------
// QSettings cache
// ---------------------------------------------------------------------------

void PackageManager::saveToCache(const PackageInfo& info,
                                 const QList<FeatureEntry>& features)
{
  QSettings settings;
  QString prefix = QStringLiteral("packages/") + info.name + '/';

  settings.setValue(prefix + "directory", info.directory);
  settings.setValue(prefix + "command", info.command);
  settings.setValue(prefix + "version", info.version);
  // not really crucial
  settings.setValue(prefix + "description", info.description);

  // Serialize features as a JSON array string
  QJsonArray arr;
  for (const auto& f : features)
    arr.append(featureEntryToJson(f));

  settings.setValue(prefix + "features",
                    QJsonDocument(arr).toJson(QJsonDocument::Compact));
}

void PackageManager::removeFromCache(const QString& packageName)
{
  QSettings settings;
  settings.beginGroup(QStringLiteral("packages"));
  settings.remove(packageName);
  settings.endGroup();
}

bool PackageManager::loadFromCache(const QString& packageName,
                                   PackageInfo& info,
                                   QList<FeatureEntry>& features)
{
  QSettings settings;
  QString prefix = QStringLiteral("packages/") + packageName + '/';

  info.name = packageName;
  info.directory = settings.value(prefix + "directory").toString();
  info.command = settings.value(prefix + "command").toString();
  info.version = settings.value(prefix + "version").toString();
  info.description = settings.value(prefix + "description").toString();

  if (info.directory.isEmpty() || info.command.isEmpty())
    return false;

  QByteArray json = settings.value(prefix + "features").toByteArray();
  QJsonDocument doc = QJsonDocument::fromJson(json);
  if (!doc.isArray())
    return false;

  const QJsonArray arr = doc.array();
  for (const auto& val : arr) {
    if (val.isObject())
      features.append(featureEntryFromJson(val.toObject()));
  }

  return true;
}

} // namespace Avogadro::QtGui
