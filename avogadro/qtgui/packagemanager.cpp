/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "packagemanager.h"
#include "tomlparse.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QStandardPaths>
#include <QtCore/QThread>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonParseError>
#include <QtCore/QSettings>

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

QString PackageManager::packageFeatureKey(const QString& packageDir,
                                          const QString& command,
                                          const QString& identifier)
{
  return packageDir + QLatin1Char('\n') + command + QLatin1Char('\n') +
         identifier;
}

QJsonObject PackageManager::loadOptionsFromFile(const QString& userOptionsPath)
{
  QFile optFile(userOptionsPath);
  if (!optFile.open(QIODevice::ReadOnly)) {
    qWarning() << "PackageManager: could not open user-options file:"
               << userOptionsPath;
    return {};
  }

  const QByteArray optContent = optFile.readAll();
  if (userOptionsPath.endsWith(QLatin1String(".toml"), Qt::CaseInsensitive)) {
    bool ok = false;
    const QJsonObject opts = parseTomlToJson(optContent, &ok);
    if (!ok) {
      qWarning() << "PackageManager: failed to parse TOML user-options file:"
                 << userOptionsPath;
      return {};
    }
    return opts;
  }

  QJsonParseError err;
  const QJsonDocument doc = QJsonDocument::fromJson(optContent, &err);
  if (err.error != QJsonParseError::NoError) {
    qWarning() << "PackageManager: failed to parse user-options JSON:"
               << userOptionsPath << err.errorString();
    return {};
  }
  // Accept either a bare array (new style, multiple tabs) or a wrapping
  // object (old style, with a "userOptions" key).  A bare array is normalised
  // to {"userOptions": <array>} so the rest of the code sees a uniform object.
  if (doc.isArray()) {
    QJsonObject wrapped;
    wrapped.insert(QStringLiteral("userOptions"), doc.array());
    return wrapped;
  }

  if (!doc.isObject()) {
    qWarning() << "PackageManager: user-options JSON root is not an object or"
                  " array:"
               << userOptionsPath;
    return {};
  }

  return doc.object();
}

void PackageManager::mergeOptionsFromFile(QJsonObject& opts,
                                          const QString& userOptionsPath)
{
  const QJsonObject fileOpts = loadOptionsFromFile(userOptionsPath);
  for (auto it = fileOpts.constBegin(); it != fileOpts.constEnd(); ++it)
    opts.insert(it.key(), it.value());
}

// Locate an installed console script inside a pixi or venv environment.
static QString findInstalledScript(const QString& packageDir,
                                   const QString& scriptName, bool isPixi)
{
#ifdef Q_OS_WIN
  const QString binDir =
    packageDir + (isPixi ? QStringLiteral("/.pixi/envs/default/Scripts")
                         : QStringLiteral("/.venv/Scripts"));
  const QStringList exeSuffixes = { QStringLiteral(".exe"), QString() };
#else
  const QString binDir =
    packageDir + (isPixi ? QStringLiteral("/.pixi/envs/default/bin")
                         : QStringLiteral("/.venv/bin"));
  const QStringList exeSuffixes = { QString() };
#endif

  for (const QString& suffix : exeSuffixes) {
    const QString candidate = binDir + QLatin1Char('/') + scriptName + suffix;
    if (QFileInfo(candidate).isExecutable())
      return candidate;
  }
  return {};
}

QJsonObject PackageManager::loadOptionsFromScript(const QString& packageDir,
                                                  const QString& command,
                                                  const QString& identifier)
{
  // Locate pixi or the venv-installed script.
  QString pixiExe = QStandardPaths::findExecutable(QStringLiteral("pixi"));
  QProcess proc;
  proc.setWorkingDirectory(packageDir);

  QStringList userOptsArgs;
  if (!identifier.isEmpty())
    userOptsArgs << identifier;
  userOptsArgs << QStringLiteral("--user-options");

  if (!pixiExe.isEmpty()) {
    QStringList pixiArgs = { QStringLiteral("run"), QStringLiteral("--as-is"),
                             command };
    pixiArgs << userOptsArgs;
    proc.start(pixiExe, pixiArgs);
  } else {
    // Try the venv-installed script directly.
    QString scriptExe = findInstalledScript(packageDir, command, false);
    if (scriptExe.isEmpty()) {
      qWarning() << "PackageManager: cannot find pixi or venv script for"
                 << command << "in" << packageDir;
      return {};
    }
    proc.start(scriptExe, userOptsArgs);
  }

  constexpr int timeoutMs = 30000; // 30 seconds
  if (!proc.waitForStarted(timeoutMs)) {
    qWarning() << "PackageManager: --user-options script could not start:"
               << proc.errorString();
    return {};
  }
  if (!proc.waitForFinished(timeoutMs)) {
    qWarning() << "PackageManager: --user-options script timed out for"
               << packageDir;
    proc.kill();
    return {};
  }
  if (proc.exitCode() != 0) {
    qWarning() << "PackageManager: --user-options script failed for"
               << packageDir << ":"
               << QString::fromUtf8(proc.readAllStandardError());
    return {};
  }

  const QByteArray output = proc.readAllStandardOutput();
  QJsonParseError err;
  const QJsonDocument doc = QJsonDocument::fromJson(output, &err);
  if (err.error != QJsonParseError::NoError) {
    qWarning() << "PackageManager: failed to parse --user-options JSON from"
               << command << ":" << err.errorString();
    return {};
  }

  if (doc.isArray()) {
    QJsonObject wrapped;
    wrapped.insert(QStringLiteral("userOptions"), doc.array());
    return wrapped;
  }

  if (!doc.isObject()) {
    qWarning() << "PackageManager: --user-options output is not an object or"
                  " array from"
               << command;
    return {};
  }

  return doc.object();
}

QJsonObject PackageManager::resolveUserOptions(const QString& userOptionsValue,
                                               const QString& packageDir,
                                               const QString& command,
                                               const QString& identifier)
{
  if (userOptionsValue.isEmpty())
    return {};

  QJsonObject result;
  if (userOptionsValue == QLatin1String("dynamic"))
    result = loadOptionsFromScript(packageDir, command, identifier);
  else
    result = loadOptionsFromFile(packageDir + '/' + userOptionsValue);

  // Both loadOptionsFromFile() and loadOptionsFromScript() may wrap a bare
  // array under "userOptions".  Unwrap so callers can insert under their own
  // key without double-nesting.
  if (result.contains(QStringLiteral("userOptions"))) {
    QJsonValue val = result.value(QStringLiteral("userOptions"));
    if (val.isObject())
      return val.toObject();
    // Value is an array; return wrapped form for caller to handle.
    return result;
  }

  return result;
}

static bool hasNonExecutablePixiPython(const QString& packageDir)
{
#ifdef Q_OS_WIN
  const QStringList pythonDirs = {
    packageDir + QStringLiteral("/.pixi/envs/default/Scripts"),
    packageDir + QStringLiteral("/.pixi/envs/default/bin")
  };
#else
  const QStringList pythonDirs = { packageDir +
                                   QStringLiteral("/.pixi/envs/default/bin") };
#endif

  for (const QString& dirPath : pythonDirs) {
    QDir dir(dirPath);
    if (!dir.exists())
      continue;

    const QFileInfoList candidates =
      dir.entryInfoList(QStringList() << QStringLiteral("python*"),
                        QDir::Files | QDir::NoDotAndDotDot);
    if (candidates.isEmpty())
      continue;

    for (const QFileInfo& candidate : candidates) {
      if (!candidate.isExecutable())
        return true;
    }
  }

  return false;
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
// Installation
// ---------------------------------------------------------------------------

// Read the *-setup script name from [project.scripts], if any.
static QString readSetupCommand(const QString& packageDir)
{
  QString tomlPath = packageDir + QStringLiteral("/pyproject.toml");
  QFile tomlFile(tomlPath);
  if (!tomlFile.open(QIODevice::ReadOnly))
    return {};
  const QByteArray content = tomlFile.readAll();

  bool ok = false;
  const QVariantMap root =
    parseTomlString(std::string_view(content.constData(), content.size()), &ok);
  if (!ok)
    return {};

  const QVariantMap scripts = root.value(QStringLiteral("project"))
                                .toMap()
                                .value(QStringLiteral("scripts"))
                                .toMap();
  // Only allow script names with safe characters (letters, digits, hyphen,
  // underscore) to prevent path traversal when the name is used to build
  // an executable path.
  auto isSafeScriptName = [](const QString& name) {
    for (const QChar ch : name) {
      const ushort u = ch.unicode();
      if (!((u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') ||
            (u >= '0' && u <= '9') || u == '-' || u == '_'))
        return false;
    }
    return !name.isEmpty();
  };

  for (auto it = scripts.constBegin(); it != scripts.constEnd(); ++it) {
    if (it.key().startsWith(QStringLiteral("avogadro-")) &&
        it.key().endsWith(QStringLiteral("-setup")) &&
        isSafeScriptName(it.key()))
      return it.key();
  }
  return {};
}

// Run a package's *-setup script (e.g. to download ML model weights).
static void runSetupScript(const QString& packageDir, const QString& setupCmd,
                           bool isPixi, int timeoutMs)
{
  if (setupCmd.isEmpty())
    return;
  const QString setupExe = findInstalledScript(packageDir, setupCmd, isPixi);
  if (setupExe.isEmpty())
    return;

  QProcess proc;
  proc.setWorkingDirectory(packageDir);
  proc.start(setupExe, {});
  if (!proc.waitForStarted(timeoutMs)) {
    qWarning() << "setup script could not be started for" << packageDir << ":"
               << proc.errorString();
    return;
  }
  if (!proc.waitForFinished(timeoutMs)) {
    qWarning() << "setup script timed out for" << packageDir;
    proc.kill();
  } else if (proc.exitCode() != 0) {
    qWarning() << "setup script failed for" << packageDir << ":"
               << QString::fromUtf8(proc.readAllStandardError());
  }
}

void PackageManager::installPackages(const QStringList& packageDirs)
{
  QString pixiExe = QStandardPaths::findExecutable(QStringLiteral("pixi"));
  QString pythonExe;
  if (pixiExe.isEmpty()) {
    pythonExe = QStandardPaths::findExecutable(QStringLiteral("python3"));
    if (pythonExe.isEmpty())
      pythonExe = QStandardPaths::findExecutable(QStringLiteral("python"));
  }

  // Pre-read setup commands on the main thread so the install thread doesn't
  // need to re-parse pyproject.toml (parsePackage() will read it again later).
  QMap<QString, QString> setupCommands;
  for (const QString& dir : packageDirs)
    setupCommands[dir] = readSetupCommand(dir);

  QThread* installThread =
    QThread::create([pixiExe, pythonExe, packageDirs, setupCommands]() {
      constexpr int installTimeoutMs = 10 * 60 * 1000; // 10 minutes
      for (const QString& packageDir : packageDirs) {
        if (pixiExe.isEmpty() && pythonExe.isEmpty())
          continue;

        if (!pixiExe.isEmpty()) {
          // If a copied package includes a non-executable .pixi environment,
          // pixi install fails querying its interpreter. Remove it and
          // recreate.
          const QString pixiDir = packageDir + QStringLiteral("/.pixi");
          if (hasNonExecutablePixiPython(packageDir)) {
            if (!QDir(pixiDir).removeRecursively()) {
              qWarning() << "Could not remove invalid .pixi directory in"
                         << packageDir;
            }
          }

          // Pixi install
          QProcess installProc;
          installProc.setWorkingDirectory(packageDir);
          installProc.start(pixiExe, { QStringLiteral("install") });
          if (!installProc.waitForFinished(installTimeoutMs)) {
            qWarning() << "pixi install timed out for" << packageDir;
            installProc.kill();
            continue;
          }
          if (installProc.exitCode() != 0) {
            qWarning() << "pixi install failed for" << packageDir << ":"
                       << QString::fromUtf8(installProc.readAllStandardError());
          } else {
            // Run the *-setup script if one is declared (e.g. to download ML
            // model weights).
            runSetupScript(packageDir, setupCommands.value(packageDir), true,
                           installTimeoutMs);
          }
        } else {
          // Step 1: create a venv
          QProcess venvProc;
          venvProc.setWorkingDirectory(packageDir);
          venvProc.start(pythonExe,
                         { QStringLiteral("-m"), QStringLiteral("venv"),
                           QStringLiteral(".venv") });
          if (!venvProc.waitForFinished(installTimeoutMs)) {
            qWarning() << "venv creation timed out for" << packageDir;
            venvProc.kill();
            continue;
          }
          if (venvProc.exitCode() != 0) {
            qWarning() << "venv creation failed for" << packageDir << ":"
                       << venvProc.readAllStandardError();
            continue;
          }

        // Step 2: pip install . using the venv's pip
#ifdef Q_OS_WIN
          QString venvPip =
            packageDir + QStringLiteral("/.venv/Scripts/pip.exe");
#else
          QString venvPip = packageDir + QStringLiteral("/.venv/bin/pip");
#endif
          QProcess installProc;
          installProc.setWorkingDirectory(packageDir);
          installProc.start(venvPip,
                            { QStringLiteral("install"), QStringLiteral(".") });
          if (!installProc.waitForFinished(installTimeoutMs)) {
            qWarning() << "pip install timed out for" << packageDir;
            installProc.kill();
            continue;
          }
          if (installProc.exitCode() != 0) {
            qWarning() << "pip install failed for" << packageDir << ":"
                       << installProc.readAllStandardError();
          } else {
            // Run the *-setup script if one is declared.
            runSetupScript(packageDir, setupCommands.value(packageDir), false,
                           installTimeoutMs);
          }
        }
      }
    });

  connect(
    installThread, &QThread::finished, this,
    [this, packageDirs, installThread]() {
      for (const QString& packageDir : packageDirs)
        registerPackage(packageDir);
      emit packagesInstalled();
      installThread->deleteLater();
    },
    Qt::QueuedConnection);

  installThread->start();
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
    emit featureRemoved(f.type, info.directory, info.command, f.identifier);

  removeFromCache(packageName);
  return true;
}

// ---------------------------------------------------------------------------
// Directory scanning
// ---------------------------------------------------------------------------

QStringList PackageManager::scanDirectory(const QString& directoryPath)
{
  QStringList result;

  QDir dir(directoryPath);
  if (!dir.exists()) {
#ifndef NDEBUG
    qWarning() << "PackageManager::scanDirectory: directory does not exist:"
               << directoryPath;
#endif
    return result;
  }

  const QStringList subdirs = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);

  for (const QString& subdir : subdirs) {
    QString packageDir = dir.absoluteFilePath(subdir);
    QString tomlPath = packageDir + QStringLiteral("/pyproject.toml");

    QFile tomlFile(tomlPath);
    if (!tomlFile.exists())
      continue;

    // Compute hash of the current pyproject.toml
    if (!tomlFile.open(QIODevice::ReadOnly))
      continue;
    QByteArray currentHash =
      QCryptographicHash::hash(tomlFile.readAll(), QCryptographicHash::Sha256)
        .toHex();
    tomlFile.close();

    // Check if we already have this package with the same hash
    // We need to find the package name — check all registered packages
    bool needsRegistration = true;
    const QStringList known = registeredPackages();
    for (const QString& name : known) {
      PackageInfo info = packageInfo(name);
      if (QDir(info.directory) == QDir(packageDir)) {
        // Same directory — check the cached hash
        QSettings settings;
        QString prefix = QStringLiteral("plugins/") + name + '/';
        QByteArray cachedHash =
          settings.value(prefix + "tomlHash").toByteArray();
        if (cachedHash == currentHash) {
          needsRegistration = false;
        }
        break;
      }
    }

    if (needsRegistration) {
      result.append(packageDir);
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

void PackageManager::loadRegisteredPackages(const QString& typeFilter)
{
  QSettings settings;
  settings.beginGroup(QStringLiteral("plugins"));
  const QStringList names = settings.childGroups();
  settings.endGroup();

  for (const QString& name : names) {
    PackageInfo info;
    QList<FeatureEntry> features;
    if (!loadFromCache(name, info, features))
      continue;

    if (typeFilter.isEmpty()) {
      emitFeatures(info, features);
      continue;
    }

    QList<FeatureEntry> filtered;
    for (const auto& feature : features) {
      if (feature.type == typeFilter)
        filtered.append(feature);
    }
    if (!filtered.isEmpty())
      emitFeatures(info, filtered);
  }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

QStringList PackageManager::registeredPackages() const
{
  QSettings settings;
  settings.beginGroup(QStringLiteral("plugins"));
  QStringList names = settings.childGroups();
  settings.endGroup();
  return names;
}

QStringList PackageManager::packageFeatureTypes(
  const QString& packageName) const
{
  QSettings settings;
  QString prefix = QStringLiteral("plugins/") + packageName + '/';
  QByteArray json = settings.value(prefix + "features").toByteArray();
  QJsonDocument doc = QJsonDocument::fromJson(json);
  if (!doc.isArray())
    return {};

  QStringList types;
  const QJsonArray arr = doc.array();
  for (const auto& val : arr) {
    if (!val.isObject())
      continue;
    const QString type =
      val.toObject().value(QStringLiteral("type")).toString();
    if (!type.isEmpty() && !types.contains(type))
      types.append(type);
  }
  return types;
}

PackageManager::PackageInfo PackageManager::packageInfo(
  const QString& packageName) const
{
  PackageInfo info;
  QSettings settings;
  QString prefix = QStringLiteral("plugins/") + packageName + '/';
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

  QFile tomlFile(tomlPath);
  if (!tomlFile.open(QIODevice::ReadOnly | QIODevice::Text))
    return false;
  QByteArray content = tomlFile.readAll();

  bool ok = false;
  QVariantMap root =
    parseTomlString(std::string_view(content.constData(), content.size()), &ok);
  if (!ok) {
    qWarning() << "PackageManager: TOML parse error in" << tomlPath;
    return false;
  }

  // --- [project] ---
  QVariantMap project = root.value(QStringLiteral("project")).toMap();
  if (project.isEmpty()) {
    qWarning() << "PackageManager: missing [project] table in" << tomlPath;
    return false;
  }

  info.directory = QDir(packageDir).absolutePath();
  info.name = project.value(QStringLiteral("name")).toString();
  info.version = project.value(QStringLiteral("version")).toString();
  // not really crucial
  info.description = project.value(QStringLiteral("description")).toString();

  if (info.name.isEmpty()) {
    qWarning() << "PackageManager: [project.name] is required in" << tomlPath;
    return false;
  }

  // --- [project.scripts] → find the avogadro- entry point ---
  // Skip *-setup scripts; those are post-install helpers, not the main command.
  QVariantMap scripts = project.value(QStringLiteral("scripts")).toMap();
  for (auto it = scripts.constBegin(); it != scripts.constEnd(); ++it) {
    if (it.key().startsWith(QStringLiteral("avogadro-")) &&
        !it.key().endsWith(QStringLiteral("-setup"))) {
      if (info.command.isEmpty())
        info.command = it.key();
      // in principle we should break, but check for multiple entries
      // and warn about them
      else
        qWarning() << "PackageManager: multiple avogadro-* entry points in"
                   << tomlPath;
    }
  }
  if (info.command.isEmpty()) {
    qWarning() << "PackageManager: no avogadro-* entry in [project.scripts]"
               << "in" << tomlPath;
    return false;
  }

  // --- [tool.avogadro.*] feature arrays ---
  QVariantMap toolAvogadro = root.value(QStringLiteral("tool"))
                               .toMap()
                               .value(QStringLiteral("avogadro"))
                               .toMap();
  if (toolAvogadro.isEmpty()) {
    qWarning() << "PackageManager: missing [tool.avogadro] in" << tomlPath;
    return false;
  }

  const QStringList types = featureTypes();
  for (const QString& type : types) {
    const QVariantList arr = toolAvogadro.value(type).toList();
    for (const QVariant& element : arr) {
      QVariantMap table = element.toMap();
      if (table.isEmpty())
        continue;

      FeatureEntry entry;
      entry.type = type;
      entry.identifier = table.value(QStringLiteral("identifier")).toString();

      if (entry.identifier.isEmpty()) {
        qWarning() << "PackageManager: feature in" << type
                   << "missing identifier, skipping";
        continue;
      }

      // Store the entire table as metadata (identifier is kept for
      // convenience)
      entry.metadata = table;
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
  QString prefix = QStringLiteral("plugins/") + info.name + '/';

  settings.setValue(prefix + "directory", info.directory);
  settings.setValue(prefix + "command", info.command);
  settings.setValue(prefix + "version", info.version);
  // not really crucial
  settings.setValue(prefix + "description", info.description);

  // Store a hash of pyproject.toml so scanDirectory() can detect changes
  QString tomlPath = info.directory + QStringLiteral("/pyproject.toml");
  QFile tomlFile(tomlPath);
  if (tomlFile.open(QIODevice::ReadOnly)) {
    QByteArray hash =
      QCryptographicHash::hash(tomlFile.readAll(), QCryptographicHash::Sha256);
    settings.setValue(prefix + "tomlHash", hash.toHex());
  }

  // Serialize features as a JSON array string
  QJsonArray arr;
  for (const auto& f : features)
    arr.append(featureEntryToJson(f));

  settings.setValue(prefix + "features",
                    QJsonDocument(arr).toJson(QJsonDocument::Compact));
  settings.sync();
}

void PackageManager::removeFromCache(const QString& packageName)
{
  QSettings settings;
  settings.beginGroup(QStringLiteral("plugins"));
  settings.remove(packageName);
  settings.endGroup();
  settings.sync();
}

bool PackageManager::loadFromCache(const QString& packageName,
                                   PackageInfo& info,
                                   QList<FeatureEntry>& features)
{
  QSettings settings;
  QString prefix = QStringLiteral("plugins/") + packageName + '/';

  info.name = packageName;
  info.directory = settings.value(prefix + "directory").toString();
  info.command = settings.value(prefix + "command").toString();
  info.version = settings.value(prefix + "version").toString();
  info.description = settings.value(prefix + "description").toString();

  if (info.directory.isEmpty() || info.command.isEmpty())
    return false;

  // Verify the package directory still exists and has a pyproject.toml
  QFileInfo pyproject(info.directory + QLatin1String("/pyproject.toml"));
  if (!pyproject.isFile()) {
    removeFromCache(packageName);
    return false;
  }

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
