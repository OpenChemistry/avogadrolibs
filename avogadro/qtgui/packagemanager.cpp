/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "packagemanager.h"
#include "tomlparse.h"
#include "utilities.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QRegularExpression>
#include <QtCore/QStandardPaths>
#include <QtCore/QThread>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonParseError>
#include <QtCore/QSettings>

using namespace Qt::StringLiterals;

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

QString PackageManager::featureSettingsKey(const QString& packageDir,
                                           const QString& command,
                                           const QString& identifier)
{
  // The directory name is enough to tell packages apart: they all live side
  // by side in the plugin directory, so two cannot share one.
  static const QRegularExpression unsafe(QStringLiteral("[^A-Za-z0-9._-]+"));
  auto clean = [](const QString& part) {
    return QString(part).replace(unsafe, QStringLiteral("_"));
  };

  return clean(QFileInfo(packageDir).fileName()) + QLatin1Char('/') +
         clean(command) + QLatin1Char('/') + clean(identifier);
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
  } else if (doc.isObject()) {
    QJsonObject wrapped;
    wrapped.insert(QStringLiteral("userOptions"), doc.object());
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

// Names to try, in order of preference, when looking for a Python
// interpreter to install a package with.
static QStringList pythonExecutableNames()
{
#ifdef Q_OS_WIN
  return { QStringLiteral("python.exe"), QStringLiteral("python3.exe") };
#else
  return { QStringLiteral("python3"), QStringLiteral("python") };
#endif
}

// Full path to the pixi executable, or an empty string if it is not installed.
static QString findPixiExecutable()
{
#ifdef Q_OS_WIN
  const QString pixiName = QStringLiteral("pixi.exe");
#else
  const QString pixiName = QStringLiteral("pixi");
#endif
  const QString pixiDir = Utilities::findExecutablePath(pixiName);
  return pixiDir.isEmpty() ? QString() : pixiDir + '/' + pixiName;
}

bool PackageManager::hasPixiManifest(const QString& packageDir)
{
  if (packageDir.isEmpty())
    return false;

  // A standalone pixi.toml is a workspace in its own right.
  if (QFileInfo::exists(packageDir + QStringLiteral("/pixi.toml")))
    return true;

  QFile tomlFile(packageDir + QStringLiteral("/pyproject.toml"));
  if (!tomlFile.open(QIODevice::ReadOnly))
    return false;
  const QByteArray content = tomlFile.readAll();

  bool ok = false;
  const QVariantMap root =
    parseTomlString(std::string_view(content.constData(), content.size()), &ok);
  if (!ok)
    return false;

  return !root.value(QStringLiteral("tool"))
            .toMap()
            .value(QStringLiteral("pixi"))
            .toMap()
            .isEmpty();
}

QString PackageManager::pixiScriptPath(const QString& packageDir,
                                       const QString& command)
{
  if (packageDir.isEmpty() || command.isEmpty())
    return {};
  return findInstalledScript(packageDir, command, true);
}

QString PackageManager::venvScriptPath(const QString& packageDir,
                                       const QString& command)
{
  if (packageDir.isEmpty() || command.isEmpty())
    return {};
  return findInstalledScript(packageDir, command, false);
}

PackageManager::CommandLine PackageManager::resolveCommandLine(
  const QString& packageDir, const QString& command)
{
  CommandLine commandLine;

  const QString pixiExe = findPixiExecutable();
  if (!pixiExe.isEmpty() && !pixiScriptPath(packageDir, command).isEmpty()) {
    commandLine.program = pixiExe;
    commandLine.prefixArgs = { QStringLiteral("run"), QStringLiteral("--as-is"),
                               command };
    return commandLine;
  }

  commandLine.program = venvScriptPath(packageDir, command);
  return commandLine;
}

QJsonObject PackageManager::loadOptionsFromScript(const QString& packageDir,
                                                  const QString& command,
                                                  const QString& identifier)
{
  const CommandLine commandLine = resolveCommandLine(packageDir, command);
  if (commandLine.program.isEmpty()) {
    qWarning() << "PackageManager: no installed environment providing"
               << command << "in" << packageDir;
    return {};
  }

  QStringList userOptsArgs = commandLine.prefixArgs;
  if (!identifier.isEmpty())
    userOptsArgs << identifier;
  userOptsArgs << QStringLiteral("--user-options");

  QProcess proc;
  proc.setWorkingDirectory(packageDir);
  proc.start(commandLine.program, userOptsArgs);

  // Plugins may always expect some valid JSON as input over stdin, even if it's
  // just an empty object
  QByteArray scriptStdin = "{}"_ba;
  proc.write(scriptStdin);
  // Python
  proc.closeWriteChannel();

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

bool PackageManager::isDynamicUserOptions(const QString& userOptionsValue)
{
  return userOptionsValue == QLatin1String("dynamic");
}

QJsonObject PackageManager::resolveUserOptions(const QString& userOptionsValue,
                                               const QString& packageDir,
                                               const QString& command,
                                               const QString& identifier)
{
  if (userOptionsValue.isEmpty())
    return {};

  QJsonObject result;
  if (isDynamicUserOptions(userOptionsValue))
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

// Entry-point names read from [project.scripts].
struct PackageCommands
{
  QString command;      ///< the avogadro-* entry point
  QString setupCommand; ///< the avogadro-*-setup helper, if any
};

// Only allow script names with safe characters (letters, digits, hyphen,
// underscore) to prevent path traversal when the name is used to build
// an executable path.
static bool isSafeScriptName(const QString& name)
{
  for (const QChar ch : name) {
    const ushort u = ch.unicode();
    if (!((u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') ||
          (u >= '0' && u <= '9') || u == '-' || u == '_'))
      return false;
  }
  return !name.isEmpty();
}

// Pick the avogadro-* entry points out of a parsed [project.scripts] table.
// @p tomlPath is used only for warnings.
static PackageCommands selectScriptCommands(const QVariantMap& scripts,
                                            const QString& tomlPath)
{
  PackageCommands commands;

  for (auto it = scripts.constBegin(); it != scripts.constEnd(); ++it) {
    if (!it.key().startsWith(QStringLiteral("avogadro-")) ||
        !isSafeScriptName(it.key()))
      continue;

    // *-setup scripts are post-install helpers, not the main command.
    if (it.key().endsWith(QStringLiteral("-setup"))) {
      if (commands.setupCommand.isEmpty())
        commands.setupCommand = it.key();
    } else if (commands.command.isEmpty()) {
      commands.command = it.key();
    } else {
      // in principle we should stop at the first, but check for multiple
      // entries and warn about them
      qWarning() << "PackageManager: multiple avogadro-* entry points in"
                 << tomlPath;
    }
  }

  return commands;
}

// Read the entry-point names from [project.scripts], if any.
static PackageCommands readScriptCommands(const QString& packageDir)
{
  const QString tomlPath = packageDir + QStringLiteral("/pyproject.toml");
  QFile tomlFile(tomlPath);
  if (!tomlFile.open(QIODevice::ReadOnly))
    return {};
  const QByteArray content = tomlFile.readAll();

  bool ok = false;
  const QVariantMap root =
    parseTomlString(std::string_view(content.constData(), content.size()), &ok);
  if (!ok)
    return {};

  return selectScriptCommands(root.value(QStringLiteral("project"))
                                .toMap()
                                .value(QStringLiteral("scripts"))
                                .toMap(),
                              tomlPath);
}

// Compare two package names the way Python does (PEP 503): case-insensitively,
// with any run of "-", "_" and "." equivalent. An exact comparison would be
// wrong in both directions here — QSettings folds key case on Windows and
// macOS, and a package is free to respell "avogadro_x" as "avogadro-x" without
// becoming a different package.
static QString normalizedPackageName(const QString& name)
{
  static const QRegularExpression separators(QStringLiteral("[-_.]+"));
  return QString(name).replace(separators, QStringLiteral("-")).toLower();
}

// The [project] table of the pyproject.toml in @p packageDir, empty if the
// file cannot be read or parsed.
static QVariantMap readProjectTable(const QString& packageDir)
{
  QFile tomlFile(packageDir + QStringLiteral("/pyproject.toml"));
  if (!tomlFile.open(QIODevice::ReadOnly))
    return {};
  const QByteArray content = tomlFile.readAll();

  bool ok = false;
  const QVariantMap root =
    parseTomlString(std::string_view(content.constData(), content.size()), &ok);
  if (!ok)
    return {};

  return root.value(QStringLiteral("project")).toMap();
}

// The [project.name] declared by the pyproject.toml in @p packageDir, or an
// empty string if it cannot be read.
static QString readPackageName(const QString& packageDir)
{
  return readProjectTable(packageDir).value(QStringLiteral("name")).toString();
}

QString PackageManager::packageVersion(const QString& packageDir)
{
  if (packageDir.isEmpty())
    return {};
  return readProjectTable(packageDir)
    .value(QStringLiteral("version"))
    .toString();
}

bool PackageManager::removeSupersededVenv(const QString& packageDir,
                                          const QString& command)
{
  // Never build a path to remove recursively out of an empty directory.
  if (packageDir.isEmpty())
    return false;

  const QString venvDir = packageDir + QStringLiteral("/.venv");
  if (!QDir(venvDir).exists())
    return false;

  // Only give up the venv once pixi can actually run the command, so that a
  // failed or partial install cannot leave the package unrunnable.
  if (pixiScriptPath(packageDir, command).isEmpty()) {
    qWarning() << "Keeping" << venvDir
               << "because the pixi environment does not provide" << command;
    return false;
  }

  if (!QDir(venvDir).removeRecursively()) {
    qWarning() << "Could not remove superseded virtual environment" << venvDir;
    return false;
  }

  return true;
}

// Run a package's *-setup command (e.g. to download ML model weights).
// This is called regardless of whether the package has defined one or not.
static void runSetupScript(const QString& packageDir, const QString& setupCmd,
                           const QString& pixiExe, bool isPixi, int timeoutMs)
{
  if (setupCmd.isEmpty())
    return;
  QProcess proc;
  proc.setWorkingDirectory(packageDir);
  if (isPixi) {
    // If we have Pixi, just run the command using `pixi run`
    proc.start(pixiExe, { QStringLiteral("run"), setupCmd });
  } else {
    const QString setupExe = findInstalledScript(packageDir, setupCmd, isPixi);
    if (setupExe.isEmpty()) {
      qDebug("No setup exe found, early return");
      return;
    }
    proc.start(setupExe, {});
  }
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

// Install @p packageDir with pixi. Returns true only if the package's command
// can afterwards be run from its pixi environment.
static bool installWithPixi(const QString& packageDir,
                            const PackageCommands& commands,
                            const QString& pixiExe, int timeoutMs)
{
  // Without a workspace of its own, pixi would install an ancestor's
  // environment and report success, leaving this package unrunnable.
  if (!PackageManager::hasPixiManifest(packageDir)) {
    qWarning() << "PackageManager:" << packageDir
               << "declares no pixi workspace, installing with pip instead";
    return false;
  }

  // If a copied package includes a non-executable .pixi environment,
  // pixi install fails querying its interpreter. Remove it and recreate.
  const QString pixiDir = packageDir + QStringLiteral("/.pixi");
  if (hasNonExecutablePixiPython(packageDir)) {
    if (!QDir(pixiDir).removeRecursively()) {
      qWarning() << "Could not remove invalid .pixi directory in" << packageDir;
    }
  }

  QProcess installProc;
  installProc.setWorkingDirectory(packageDir);
  installProc.start(pixiExe, { QStringLiteral("install") });
  if (!installProc.waitForFinished(timeoutMs)) {
    qWarning() << "pixi install timed out for" << packageDir;
    installProc.kill();
    return false;
  }
  if (installProc.exitCode() != 0) {
    qWarning() << "pixi install failed for" << packageDir << ":"
               << QString::fromUtf8(installProc.readAllStandardError());
    return false;
  }

  // Exit code 0 is not proof that this package was installed, so check that
  // the command actually landed in the environment before relying on it.
  if (!commands.command.isEmpty() &&
      PackageManager::pixiScriptPath(packageDir, commands.command).isEmpty()) {
    qWarning() << "pixi install reported success but did not provide"
               << commands.command << "in" << packageDir;
    return false;
  }

  // A package set up before pixi was available was pip-installed into .venv.
  // Now that pixi has taken over, drop that tree.
  PackageManager::removeSupersededVenv(packageDir, commands.command);

  // Run the *-setup script if one is declared (e.g. to download ML model
  // weights).
  runSetupScript(packageDir, commands.setupCommand, pixiExe, true, timeoutMs);
  return true;
}

// Install @p packageDir with pip into a fresh .venv. Returns true only if the
// package's command can afterwards be run from that environment.
static bool installWithPip(const QString& packageDir,
                           const PackageCommands& commands,
                           const QString& pythonExe, int timeoutMs)
{
  // Step 1: create a venv
  QProcess venvProc;
  venvProc.setWorkingDirectory(packageDir);
  venvProc.start(pythonExe, { QStringLiteral("-m"), QStringLiteral("venv"),
                              QStringLiteral(".venv") });
  if (!venvProc.waitForFinished(timeoutMs)) {
    qWarning() << "venv creation timed out for" << packageDir;
    venvProc.kill();
    return false;
  }
  if (venvProc.exitCode() != 0) {
    qWarning() << "venv creation failed for" << packageDir << ":"
               << venvProc.readAllStandardError();
    return false;
  }

  // Step 2: pip install . using the venv's pip
#ifdef Q_OS_WIN
  QString venvPip = packageDir + QStringLiteral("/.venv/Scripts/pip.exe");
#else
  QString venvPip = packageDir + QStringLiteral("/.venv/bin/pip");
#endif
  QProcess installProc;
  installProc.setWorkingDirectory(packageDir);
  installProc.start(venvPip,
                    { QStringLiteral("install"), QStringLiteral(".") });
  if (!installProc.waitForFinished(timeoutMs)) {
    qWarning() << "pip install timed out for" << packageDir;
    installProc.kill();
    return false;
  }
  if (installProc.exitCode() != 0) {
    qWarning() << "pip install failed for" << packageDir << ":"
               << installProc.readAllStandardError();
    return false;
  }

  // Exit code 0 is not proof that this package was installed, so check that
  // the command actually landed in the environment before relying on it.
  if (!commands.command.isEmpty() &&
      PackageManager::venvScriptPath(packageDir, commands.command).isEmpty()) {
    qWarning() << "pip install reported success but did not provide"
               << commands.command << "in" << packageDir;
    return false;
  }

  // Run the *-setup script if one is declared.
  runSetupScript(packageDir, commands.setupCommand, QString(), false,
                 timeoutMs);
  return true;
}

void PackageManager::installPackages(const QStringList& packageDirs)
{
  const QString pixiExe = findPixiExecutable();
  QString pythonExe;
  // Paths come back in the order the names were given, so the first hit is
  // the most preferred interpreter.
  const QStringList pythons =
    Utilities::findExecutablePaths(pythonExecutableNames());
  if (!pythons.isEmpty())
    pythonExe = pythons.constFirst();

  // Pre-read entry-point names on the main thread so the install thread
  // doesn't need to re-parse pyproject.toml (parsePackage() reads it again
  // later).
  QMap<QString, PackageCommands> packageCommands;
  for (const QString& dir : packageDirs)
    packageCommands[dir] = readScriptCommands(dir);
  QThread* installThread =
    QThread::create([pixiExe, pythonExe, packageDirs, packageCommands]() {
      constexpr int installTimeoutMs = 10 * 60 * 1000; // 10 minutes
      for (const QString& packageDir : packageDirs) {
        const PackageCommands commands = packageCommands.value(packageDir);
        bool installed = false;

        if (!pixiExe.isEmpty()) {
          installed =
            installWithPixi(packageDir, commands, pixiExe, installTimeoutMs);
        }

        // pixi is preferred, but it cannot install a package that declares no
        // workspace of its own, and an install that leaves the command
        // missing is no install at all. Either way pip can still do it.
        if (!installed && !pythonExe.isEmpty()) {
          installed =
            installWithPip(packageDir, commands, pythonExe, installTimeoutMs);
        }

        if (!installed) {
          qWarning() << "PackageManager: could not install" << packageDir;
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

// Decide whether an already-registered package whose pyproject.toml is
// unchanged should nevertheless be installed again. Nothing about the package
// itself has changed, but the environment it was installed into may be missing
// or may have been built with a backend we no longer prefer: a package
// pip-installed into .venv predates pixi being available on this machine, and
// "pixi run --as-is" will not create the pixi environment on demand. Both are
// repaired by installing again — except that a package declaring no pixi
// workspace of its own can never be moved off .venv, so pixi being merely
// present must not be treated as a reason to reinstall it: that would re-offer
// the install on every launch, for ever.
static bool environmentNeedsInstall(const QString& packageDir,
                                    const QString& command, bool pixiUsable,
                                    bool canInstall)
{
  // Nothing to install with, or nothing to install — don't ask every launch.
  if (!canInstall || command.isEmpty())
    return false;

  if (!PackageManager::pixiScriptPath(packageDir, command).isEmpty())
    return false; // usable pixi environment, the preferred backend

  if (PackageManager::venvScriptPath(packageDir, command).isEmpty())
    return true; // no usable environment at all

  // A working .venv, but pixi has been installed since it was created and can
  // install this package.
  return pixiUsable;
}

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

  // Whether we could repair a package with a missing or outdated environment.
  const bool pixiAvailable = !findPixiExecutable().isEmpty();
  const bool pythonAvailable =
    !Utilities::findExecutablePaths(pythonExecutableNames()).isEmpty();

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

    // pixi can only install a package that brings its own workspace.
    const bool pixiUsable = pixiAvailable && hasPixiManifest(packageDir);
    const bool canInstall = pixiUsable || pythonAvailable;

    // Several cache entries can name the same directory: a package renamed
    // upstream leaves its old name behind, with the hash of a pyproject.toml
    // that will never be seen again. Check them all rather than stopping at
    // the first, or that stale entry alone would keep the package looking
    // out of date on every launch.
    bool needsRegistration = true;
    const QStringList known = registeredPackages();
    for (const QString& name : known) {
      const PackageInfo info = packageInfo(name);
      if (QDir(info.directory) != QDir(packageDir))
        continue;

      QSettings settings;
      const QString prefix = QStringLiteral("plugins/") + name + '/';
      const QByteArray cachedHash =
        settings.value(prefix + "tomlHash").toByteArray();
      if (cachedHash != currentHash)
        continue;

      if (!environmentNeedsInstall(packageDir, info.command, pixiUsable,
                                   canInstall)) {
        needsRegistration = false;
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
  info.command = selectScriptCommands(
                   project.value(QStringLiteral("scripts")).toMap(), tomlPath)
                   .command;
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

  // A package renamed upstream leaves its old entry behind: the directory and
  // its pyproject.toml are still there, but they now describe a different
  // package. Replaying it would register features that can never run.
  const QString declaredName =
    normalizedPackageName(readPackageName(info.directory));
  if (!declaredName.isEmpty() &&
      declaredName != normalizedPackageName(packageName)) {
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
