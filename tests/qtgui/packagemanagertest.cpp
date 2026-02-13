/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/packagemanager.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QSettings>
#include <QtCore/QTemporaryDir>
#include <QtCore/QVariantMap>

#include <QSignalSpy>

using Avogadro::QtGui::PackageManager;

class PackageManagerTest : public testing::Test
{
protected:
  void SetUp() override
  {
    // Write a minimal pyproject.toml into a temp directory
    m_tmpDir.reset(new QTemporaryDir);
    ASSERT_TRUE(m_tmpDir->isValid());
    m_packageDir = m_tmpDir->path();

    QFile f(m_packageDir + "/pyproject.toml");
    ASSERT_TRUE(f.open(QIODevice::WriteOnly | QIODevice::Text));
    f.write(sampleToml());
    f.close();

    // Clear any previous test data from QSettings
    QSettings settings;
    settings.beginGroup("packages");
    settings.remove("test-plugin");
    settings.endGroup();
  }

  void TearDown() override
  {
    // Clean up QSettings
    QSettings settings;
    settings.beginGroup("packages");
    settings.remove("test-plugin");
    settings.endGroup();
  }

  static QByteArray sampleToml()
  {
    return R"(
[project]
name = "test-plugin"
version = "1.2.3"
description = "A test plugin"

[project.scripts]
avogadro-test-plugin = "test_plugin:main"

[build-system]
build-backend = "hatchling.build"
requires = ["hatchling"]

[tool.avogadro]
minimum-avogadro-version = "1.103"

[[tool.avogadro.menu-commands]]
identifier = "do-something"
input-format = "cjson"
path.menu = "Extensions"
path.entry = { label = "Do Something", priority = 200 }

[[tool.avogadro.menu-commands]]
identifier = "do-other"
input-format = "cjson"
path.menu = "Build"
path.entry = { label = "Do Other", priority = 100 }

[[tool.avogadro.electrostatic-models]]
identifier = "test_charges"
model-name = "TestCharges"
input-format = "sdf"
support.charges = true
support.potentials = false
support.elements = "1-18"

[[tool.avogadro.energy-models]]
identifier = "test_energy"
model-name = "TestEnergy"
input-format = "cjson"
support.gradients = true
support.elements = "1-86"

[[tool.avogadro.file-formats]]
identifier = "tst"
format-name = "TST format"
file-extensions = ["tst", "tst2"]
support.read = true
support.write = false
output-format = "cjson"

[[tool.avogadro.input-generators]]
identifier = "test_input"
program-name = "Test Input Gen"
input-format = "cjson"
)";
  }

  std::unique_ptr<QTemporaryDir> m_tmpDir;
  QString m_packageDir;
};

TEST_F(PackageManagerTest, featureTypes)
{
  QStringList types = PackageManager::featureTypes();
  EXPECT_EQ(types.size(), 5);
  EXPECT_TRUE(types.contains("menu-commands"));
  EXPECT_TRUE(types.contains("electrostatic-models"));
  EXPECT_TRUE(types.contains("energy-models"));
  EXPECT_TRUE(types.contains("file-formats"));
  EXPECT_TRUE(types.contains("input-generators"));
}

TEST_F(PackageManagerTest, registerPackageSuccess)
{
  auto* pm = PackageManager::instance();

  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  ASSERT_TRUE(spy.isValid());

  bool ok = pm->registerPackage(m_packageDir);
  EXPECT_TRUE(ok);

  // 2 menu-commands + 1 charges + 1 energy + 1 file-format + 1 input-gen = 6
  EXPECT_EQ(spy.count(), 6);
}

TEST_F(PackageManagerTest, registerPackageEmitsCorrectSignals)
{
  auto* pm = PackageManager::instance();

  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  pm->registerPackage(m_packageDir);

  // Collect all emitted (type, identifier) pairs
  QMap<QString, QStringList> featuresByType;
  for (int i = 0; i < spy.count(); ++i) {
    QList<QVariant> args = spy.at(i);
    QString type = args.at(0).toString();
    QString identifier = args.at(3).toString();
    featuresByType[type].append(identifier);
  }

  EXPECT_EQ(featuresByType["menu-commands"].size(), 2);
  EXPECT_TRUE(featuresByType["menu-commands"].contains("do-something"));
  EXPECT_TRUE(featuresByType["menu-commands"].contains("do-other"));

  EXPECT_EQ(featuresByType["electrostatic-models"].size(), 1);
  EXPECT_TRUE(featuresByType["electrostatic-models"].contains("test_charges"));

  EXPECT_EQ(featuresByType["energy-models"].size(), 1);
  EXPECT_TRUE(featuresByType["energy-models"].contains("test_energy"));

  EXPECT_EQ(featuresByType["file-formats"].size(), 1);
  EXPECT_TRUE(featuresByType["file-formats"].contains("tst"));

  EXPECT_EQ(featuresByType["input-generators"].size(), 1);
  EXPECT_TRUE(featuresByType["input-generators"].contains("test_input"));
}

TEST_F(PackageManagerTest, signalCarriesCorrectMetadata)
{
  auto* pm = PackageManager::instance();

  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  pm->registerPackage(m_packageDir);

  // Find the "do-something" menu-command signal
  for (int i = 0; i < spy.count(); ++i) {
    QList<QVariant> args = spy.at(i);
    if (args.at(3).toString() == "do-something") {
      EXPECT_EQ(args.at(0).toString(), "menu-commands");
      EXPECT_EQ(args.at(1).toString(), QDir(m_packageDir).absolutePath());
      EXPECT_EQ(args.at(2).toString(), "avogadro-test-plugin");

      QVariantMap meta = args.at(4).toMap();
      EXPECT_EQ(meta["input-format"].toString(), "cjson");

      // Nested table: path.menu
      QVariantMap path = meta["path"].toMap();
      EXPECT_EQ(path["menu"].toString(), "Extensions");

      QVariantMap entry = path["entry"].toMap();
      EXPECT_EQ(entry["label"].toString(), "Do Something");
      EXPECT_EQ(entry["priority"].toLongLong(), 200);
      return;
    }
  }
  FAIL() << "did not find 'do-something' feature in signals";
}

TEST_F(PackageManagerTest, signalCarriesArrayMetadata)
{
  auto* pm = PackageManager::instance();

  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  pm->registerPackage(m_packageDir);

  // Find the "tst" file-format signal
  for (int i = 0; i < spy.count(); ++i) {
    QList<QVariant> args = spy.at(i);
    if (args.at(3).toString() == "tst") {
      QVariantMap meta = args.at(4).toMap();
      QVariantList exts = meta["file-extensions"].toList();
      EXPECT_EQ(exts.size(), 2);
      EXPECT_EQ(exts.at(0).toString(), "tst");
      EXPECT_EQ(exts.at(1).toString(), "tst2");

      QVariantMap support = meta["support"].toMap();
      EXPECT_TRUE(support["read"].toBool());
      EXPECT_FALSE(support["write"].toBool());
      return;
    }
  }
  FAIL() << "did not find 'tst' feature in signals";
}

TEST_F(PackageManagerTest, packageInfoAfterRegister)
{
  auto* pm = PackageManager::instance();
  pm->registerPackage(m_packageDir);

  auto info = pm->packageInfo("test-plugin");
  EXPECT_EQ(info.name, "test-plugin");
  EXPECT_EQ(info.version, "1.2.3");
  EXPECT_EQ(info.description, "A test plugin");
  EXPECT_EQ(info.command, "avogadro-test-plugin");
  EXPECT_EQ(info.directory, QDir(m_packageDir).absolutePath());
}

TEST_F(PackageManagerTest, registeredPackagesList)
{
  auto* pm = PackageManager::instance();
  pm->registerPackage(m_packageDir);

  QStringList packages = pm->registeredPackages();
  EXPECT_TRUE(packages.contains("test-plugin"));
}

TEST_F(PackageManagerTest, loadRegisteredPackagesReplaysSignals)
{
  auto* pm = PackageManager::instance();

  // Register first (this caches to QSettings)
  pm->registerPackage(m_packageDir);

  // Now spy and replay from cache
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  pm->loadRegisteredPackages();

  EXPECT_EQ(spy.count(), 6);
}

TEST_F(PackageManagerTest, unregisterPackage)
{
  auto* pm = PackageManager::instance();
  pm->registerPackage(m_packageDir);

  QSignalSpy removedSpy(pm, &PackageManager::featureRemoved);
  bool ok = pm->unregisterPackage("test-plugin");
  EXPECT_TRUE(ok);

  // Should have emitted featureRemoved for all 6 features
  EXPECT_EQ(removedSpy.count(), 6);

  // Package should no longer be in the list
  EXPECT_FALSE(pm->registeredPackages().contains("test-plugin"));
}

TEST_F(PackageManagerTest, registerInvalidDirFails)
{
  auto* pm = PackageManager::instance();
  bool ok = pm->registerPackage("/nonexistent/path");
  EXPECT_FALSE(ok);
}

TEST_F(PackageManagerTest, registerDirWithoutTomlFails)
{
  QTemporaryDir emptyDir;
  ASSERT_TRUE(emptyDir.isValid());

  auto* pm = PackageManager::instance();
  bool ok = pm->registerPackage(emptyDir.path());
  EXPECT_FALSE(ok);
}

TEST_F(PackageManagerTest, unregisterNonexistentFails)
{
  auto* pm = PackageManager::instance();
  bool ok = pm->unregisterPackage("no-such-package");
  EXPECT_FALSE(ok);
}

// ---------------------------------------------------------------------------
// TOML parsing edge-case tests
// ---------------------------------------------------------------------------

// Helper: write a pyproject.toml with custom [tool.avogadro] content,
// keeping the required [project] and [project.scripts] boilerplate.
static QString writeToml(QTemporaryDir& dir, const QByteArray& avogadroBlock)
{
  QByteArray toml = R"(
[project]
name = "parse-test"
version = "0.1.0"
description = "parsing tests"

[project.scripts]
avogadro-parse-test = "parse_test:main"

[tool.avogadro]
minimum-avogadro-version = "1.103"

)" + avogadroBlock;

  QFile f(dir.path() + "/pyproject.toml");
  f.open(QIODevice::WriteOnly | QIODevice::Text);
  f.write(toml);
  f.close();
  return dir.path();
}

// Find the first signal with the given identifier and return its metadata.
static QVariantMap findFeatureMetadata(const QSignalSpy& spy,
                                       const QString& identifier)
{
  for (int i = 0; i < spy.count(); ++i) {
    if (spy.at(i).at(3).toString() == identifier)
      return spy.at(i).at(4).toMap();
  }
  return {};
}

TEST(TomlParsing, stringValues)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QString path = writeToml(dir, R"(
[[tool.avogadro.menu-commands]]
identifier = "str-test"
simple = "hello world"
empty = ""
unicode = "café ☕"
)");

  auto* pm = PackageManager::instance();
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  ASSERT_TRUE(pm->registerPackage(path));

  QVariantMap meta = findFeatureMetadata(spy, "str-test");
  ASSERT_FALSE(meta.isEmpty());
  EXPECT_EQ(meta["simple"].toString(), "hello world");
  EXPECT_EQ(meta["empty"].toString(), "");
  EXPECT_EQ(meta["unicode"].toString(), QString::fromUtf8("café ☕"));

  pm->unregisterPackage("parse-test");
}

TEST(TomlParsing, integerValues)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QString path = writeToml(dir, R"(
[[tool.avogadro.menu-commands]]
identifier = "int-test"
positive = 42
zero = 0
negative = -7
large = 2147483648
)");

  auto* pm = PackageManager::instance();
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  ASSERT_TRUE(pm->registerPackage(path));

  QVariantMap meta = findFeatureMetadata(spy, "int-test");
  ASSERT_FALSE(meta.isEmpty());
  EXPECT_EQ(meta["positive"].toLongLong(), 42);
  EXPECT_EQ(meta["zero"].toLongLong(), 0);
  EXPECT_EQ(meta["negative"].toLongLong(), -7);
  EXPECT_EQ(meta["large"].toLongLong(), 2147483648LL);

  pm->unregisterPackage("parse-test");
}

TEST(TomlParsing, floatingPointValues)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QString path = writeToml(dir, R"(
[[tool.avogadro.menu-commands]]
identifier = "float-test"
pi = 3.14159
negative = -0.5
zero = 0.0
)");

  auto* pm = PackageManager::instance();
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  ASSERT_TRUE(pm->registerPackage(path));

  QVariantMap meta = findFeatureMetadata(spy, "float-test");
  ASSERT_FALSE(meta.isEmpty());
  EXPECT_DOUBLE_EQ(meta["pi"].toDouble(), 3.14159);
  EXPECT_DOUBLE_EQ(meta["negative"].toDouble(), -0.5);
  EXPECT_DOUBLE_EQ(meta["zero"].toDouble(), 0.0);

  pm->unregisterPackage("parse-test");
}

TEST(TomlParsing, booleanValues)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QString path = writeToml(dir, R"(
[[tool.avogadro.menu-commands]]
identifier = "bool-test"
yes = true
no = false
)");

  auto* pm = PackageManager::instance();
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  ASSERT_TRUE(pm->registerPackage(path));

  QVariantMap meta = findFeatureMetadata(spy, "bool-test");
  ASSERT_FALSE(meta.isEmpty());
  EXPECT_TRUE(meta["yes"].toBool());
  EXPECT_FALSE(meta["no"].toBool());

  pm->unregisterPackage("parse-test");
}

TEST(TomlParsing, nestedTables)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QString path = writeToml(dir, R"(
[[tool.avogadro.menu-commands]]
identifier = "nested-test"
path.menu = "Extensions"
path.submenu.menu = "Demo"
path.submenu.priority = 500
path.entry = { label = "Hello", priority = 100 }
)");

  auto* pm = PackageManager::instance();
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  ASSERT_TRUE(pm->registerPackage(path));

  QVariantMap meta = findFeatureMetadata(spy, "nested-test");
  ASSERT_FALSE(meta.isEmpty());

  QVariantMap pathMap = meta["path"].toMap();
  EXPECT_EQ(pathMap["menu"].toString(), "Extensions");

  QVariantMap submenu = pathMap["submenu"].toMap();
  EXPECT_EQ(submenu["menu"].toString(), "Demo");
  EXPECT_EQ(submenu["priority"].toLongLong(), 500);

  QVariantMap entry = pathMap["entry"].toMap();
  EXPECT_EQ(entry["label"].toString(), "Hello");
  EXPECT_EQ(entry["priority"].toLongLong(), 100);

  pm->unregisterPackage("parse-test");
}

TEST(TomlParsing, arrays)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QString path = writeToml(dir, R"(
[[tool.avogadro.menu-commands]]
identifier = "array-test"
string-list = ["alpha", "beta", "gamma"]
int-list = [1, 2, 3]
mixed-nested = [{ name = "a" }, { name = "b" }]
empty-list = []
)");

  auto* pm = PackageManager::instance();
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  ASSERT_TRUE(pm->registerPackage(path));

  QVariantMap meta = findFeatureMetadata(spy, "array-test");
  ASSERT_FALSE(meta.isEmpty());

  QVariantList strings = meta["string-list"].toList();
  ASSERT_EQ(strings.size(), 3);
  EXPECT_EQ(strings[0].toString(), "alpha");
  EXPECT_EQ(strings[1].toString(), "beta");
  EXPECT_EQ(strings[2].toString(), "gamma");

  QVariantList ints = meta["int-list"].toList();
  ASSERT_EQ(ints.size(), 3);
  EXPECT_EQ(ints[0].toLongLong(), 1);
  EXPECT_EQ(ints[1].toLongLong(), 2);
  EXPECT_EQ(ints[2].toLongLong(), 3);

  QVariantList nested = meta["mixed-nested"].toList();
  ASSERT_EQ(nested.size(), 2);
  EXPECT_EQ(nested[0].toMap()["name"].toString(), "a");
  EXPECT_EQ(nested[1].toMap()["name"].toString(), "b");

  QVariantList empty = meta["empty-list"].toList();
  EXPECT_EQ(empty.size(), 0);

  pm->unregisterPackage("parse-test");
}

TEST(TomlParsing, multipleFeatureTypes)
{
  // Verify that a single package can register features across different types
  // and each gets the correct type string.
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QString path = writeToml(dir, R"(
[[tool.avogadro.menu-commands]]
identifier = "cmd1"

[[tool.avogadro.electrostatic-models]]
identifier = "charge1"
model-name = "C1"

[[tool.avogadro.energy-models]]
identifier = "energy1"
model-name = "E1"

[[tool.avogadro.file-formats]]
identifier = "fmt1"
format-name = "F1"

[[tool.avogadro.input-generators]]
identifier = "gen1"
program-name = "G1"
)");

  auto* pm = PackageManager::instance();
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  ASSERT_TRUE(pm->registerPackage(path));

  EXPECT_EQ(spy.count(), 5);

  // Check each signal got the right type
  QMap<QString, QString> typeForId;
  for (int i = 0; i < spy.count(); ++i) {
    typeForId[spy.at(i).at(3).toString()] = spy.at(i).at(0).toString();
  }
  EXPECT_EQ(typeForId["cmd1"], "menu-commands");
  EXPECT_EQ(typeForId["charge1"], "electrostatic-models");
  EXPECT_EQ(typeForId["energy1"], "energy-models");
  EXPECT_EQ(typeForId["fmt1"], "file-formats");
  EXPECT_EQ(typeForId["gen1"], "input-generators");

  pm->unregisterPackage("parse-test");
}

TEST(TomlParsing, missingProjectTableFails)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QFile f(dir.path() + "/pyproject.toml");
  f.open(QIODevice::WriteOnly | QIODevice::Text);
  f.write(R"(
[tool.avogadro]
minimum-avogadro-version = "1.103"
)");
  f.close();

  auto* pm = PackageManager::instance();
  EXPECT_FALSE(pm->registerPackage(dir.path()));
}

TEST(TomlParsing, missingScriptsEntryFails)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QFile f(dir.path() + "/pyproject.toml");
  f.open(QIODevice::WriteOnly | QIODevice::Text);
  f.write(R"(
[project]
name = "no-scripts"
version = "0.1.0"

[project.scripts]
not-avogadro = "foo:bar"

[tool.avogadro]
minimum-avogadro-version = "1.103"
)");
  f.close();

  auto* pm = PackageManager::instance();
  EXPECT_FALSE(pm->registerPackage(dir.path()));
}

TEST(TomlParsing, missingToolAvogadroFails)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QFile f(dir.path() + "/pyproject.toml");
  f.open(QIODevice::WriteOnly | QIODevice::Text);
  f.write(R"(
[project]
name = "no-tool"
version = "0.1.0"

[project.scripts]
avogadro-no-tool = "no_tool:main"
)");
  f.close();

  auto* pm = PackageManager::instance();
  EXPECT_FALSE(pm->registerPackage(dir.path()));
}

TEST(TomlParsing, featureWithoutIdentifierSkipped)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QString path = writeToml(dir, R"(
[[tool.avogadro.menu-commands]]
identifier = "good"
input-format = "cjson"

[[tool.avogadro.menu-commands]]
input-format = "cjson"
)");

  auto* pm = PackageManager::instance();
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  ASSERT_TRUE(pm->registerPackage(path));

  // Only the one with an identifier should be emitted
  EXPECT_EQ(spy.count(), 1);
  EXPECT_EQ(spy.at(0).at(3).toString(), "good");

  pm->unregisterPackage("parse-test");
}

TEST(TomlParsing, invalidTomlSyntaxFails)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QFile f(dir.path() + "/pyproject.toml");
  f.open(QIODevice::WriteOnly | QIODevice::Text);
  f.write("this is not valid [[[toml syntax");
  f.close();

  auto* pm = PackageManager::instance();
  EXPECT_FALSE(pm->registerPackage(dir.path()));
}

TEST(TomlParsing, cacheRoundTrip)
{
  // Verify that data survives a register → load-from-cache round-trip,
  // including nested tables, arrays, and all scalar types.
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());

  QString path = writeToml(dir, R"(
[[tool.avogadro.menu-commands]]
identifier = "roundtrip"
str = "hello"
num = 42
pi = 3.14
flag = true
tags = ["a", "b"]
nested.key = "val"
)");

  auto* pm = PackageManager::instance();

  // Register (writes to QSettings)
  pm->registerPackage(path);

  // Replay from cache
  QSignalSpy spy(pm, &PackageManager::featureRegistered);
  pm->loadRegisteredPackages();

  QVariantMap meta = findFeatureMetadata(spy, "roundtrip");
  ASSERT_FALSE(meta.isEmpty());
  EXPECT_EQ(meta["str"].toString(), "hello");
  // Note: JSON round-trip converts integers to double
  EXPECT_EQ(meta["num"].toInt(), 42);
  EXPECT_DOUBLE_EQ(meta["pi"].toDouble(), 3.14);
  EXPECT_TRUE(meta["flag"].toBool());

  QVariantList tags = meta["tags"].toList();
  ASSERT_EQ(tags.size(), 2);
  EXPECT_EQ(tags[0].toString(), "a");
  EXPECT_EQ(tags[1].toString(), "b");

  QVariantMap nested = meta["nested"].toMap();
  EXPECT_EQ(nested["key"].toString(), "val");

  pm->unregisterPackage("parse-test");
}
