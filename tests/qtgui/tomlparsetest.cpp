/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/tomlparse.h>

#include <QDate>
#include <QDateTime>
#include <QJsonObject>
#include <QString>
#include <QTime>
#include <QTimeZone>
#include <QVariantList>
#include <QVariantMap>

using Avogadro::QtGui::parseTomlString;
using Avogadro::QtGui::parseTomlToJson;

class TomlParseTest : public ::testing::Test
{};

// --- One test per type mapping documented in tomlparse.h -------------------

TEST_F(TomlParseTest, StringType)
{
  bool ok = false;
  auto map = parseTomlString(std::string_view("s = \"hello\"\n"), &ok);
  ASSERT_TRUE(ok);
  ASSERT_TRUE(map.contains("s"));
  EXPECT_EQ(map.value("s").typeId(), QMetaType::QString);
  EXPECT_EQ(map.value("s").toString(), QStringLiteral("hello"));
}

TEST_F(TomlParseTest, IntegerType)
{
  bool ok = false;
  auto map = parseTomlString(std::string_view("i = -42\n"), &ok);
  ASSERT_TRUE(ok);
  EXPECT_EQ(map.value("i").typeId(), QMetaType::LongLong);
  EXPECT_EQ(map.value("i").toLongLong(), -42);
}

TEST_F(TomlParseTest, FloatType)
{
  bool ok = false;
  auto map = parseTomlString(std::string_view("f = 3.5\n"), &ok);
  ASSERT_TRUE(ok);
  EXPECT_EQ(map.value("f").typeId(), QMetaType::Double);
  EXPECT_DOUBLE_EQ(map.value("f").toDouble(), 3.5);
}

TEST_F(TomlParseTest, BooleanType)
{
  bool ok = false;
  auto map = parseTomlString(std::string_view("b = true\n"), &ok);
  ASSERT_TRUE(ok);
  EXPECT_EQ(map.value("b").typeId(), QMetaType::Bool);
  EXPECT_TRUE(map.value("b").toBool());
}

TEST_F(TomlParseTest, DateType)
{
  bool ok = false;
  auto map = parseTomlString(std::string_view("d = 2026-09-22\n"), &ok);
  ASSERT_TRUE(ok);
  EXPECT_EQ(map.value("d").typeId(), QMetaType::QDate);
  EXPECT_EQ(map.value("d").toDate(), QDate(2026, 9, 22));
}

TEST_F(TomlParseTest, TimeType)
{
  bool ok = false;
  auto map = parseTomlString(std::string_view("t = 13:45:30\n"), &ok);
  ASSERT_TRUE(ok);
  EXPECT_EQ(map.value("t").typeId(), QMetaType::QTime);
  EXPECT_EQ(map.value("t").toTime(), QTime(13, 45, 30));
}

TEST_F(TomlParseTest, DatetimeType)
{
  bool ok = false;
  auto map =
    parseTomlString(std::string_view("dt = 2026-09-22T13:45:30Z\n"), &ok);
  ASSERT_TRUE(ok);
  EXPECT_EQ(map.value("dt").typeId(), QMetaType::QDateTime);
  // Matches how tomlparse.cpp itself builds an offset datetime: "Z" is an
  // explicit zero-minute offset, not the special Qt::UTC spec.
  QDateTime expected(QDate(2026, 9, 22), QTime(13, 45, 30),
                     QTimeZone::fromSecondsAheadOfUtc(0));
  EXPECT_EQ(map.value("dt").toDateTime(), expected);
}

TEST_F(TomlParseTest, ArrayType)
{
  bool ok = false;
  auto map = parseTomlString(std::string_view("a = [1, 2, 3]\n"), &ok);
  ASSERT_TRUE(ok);
  ASSERT_EQ(map.value("a").typeId(), QMetaType::QVariantList);
  auto list = map.value("a").toList();
  ASSERT_EQ(list.size(), 3);
  EXPECT_EQ(list.at(0).toLongLong(), 1);
  EXPECT_EQ(list.at(2).toLongLong(), 3);
}

TEST_F(TomlParseTest, TableType)
{
  bool ok = false;
  auto map =
    parseTomlString(std::string_view("[table]\nkey = \"value\"\n"), &ok);
  ASSERT_TRUE(ok);
  ASSERT_EQ(map.value("table").typeId(), QMetaType::QVariantMap);
  auto table = map.value("table").toMap();
  EXPECT_EQ(table.value("key").toString(), QStringLiteral("value"));
}

TEST_F(TomlParseTest, NestedTables)
{
  bool ok = false;
  auto map =
    parseTomlString(std::string_view("[a]\n[a.b]\n[a.b.c]\nleaf = 7\n"), &ok);
  ASSERT_TRUE(ok);
  auto a = map.value("a").toMap();
  auto b = a.value("b").toMap();
  auto c = b.value("c").toMap();
  EXPECT_EQ(c.value("leaf").toLongLong(), 7);
}

TEST_F(TomlParseTest, ArrayOfTables)
{
  bool ok = false;
  auto map = parseTomlString(
    std::string_view(
      "[[items]]\nname = \"first\"\n[[items]]\nname = \"second\"\n"),
    &ok);
  ASSERT_TRUE(ok);
  auto items = map.value("items").toList();
  ASSERT_EQ(items.size(), 2);
  EXPECT_EQ(items.at(0).toMap().value("name").toString(),
            QStringLiteral("first"));
  EXPECT_EQ(items.at(1).toMap().value("name").toString(),
            QStringLiteral("second"));
}

// --- Empty / whitespace / comments-only input -------------------------------

TEST_F(TomlParseTest, EmptyInput_OkTrueEmptyMap)
{
  bool ok = false;
  auto map = parseTomlString(std::string_view(""), &ok);
  EXPECT_TRUE(ok);
  EXPECT_TRUE(map.isEmpty());
}

TEST_F(TomlParseTest, WhitespaceOnlyInput_OkTrueEmptyMap)
{
  bool ok = false;
  auto map = parseTomlString(std::string_view("   \n\t\n  \n"), &ok);
  EXPECT_TRUE(ok);
  EXPECT_TRUE(map.isEmpty());
}

TEST_F(TomlParseTest, CommentsOnlyInput_OkTrueEmptyMap)
{
  bool ok = false;
  auto map =
    parseTomlString(std::string_view("# just a comment\n# another one\n"), &ok);
  EXPECT_TRUE(ok);
  EXPECT_TRUE(map.isEmpty());
}

// --- Malformed input ---------------------------------------------------------

TEST_F(TomlParseTest, UnterminatedString_OkFalseEmptyMap)
{
  bool ok = true;
  auto map = parseTomlString(std::string_view("s = \"unterminated\n"), &ok);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(map.isEmpty());
}

TEST_F(TomlParseTest, DuplicateKey_OkFalseEmptyMap)
{
  bool ok = true;
  auto map = parseTomlString(std::string_view("a = 1\na = 2\n"), &ok);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(map.isEmpty());
}

TEST_F(TomlParseTest, BadTableHeader_OkFalseEmptyMap)
{
  bool ok = true;
  auto map = parseTomlString(std::string_view("[table\nkey = 1\n"), &ok);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(map.isEmpty());
}

TEST_F(TomlParseTest, InvalidUtf8Bytes_OkFalseEmptyMapNoCrash)
{
  bool ok = true;
  // 0xFF is not valid UTF-8 anywhere; embed it in an otherwise plausible
  // document so the decoder actually has to reject the byte.
  std::string content = "s = \"bad\xFF byte\"\n";
  auto map = parseTomlString(std::string_view(content), &ok);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(map.isEmpty());
}

// --- Overloads ---------------------------------------------------------------

TEST_F(TomlParseTest, NullOkPointer_DoesNotCrashOnSuccess)
{
  auto map = parseTomlString(std::string_view("a = 1\n"), nullptr);
  EXPECT_EQ(map.value("a").toLongLong(), 1);
}

TEST_F(TomlParseTest, NullOkPointer_DoesNotCrashOnFailure)
{
  auto map = parseTomlString(std::string_view("a = [1, 2\n"), nullptr);
  EXPECT_TRUE(map.isEmpty());
}

TEST_F(TomlParseTest, QStringOverload_NonAsciiText)
{
  bool ok = false;
  QString content = QStringLiteral("name = \"café αβγ\"\n");
  auto map = parseTomlString(content, &ok);
  ASSERT_TRUE(ok);
  EXPECT_EQ(map.value("name").toString(),
            QString::fromUtf8("caf\xc3\xa9 \xce\xb1\xce\xb2\xce\xb3"));
}

TEST_F(TomlParseTest, ToJson_MirrorsVariantMap)
{
  bool ok = false;
  QByteArray content = "[tool.avogadro]\nkey = 1\n";
  QJsonObject obj = parseTomlToJson(content, &ok);
  ASSERT_TRUE(ok);
  ASSERT_TRUE(obj.contains("tool"));
  QJsonObject tool = obj.value("tool").toObject();
  QJsonObject avogadro = tool.value("avogadro").toObject();
  EXPECT_EQ(avogadro.value("key").toInt(), 1);
}

TEST_F(TomlParseTest, ToJson_FailureReturnsEmptyObject)
{
  bool ok = true;
  QByteArray content = "not [ valid toml\n";
  QJsonObject obj = parseTomlToJson(content, &ok);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(obj.isEmpty());
}

// --- A realistic pyproject.toml / pixi.toml pair ----------------------------
// Trimmed from a real Avogadro plugin (avogadro-mace/pyproject.toml), which
// combines a [tool.avogadro] section with an array of energy-model tables
// and a [tool.pixi.*] section, exactly as Avogadro plugins ship them.

TEST_F(TomlParseTest, RealisticPyprojectToml)
{
  static const char kPyproject[] = R"toml(
[project]
authors = [{name = "Geoffrey Hutchison", email = "geoff.hutchison@gmail.com"}]
dependencies = ["avogadro>=2.0", "mace-torch>=0.3.15,<0.4"]
name = "avogadro-mace"
requires-python = ">= 3.11"
version = "0.1.0"
license = "BSD-3-Clause"
description = "Energy model using MACE ML potentials"

[project.scripts]
avogadro-mace = "avogadro_mace:main"

[build-system]
build-backend = "hatchling.build"
requires = ["hatchling"]

[tool.avogadro]
minimum-avogadro-version = "1.103"

[[tool.avogadro.energy-models]]
identifier = "MACE-MP-0"
model-name = "MACE-MP-0"
input-format = "cjson"
protocol = "binary-v1"
support.gradients = true
support.elements = "1-89"

[[tool.avogadro.energy-models]]
identifier = "MACE-OFF23"
model-name = "MACE-OFF23"
input-format = "cjson"
protocol = "binary-v1"
support.gradients = true
support.elements = "1, 6, 7, 8, 9, 15, 16, 17, 35, 53"

[tool.pixi.workspace]
channels = ["conda-forge"]
platforms = ["win-64", "linux-64", "linux-aarch64", "osx-arm64"]

[tool.pixi.pypi-dependencies]
avogadro_mace = { path = ".", editable = true }

[tool.pixi.tasks]
)toml";

  bool ok = false;
  auto map = parseTomlString(std::string_view(kPyproject), &ok);
  ASSERT_TRUE(ok);

  EXPECT_EQ(map.value("project").toMap().value("name").toString(),
            QStringLiteral("avogadro-mace"));

  auto authors = map.value("project").toMap().value("authors").toList();
  ASSERT_EQ(authors.size(), 1);
  EXPECT_EQ(authors.at(0).toMap().value("email").toString(),
            QStringLiteral("geoff.hutchison@gmail.com"));

  auto tool = map.value("tool").toMap();
  EXPECT_EQ(
    tool.value("avogadro").toMap().value("minimum-avogadro-version").toString(),
    QStringLiteral("1.103"));

  auto energyModels =
    tool.value("avogadro").toMap().value("energy-models").toList();
  ASSERT_EQ(energyModels.size(), 2);
  EXPECT_EQ(energyModels.at(0).toMap().value("identifier").toString(),
            QStringLiteral("MACE-MP-0"));
  EXPECT_TRUE(energyModels.at(1)
                .toMap()
                .value("support")
                .toMap()
                .value("gradients")
                .toBool());

  auto pixi = tool.value("pixi").toMap();
  auto platforms = pixi.value("workspace").toMap().value("platforms").toList();
  ASSERT_EQ(platforms.size(), 4);
  EXPECT_EQ(platforms.at(0).toString(), QStringLiteral("win-64"));

  // [tool.pixi.tasks] declared with no keys: still a (empty) table.
  EXPECT_EQ(pixi.value("tasks").typeId(), QMetaType::QVariantMap);
  EXPECT_TRUE(pixi.value("tasks").toMap().isEmpty());
}

// --- Deep nesting must not overflow the stack -------------------------------

TEST_F(TomlParseTest, DeeplyNestedArray_DoesNotOverflowStack)
{
  // 10,000 nested arrays, e.g. a = [[[[...]]]]. tomlplusplus enforces
  // TOML_MAX_NESTED_VALUES (256 by default) and raises a parse_error once
  // exceeded, well before the recursive-descent parser could recurse deep
  // enough to overflow a normal thread stack.
  std::string content = "a = ";
  content.reserve(content.size() + 2 * 10000 + 8);
  for (int i = 0; i < 10000; ++i)
    content += '[';
  content += '1';
  for (int i = 0; i < 10000; ++i)
    content += ']';
  content += '\n';

  bool ok = true;
  auto map = parseTomlString(std::string_view(content), &ok);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(map.isEmpty());
}
