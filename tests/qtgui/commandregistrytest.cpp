/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/commandregistry.h>

#include <QtCore/QJsonArray>
#include <QtGui/QColor>
#include <QtCore/QJsonObject>

#include <cmath>
#include <limits>

using Avogadro::Index;
using Avogadro::Core::Molecule;
using Avogadro::QtGui::CommandArguments;
using Avogadro::QtGui::CommandArgumentSpec;
using Avogadro::QtGui::CommandRegistry;
using Avogadro::QtGui::CommandSpec;

namespace {

/// Five carbons, none bonded; atoms 1 and 3 selected.
Molecule makeMolecule(bool select = true)
{
  Molecule mol;
  for (int i = 0; i < 5; ++i)
    mol.addAtom(6);
  if (select) {
    mol.setAtomSelected(1, true);
    mol.setAtomSelected(3, true);
  }
  return mol;
}

QVariantList list(std::initializer_list<QVariant> values)
{
  return QVariantList(values);
}

/// A registry that records failures and handler calls.
struct Harness
{
  QStringList failures;
  int calls = 0;
  CommandArguments last;
  CommandRegistry registry{ [this](const QString& m) { failures << m; } };

  bool add(const QString& name, std::vector<CommandArgumentSpec> args,
           bool strict = true)
  {
    CommandSpec spec;
    spec.name = name;
    spec.description = QStringLiteral("test");
    spec.arguments = std::move(args);
    spec.allowUnknownOptions = !strict;
    spec.handler = [this](const CommandArguments& a) {
      ++calls;
      last = a;
    };
    return registry.add(std::move(spec));
  }

  // Run and report whether the handler ran.
  bool run(const QString& name, const QVariantMap& options, const Molecule* mol)
  {
    failures.clear();
    const int before = calls;
    EXPECT_TRUE(registry.handle(name, options, mol));
    return calls == before + 1;
  }
};

const QString kName = QStringLiteral("atoms");

} // namespace

TEST(CommandRegistryTest, atomIndicesBasics)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::atomIndices(kName, "a").withCount(2, 4) });

  EXPECT_TRUE(h.run("c", { { kName, list({ 0, 2 }) } }, &mol));
  EXPECT_TRUE(h.failures.isEmpty());
  EXPECT_EQ(h.last.atoms(kName), (std::vector<Index>{ 0, 2 }));
  EXPECT_TRUE(h.last.has(kName));

  // doubles and qlonglong are fine when integer-valued
  EXPECT_TRUE(
    h.run("c", { { kName, list({ 4.0, QVariant::fromValue<qlonglong>(1) }) } },
          &mol));
  EXPECT_EQ(h.last.atoms(kName), (std::vector<Index>{ 4, 1 }));

  // not a list
  EXPECT_FALSE(h.run("c", { { kName, 3 } }, &mol));
  EXPECT_EQ(h.failures.size(), 1);
  EXPECT_FALSE(h.run("c", { { kName, QStringLiteral("0,1") } }, &mol));
}

TEST(CommandRegistryTest, atomIndexRejections)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::atomIndices(kName, "a") });
  const auto bad = [&](const QVariant& v) {
    return !h.run("c", { { kName, list({ 0, v }) } }, &mol);
  };

  EXPECT_TRUE(bad(true)); // bool is not a number
  EXPECT_NE(h.failures.first().indexOf("#2"), -1);
  EXPECT_TRUE(bad(QStringLiteral("1"))); // numeric strings are not accepted
  EXPECT_TRUE(bad(std::nan("")));
  EXPECT_TRUE(bad(std::numeric_limits<double>::infinity()));
  EXPECT_TRUE(bad(-std::numeric_limits<double>::infinity()));
  EXPECT_TRUE(bad(1.5));
  EXPECT_TRUE(bad(-1));
  EXPECT_NE(h.failures.first().indexOf("negative"), -1);
  EXPECT_TRUE(bad(5)); // one past the end
  EXPECT_NE(h.failures.first().indexOf("out of range"), -1);
  EXPECT_TRUE(bad(1e30));
  EXPECT_TRUE(bad(QVariant()));
  EXPECT_TRUE(bad(0)); // repeated
  EXPECT_NE(h.failures.first().indexOf("repeated"), -1);
  EXPECT_EQ(h.calls, 0);
}

TEST(CommandRegistryTest, atomIndicesCountsAndUnique)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("exact",
        { CommandArgumentSpec::atomIndices(kName, "a").withCount(3, 3) });
  h.add("range",
        { CommandArgumentSpec::atomIndices(kName, "a").withCount(2, 4) });
  h.add("least",
        { CommandArgumentSpec::atomIndices(kName, "a").withCount(1, -1) });
  h.add("dup",
        { CommandArgumentSpec::atomIndices(kName, "a").withUnique(false) });

  EXPECT_TRUE(h.run("exact", { { kName, list({ 0, 1, 2 }) } }, &mol));
  EXPECT_FALSE(h.run("exact", { { kName, list({ 0, 1 }) } }, &mol));
  EXPECT_NE(h.failures.first().indexOf("exactly"), -1);
  EXPECT_FALSE(h.run("exact", { { kName, list({ 0, 1, 2, 3 }) } }, &mol));

  EXPECT_TRUE(h.run("range", { { kName, list({ 0, 1 }) } }, &mol));
  EXPECT_TRUE(h.run("range", { { kName, list({ 0, 1, 2, 3 }) } }, &mol));
  EXPECT_FALSE(h.run("range", { { kName, list({ 0 }) } }, &mol));
  EXPECT_FALSE(h.run("range", { { kName, list({ 0, 1, 2, 3, 4 }) } }, &mol));

  EXPECT_FALSE(h.run("least", { { kName, list({}) } }, &mol));
  EXPECT_TRUE(h.run("least", { { kName, list({ 0, 1, 2, 3, 4 }) } }, &mol));

  EXPECT_TRUE(h.run("dup", { { kName, list({ 2, 2 }) } }, &mol));
  EXPECT_EQ(h.last.atoms(kName), (std::vector<Index>{ 2, 2 }));
}

TEST(CommandRegistryTest, selectionFallback)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("sel", { CommandArgumentSpec::atomIndices(kName, "a")
                   .withCount(1, -1)
                   .withSelectionFallback() });
  h.add("selTwo", { CommandArgumentSpec::atomIndices(kName, "a")
                      .withCount(3, 3)
                      .withSelectionFallback() });

  EXPECT_TRUE(h.run("sel", {}, &mol));
  EXPECT_EQ(h.last.atoms(kName), (std::vector<Index>{ 1, 3 }));

  // explicit wins over the selection
  EXPECT_TRUE(h.run("sel", { { kName, list({ 4 }) } }, &mol));
  EXPECT_EQ(h.last.atoms(kName), (std::vector<Index>{ 4 }));

  // count is enforced on the selection too
  EXPECT_FALSE(h.run("selTwo", {}, &mol));
  EXPECT_EQ(h.failures.size(), 1);

  Molecule none = makeMolecule(false);
  EXPECT_FALSE(h.run("sel", {}, &none));
  EXPECT_EQ(h.failures.size(), 1);
}

TEST(CommandRegistryTest, singleAtomIndex)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::atomIndex("atom", "a").withRequired() });
  EXPECT_TRUE(h.run("c", { { "atom", 4 } }, &mol));
  EXPECT_EQ(h.last.atom("atom"), 4u);
  EXPECT_FALSE(h.run("c", { { "atom", 5 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "atom", true } }, &mol));
  EXPECT_FALSE(h.run("c", { { "atom", -1 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "atom", 0.5 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "atom", QStringLiteral("1") } }, &mol));
  EXPECT_FALSE(h.run("c", {}, &mol));
  EXPECT_NE(h.failures.first().indexOf("required"), -1);
}

TEST(CommandRegistryTest, element)
{
  Harness h;
  h.add("c", { CommandArgumentSpec::element("element", "e") });
  Molecule mol = makeMolecule();

  const auto elementOf = [&](const QVariant& v, unsigned char& z) {
    const bool ok = h.run("c", { { "element", v } }, &mol);
    if (ok)
      z = h.last.element("element");
    return ok;
  };
  unsigned char z = 0;
  EXPECT_TRUE(elementOf(6, z));
  EXPECT_EQ(z, 6);
  EXPECT_TRUE(elementOf(8.0, z));
  EXPECT_EQ(z, 8);
  EXPECT_TRUE(elementOf(QStringLiteral("6"), z)); // numeric string is OK here
  EXPECT_EQ(z, 6);
  EXPECT_TRUE(elementOf(QStringLiteral("C"), z));
  EXPECT_EQ(z, 6);
  EXPECT_TRUE(elementOf(QStringLiteral("Fe"), z));
  EXPECT_EQ(z, 26);
  EXPECT_TRUE(elementOf(1, z));
  EXPECT_EQ(z, 1);

  EXPECT_FALSE(elementOf(0, z));
  EXPECT_FALSE(elementOf(-3, z));
  EXPECT_FALSE(elementOf(1000, z));
  EXPECT_FALSE(elementOf(1e30, z));
  EXPECT_FALSE(elementOf(6.5, z));
  EXPECT_FALSE(elementOf(std::nan(""), z));
  EXPECT_FALSE(elementOf(true, z));
  EXPECT_FALSE(elementOf(QStringLiteral("Zz"), z));
  EXPECT_FALSE(elementOf(QStringLiteral(""), z));
  EXPECT_FALSE(elementOf(QStringLiteral("0"), z));
  EXPECT_FALSE(elementOf(QStringLiteral("nan"), z));
  EXPECT_FALSE(elementOf(QVariantList(), z));

  // the standalone validator
  unsigned char out = 0;
  QString error;
  EXPECT_TRUE(CommandRegistry::parseElement(QStringLiteral("N"), out, error));
  EXPECT_EQ(out, 7);
  EXPECT_FALSE(CommandRegistry::parseElement(0, out, error));
  EXPECT_FALSE(error.isEmpty());
}

TEST(CommandRegistryTest, integerAndReal)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::integer("n", "n").withRange(1, 10),
               CommandArgumentSpec::real("x", "x").withRange(-1.5, 2.5) });

  EXPECT_TRUE(h.run("c", { { "n", 1 }, { "x", -1.5 } }, &mol));
  EXPECT_EQ(h.last.integer("n"), 1);
  EXPECT_DOUBLE_EQ(h.last.real("x"), -1.5);
  EXPECT_TRUE(h.run("c", { { "n", 10.0 }, { "x", 2 } }, &mol));
  EXPECT_EQ(h.last.integer("n"), 10);
  EXPECT_DOUBLE_EQ(h.last.real("x"), 2.0);
  EXPECT_TRUE(h.run("c", { { "n", QVariant::fromValue<qlonglong>(5) } }, &mol));

  EXPECT_FALSE(h.run("c", { { "n", 0 } }, &mol)); // range
  EXPECT_FALSE(h.run("c", { { "n", 11 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "n", 2.5 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "n", true } }, &mol));
  EXPECT_FALSE(h.run("c", { { "n", QStringLiteral("3") } }, &mol));
  EXPECT_FALSE(h.run("c", { { "n", std::nan("") } }, &mol));
  EXPECT_FALSE(h.run("c", { { "n", 1e30 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "x", 2.6 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "x", -1.6 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "x", std::nan("") } }, &mol));
  EXPECT_FALSE(
    h.run("c", { { "x", std::numeric_limits<double>::infinity() } }, &mol));
  EXPECT_FALSE(h.run("c", { { "x", false } }, &mol));
  EXPECT_FALSE(h.run("c", { { "x", QStringLiteral("1.0") } }, &mol));
}

TEST(CommandRegistryTest, stringEnumBool)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c",
        { CommandArgumentSpec::string("s", "s"),
          CommandArgumentSpec::enumeration("mode", "m", { "replace", "add" }),
          CommandArgumentSpec::boolean("flag", "f") });

  EXPECT_TRUE(
    h.run("c", { { "s", "hi" }, { "mode", "add" }, { "flag", true } }, &mol));
  EXPECT_EQ(h.last.string("s"), "hi");
  EXPECT_EQ(h.last.string("mode"), "add");
  EXPECT_TRUE(h.last.boolean("flag"));

  EXPECT_FALSE(h.run("c", { { "s", 3 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "mode", "Add" } }, &mol)); // case-sensitive
  EXPECT_FALSE(h.run("c", { { "mode", "other" } }, &mol));
  EXPECT_FALSE(h.run("c", { { "mode", 1 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "flag", 1 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "flag", "true" } }, &mol));

  // absent optional options are simply not there
  EXPECT_TRUE(h.run("c", {}, &mol));
  EXPECT_FALSE(h.last.has("s"));
  EXPECT_FALSE(h.last.boolean("flag"));
}

TEST(CommandRegistryTest, requiredAndDefaults)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c",
        { CommandArgumentSpec::real("value", "v").withRequired(),
          CommandArgumentSpec::enumeration("mode", "m", { "replace", "add" })
            .withDefault("replace"),
          CommandArgumentSpec::integer("n", "n").withDefault(7) });

  EXPECT_FALSE(h.run("c", {}, &mol));
  EXPECT_NE(h.failures.first().indexOf("value"), -1);

  EXPECT_TRUE(h.run("c", { { "value", 1.0 } }, &mol));
  EXPECT_EQ(h.last.string("mode"), "replace");
  EXPECT_EQ(h.last.integer("n"), 7);
  EXPECT_TRUE(
    h.run("c", { { "value", 1.0 }, { "mode", "add" }, { "n", 2 } }, &mol));
  EXPECT_EQ(h.last.string("mode"), "add");
  EXPECT_EQ(h.last.integer("n"), 2);
}

TEST(CommandRegistryTest, aliases)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::atomIndices(kName, "a")
                 .withAliases({ "indices" }) });

  EXPECT_TRUE(h.run("c", { { "indices", list({ 2, 3 }) } }, &mol));
  EXPECT_EQ(h.last.atoms(kName), (std::vector<Index>{ 2, 3 }));

  EXPECT_FALSE(
    h.run("c", { { "indices", list({ 2 }) }, { kName, list({ 3 }) } }, &mol));
  EXPECT_EQ(h.failures.size(), 1);
  EXPECT_EQ(h.calls, 1); // only the first run reached the handler
}

TEST(CommandRegistryTest, unknownOptions)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("strict", { CommandArgumentSpec::boolean("flag", "f") });
  h.add("loose", { CommandArgumentSpec::boolean("flag", "f") }, false);

  EXPECT_FALSE(h.run("strict", { { "flg", true } }, &mol));
  ASSERT_EQ(h.failures.size(), 1);
  EXPECT_EQ(h.failures.first(),
            QStringLiteral("unknown option \"flg\" for command \"strict\"."));

  EXPECT_TRUE(h.run("loose", { { "flg", true } }, &mol));
  // a known option is still validated
  EXPECT_FALSE(h.run("loose", { { "flag", 1 } }, &mol));
}

TEST(CommandRegistryTest, moleculeHandling)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("needs", {});
  CommandSpec free;
  free.name = "free";
  free.needsMolecule = false;
  free.allowUnknownOptions = true;
  free.arguments = { CommandArgumentSpec::atomIndices(kName, "a"),
                     CommandArgumentSpec::string("s", "s") };
  free.handler = [&](const CommandArguments&) { ++h.calls; };
  ASSERT_TRUE(h.registry.add(free));

  EXPECT_FALSE(h.run("needs", {}, nullptr));
  ASSERT_EQ(h.failures.size(), 1);
  EXPECT_NE(h.failures.first().indexOf("molecule"), -1);
  EXPECT_TRUE(h.run("needs", {}, &mol));

  EXPECT_TRUE(h.run("free", { { "s", "x" } }, nullptr));
  // atom arguments can't be checked without a molecule
  EXPECT_FALSE(h.run("free", { { kName, list({ 0 }) } }, nullptr));
  EXPECT_EQ(h.failures.size(), 1);
}

TEST(CommandRegistryTest, unregisteredAndDuplicate)
{
  Molecule mol = makeMolecule();
  Harness h;
  EXPECT_TRUE(h.add("a", {}));
  EXPECT_TRUE(h.add("b", {}));

  h.failures.clear();
  EXPECT_FALSE(h.registry.handle("nope", {}, &mol));
  EXPECT_TRUE(h.failures.isEmpty());
  EXPECT_EQ(h.calls, 0);

  // first registration wins
  CommandSpec dup;
  dup.name = "a";
  dup.description = "second";
  dup.handler = [](const CommandArguments&) {};
  EXPECT_FALSE(h.registry.add(dup));
  EXPECT_EQ(h.registry.description("a"), "test");
  EXPECT_EQ(h.registry.names(), (QStringList{ "a", "b" }));
  EXPECT_TRUE(h.registry.contains("b"));
  EXPECT_FALSE(h.registry.contains("c"));
  EXPECT_EQ(h.registry.spec("c"), nullptr);
  EXPECT_TRUE(h.registry.schema("c").isEmpty());

  // no callback: failures must not crash
  CommandRegistry quiet;
  CommandSpec spec;
  spec.name = "q";
  spec.handler = [](const CommandArguments&) {};
  quiet.add(spec);
  EXPECT_TRUE(quiet.handle("q", {}, nullptr));
}

TEST(CommandRegistryTest, rejectsConflictingOptionKeys)
{
  Harness h;
  const auto real = [](const char* name) {
    return CommandArgumentSpec::real(name, "x");
  };

  // duplicate argument names
  EXPECT_FALSE(h.add("dupName", { real("x"), real("x") }));
  // alias equal to another argument's name
  EXPECT_FALSE(
    h.add("aliasIsName", { real("x"), real("y").withAliases({ "x" }) }));
  // alias shared by two arguments
  EXPECT_FALSE(h.add("sharedAlias", { real("x").withAliases({ "z" }),
                                      real("y").withAliases({ "z" }) }));
  // alias equal to its own argument's name
  EXPECT_FALSE(h.add("ownName", { real("x").withAliases({ "x" }) }));
  // alias repeated within one argument
  EXPECT_FALSE(h.add("dupAlias", { real("x").withAliases({ "z", "z" }) }));
  // empty argument name or alias
  EXPECT_FALSE(h.add("emptyName", { real("") }));
  EXPECT_FALSE(h.add("emptyAlias", { real("x").withAliases({ "" }) }));

  for (const char* name : { "dupName", "aliasIsName", "sharedAlias", "ownName",
                            "dupAlias", "emptyName", "emptyAlias" })
    EXPECT_FALSE(h.registry.contains(name)) << name;
  EXPECT_TRUE(h.registry.names().isEmpty());

  // distinct keys are still accepted
  EXPECT_TRUE(h.add("ok", { real("x").withAliases({ "a", "b" }),
                            real("y").withAliases({ "c" }) }));
  EXPECT_TRUE(h.registry.contains("ok"));
}

TEST(CommandRegistryTest, announceVisitsCommandsInOrder)
{
  Harness h;
  h.add("b", {});
  h.add("a", {});
  QStringList seen;
  h.registry.announce([&seen](const QString& name, const QString& description) {
    seen << name + ":" + description;
  });
  EXPECT_EQ(seen, (QStringList{ "b:test", "a:test" }));
}

TEST(CommandRegistryTest, handlerReceivesConvertedValues)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::atomIndices(kName, "a").withCount(2, 2),
               CommandArgumentSpec::atomIndex("center", "c"),
               CommandArgumentSpec::element("element", "e"),
               CommandArgumentSpec::integer("n", "n"),
               CommandArgumentSpec::real("x", "x") });
  EXPECT_TRUE(h.run("c",
                    { { kName, list({ 3.0, 0 }) },
                      { "center", 2.0 },
                      { "element", "O" },
                      { "n", 4.0 },
                      { "x", 3 } },
                    &mol));
  EXPECT_EQ(h.last.atoms(kName), (std::vector<Index>{ 3, 0 }));
  EXPECT_EQ(h.last.atom("center"), 2u);
  EXPECT_EQ(h.last.element("element"), 8);
  EXPECT_EQ(h.last.integer("n"), 4);
  EXPECT_DOUBLE_EQ(h.last.real("x"), 3.0);
  EXPECT_EQ(h.last.atoms("missing"), std::vector<Index>());
}

TEST(CommandRegistryTest, schema)
{
  Harness h;
  CommandSpec spec;
  spec.name = "demo";
  spec.description = "A demo.";
  spec.async = true;
  spec.needsMolecule = false;
  spec.arguments = {
    CommandArgumentSpec::atomIndices("atoms", "Atoms.")
      .withCount(2, 4)
      .withAliases({ "indices" })
      .withSelectionFallback(),
    CommandArgumentSpec::element("element", "Element."),
    CommandArgumentSpec::integer("n", "Count.").withRange(1, 9).withDefault(3),
    CommandArgumentSpec::real("value", "Value.").withRequired(),
    CommandArgumentSpec::enumeration("mode", "Mode.", { "a", "b" }),
    CommandArgumentSpec::boolean("flag", "Flag."),
    CommandArgumentSpec::string("name", "Name.")
  };
  spec.handler = [](const CommandArguments&) {};
  ASSERT_TRUE(h.registry.add(spec));

  const QJsonObject s = h.registry.schema("demo");
  EXPECT_EQ(s["type"].toString(), "object");
  EXPECT_EQ(s["description"].toString(), "A demo.");
  EXPECT_EQ(s["additionalProperties"].toBool(true), false);
  EXPECT_EQ(s["x-avogadro-async"].toBool(false), true);
  EXPECT_EQ(s["x-avogadro-needs-molecule"].toBool(true), false);
  EXPECT_EQ(s["required"].toArray(), QJsonArray{ "value" });

  const QJsonObject p = s["properties"].toObject();
  const QJsonObject atoms = p["atoms"].toObject();
  EXPECT_EQ(atoms["type"].toString(), "array");
  EXPECT_EQ(atoms["items"].toObject()["type"].toString(), "integer");
  EXPECT_EQ(atoms["items"].toObject()["minimum"].toInt(-1), 0);
  EXPECT_EQ(atoms["minItems"].toInt(), 2);
  EXPECT_EQ(atoms["maxItems"].toInt(), 4);
  EXPECT_EQ(atoms["uniqueItems"].toBool(false), true);
  EXPECT_EQ(atoms["x-avogadro-default"].toString(), "selection");
  EXPECT_EQ(atoms["description"].toString(), "Atoms.");

  const QJsonObject alias = p["indices"].toObject();
  EXPECT_EQ(alias["deprecated"].toBool(false), true);
  EXPECT_EQ(alias["description"].toString(), "Alias of atoms.");

  const QJsonArray oneOf = p["element"].toObject()["oneOf"].toArray();
  ASSERT_EQ(oneOf.size(), 2);
  EXPECT_EQ(oneOf[0].toObject()["type"].toString(), "integer");
  EXPECT_EQ(oneOf[0].toObject()["minimum"].toInt(), 1);
  EXPECT_GE(oneOf[0].toObject()["maximum"].toInt(), 118);
  EXPECT_EQ(oneOf[1].toObject()["type"].toString(), "string");

  const QJsonObject n = p["n"].toObject();
  EXPECT_EQ(n["type"].toString(), "integer");
  EXPECT_EQ(n["minimum"].toInt(), 1);
  EXPECT_EQ(n["maximum"].toInt(), 9);
  EXPECT_EQ(n["default"].toInt(), 3);

  EXPECT_EQ(p["value"].toObject()["type"].toString(), "number");
  EXPECT_EQ(p["mode"].toObject()["enum"].toArray(), (QJsonArray{ "a", "b" }));
  EXPECT_EQ(p["flag"].toObject()["type"].toString(), "boolean");
  EXPECT_EQ(p["name"].toObject()["type"].toString(), "string");

  // allowUnknownOptions flips additionalProperties
  CommandSpec loose;
  loose.name = "loose";
  loose.allowUnknownOptions = true;
  h.registry.add(loose);
  EXPECT_EQ(h.registry.schema("loose")["additionalProperties"].toBool(false),
            true);
  EXPECT_EQ(
    h.registry.schema("loose")["x-avogadro-needs-molecule"].toBool(false),
    true);
}

TEST(CommandRegistryTest, schemaRequiredAliased)
{
  Harness h;
  CommandSpec spec;
  spec.name = "one";
  spec.handler = [](const CommandArguments&) {};
  spec.arguments = {
    CommandArgumentSpec::atomIndices("atoms", "Atoms.")
      .withCount(2, 4)
      .withRequired()
      .withAliases({ "indices", "ids" }),
    CommandArgumentSpec::real("value", "Value.").withRequired(),
    CommandArgumentSpec::boolean("flag", "Flag.")
  };
  ASSERT_TRUE(h.registry.add(spec));

  const QJsonObject s = h.registry.schema("one");
  // the aliased option is not unconditionally required...
  EXPECT_EQ(s["required"].toArray(), QJsonArray{ "value" });
  EXPECT_FALSE(s.contains("anyOf"));
  // ...exactly one of its names is needed
  const QJsonArray allOf = s["allOf"].toArray();
  ASSERT_EQ(allOf.size(), 1);
  const QJsonArray oneOf = allOf[0].toObject()["oneOf"].toArray();
  ASSERT_EQ(oneOf.size(), 3);
  EXPECT_EQ(oneOf[0].toObject()["required"].toArray(), QJsonArray{ "atoms" });
  EXPECT_EQ(oneOf[1].toObject()["required"].toArray(), QJsonArray{ "indices" });
  EXPECT_EQ(oneOf[2].toObject()["required"].toArray(), QJsonArray{ "ids" });

  // and handle() agrees with the schema
  Molecule mol = makeMolecule();
  EXPECT_TRUE(h.registry.handle(
    "one", { { "indices", list({ 0, 1 }) }, { "value", 1.0 } }, &mol));

  // a command with no aliased option has neither key
  Harness g;
  g.add("plain", { CommandArgumentSpec::real("x", "x").withRequired() });
  EXPECT_FALSE(g.registry.schema("plain").contains("anyOf"));
  EXPECT_FALSE(g.registry.schema("plain").contains("allOf"));
}

TEST(CommandRegistryTest, schemaTwoRequiredAliased)
{
  Harness h;
  CommandSpec spec;
  spec.name = "two";
  spec.handler = [](const CommandArguments&) {};
  spec.arguments = {
    CommandArgumentSpec::atomIndices("atoms", "Atoms.")
      .withRequired()
      .withAliases({ "indices" }),
    CommandArgumentSpec::real("value", "Value.")
      .withRequired()
      .withAliases({ "amount" }),
    CommandArgumentSpec::string("name", "Name.").withRequired()
  };
  ASSERT_TRUE(h.registry.add(spec));

  const QJsonObject s = h.registry.schema("two");
  EXPECT_EQ(s["required"].toArray(), QJsonArray{ "name" });
  EXPECT_FALSE(s.contains("anyOf"));
  const QJsonArray allOf = s["allOf"].toArray();
  ASSERT_EQ(allOf.size(), 2);
  const QJsonArray first = allOf[0].toObject()["oneOf"].toArray();
  ASSERT_EQ(first.size(), 2);
  EXPECT_EQ(first[0].toObject()["required"].toArray(), QJsonArray{ "atoms" });
  EXPECT_EQ(first[1].toObject()["required"].toArray(), QJsonArray{ "indices" });
  const QJsonArray second = allOf[1].toObject()["oneOf"].toArray();
  ASSERT_EQ(second.size(), 2);
  EXPECT_EQ(second[0].toObject()["required"].toArray(), QJsonArray{ "value" });
  EXPECT_EQ(second[1].toObject()["required"].toArray(), QJsonArray{ "amount" });
}

TEST(CommandRegistryTest, schemaOptionalAliased)
{
  Harness h;
  ASSERT_TRUE(h.add("opt", { CommandArgumentSpec::atomIndices("atoms", "Atoms.")
                               .withAliases({ "indices", "ids" }) }));

  const QJsonObject s = h.registry.schema("opt");
  EXPECT_TRUE(s["required"].toArray().isEmpty());
  EXPECT_FALSE(s.contains("anyOf"));
  const QJsonArray allOf = s["allOf"].toArray();
  ASSERT_EQ(allOf.size(), 1);
  const QJsonObject constraint = allOf[0].toObject();
  EXPECT_FALSE(constraint.contains("oneOf"));
  // at most one: no pair of keys may appear together
  const QJsonArray pairs = constraint["not"].toObject()["anyOf"].toArray();
  ASSERT_EQ(pairs.size(), 3);
  EXPECT_EQ(pairs[0].toObject()["required"].toArray(),
            (QJsonArray{ "atoms", "indices" }));
  EXPECT_EQ(pairs[1].toObject()["required"].toArray(),
            (QJsonArray{ "atoms", "ids" }));
  EXPECT_EQ(pairs[2].toObject()["required"].toArray(),
            (QJsonArray{ "indices", "ids" }));
}

TEST(CommandRegistryTest, schemaMixedAliased)
{
  Harness h;
  ASSERT_TRUE(h.add(
    "mix",
    { CommandArgumentSpec::atomIndices("atoms", "Atoms.")
        .withRequired()
        .withAliases({ "indices" }),
      CommandArgumentSpec::real("value", "Value.").withAliases({ "amount" }),
      CommandArgumentSpec::boolean("flag", "Flag.") }));

  const QJsonObject s = h.registry.schema("mix");
  EXPECT_TRUE(s["required"].toArray().isEmpty());
  const QJsonArray allOf = s["allOf"].toArray();
  ASSERT_EQ(allOf.size(), 2);
  // argument order: the required one first, then the optional one
  const QJsonArray oneOf = allOf[0].toObject()["oneOf"].toArray();
  ASSERT_EQ(oneOf.size(), 2);
  EXPECT_EQ(oneOf[1].toObject()["required"].toArray(), QJsonArray{ "indices" });
  const QJsonArray pairs =
    allOf[1].toObject()["not"].toObject()["anyOf"].toArray();
  ASSERT_EQ(pairs.size(), 1);
  EXPECT_EQ(pairs[0].toObject()["required"].toArray(),
            (QJsonArray{ "value", "amount" }));
}

TEST(CommandRegistryTest, schemaAliasCarriesType)
{
  Harness h;
  CommandSpec spec;
  spec.name = "alias";
  spec.handler = [](const CommandArguments&) {};
  spec.arguments = { CommandArgumentSpec::atomIndices("atoms", "Atoms.")
                       .withCount(2, 4)
                       .withAliases({ "indices" }),
                     CommandArgumentSpec::integer("n", "Count.")
                       .withRange(1, 9)
                       .withAliases({ "count" }) };
  ASSERT_TRUE(h.registry.add(spec));

  const QJsonObject p = h.registry.schema("alias")["properties"].toObject();
  const QJsonObject alias = p["indices"].toObject();
  EXPECT_EQ(alias["type"].toString(), "array");
  EXPECT_EQ(alias["items"].toObject()["type"].toString(), "integer");
  EXPECT_EQ(alias["minItems"].toInt(), 2);
  EXPECT_EQ(alias["maxItems"].toInt(), 4);
  EXPECT_EQ(alias["uniqueItems"].toBool(false), true);
  EXPECT_EQ(alias["deprecated"].toBool(false), true);
  EXPECT_EQ(alias["description"].toString(), "Alias of atoms.");

  const QJsonObject count = p["count"].toObject();
  EXPECT_EQ(count["type"].toString(), "integer");
  EXPECT_EQ(count["minimum"].toInt(), 1);
  EXPECT_EQ(count["maximum"].toInt(), 9);
  EXPECT_EQ(count["deprecated"].toBool(false), true);
  EXPECT_EQ(count["description"].toString(), "Alias of n.");
  // the canonical property is not marked deprecated
  EXPECT_FALSE(p["n"].toObject().contains("deprecated"));
}

TEST(CommandRegistryTest, vector3)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::vector3("v", "A vector.") });

  EXPECT_TRUE(h.run("c", { { "v", list({ 1.5, -2.0, 3.25 }) } }, &mol));
  EXPECT_TRUE(h.last.has("v"));
  EXPECT_DOUBLE_EQ(h.last.vector3("v").x(), 1.5);
  EXPECT_DOUBLE_EQ(h.last.vector3("v").y(), -2.0);
  EXPECT_DOUBLE_EQ(h.last.vector3("v").z(), 3.25);

  // integer components, in any integer type
  EXPECT_TRUE(
    h.run("c", { { "v", list({ 1, QVariant::fromValue<qlonglong>(2), 3u }) } },
          &mol));
  EXPECT_DOUBLE_EQ(h.last.vector3("v").y(), 2.0);

  EXPECT_FALSE(h.run("c", { { "v", list({ 1, 2 }) } }, &mol));
  EXPECT_EQ(h.failures.first(),
            QStringLiteral("v must be a list of 3 finite numbers [x, y, z]."));
  EXPECT_FALSE(h.run("c", { { "v", list({ 1, 2, 3, 4 }) } }, &mol));
  EXPECT_FALSE(h.run("c", { { "v", list({}) } }, &mol));
  EXPECT_FALSE(h.run("c", { { "v", 1.0 } }, &mol));
  EXPECT_FALSE(h.run("c", { { "v", QStringLiteral("1,2,3") } }, &mol));
  EXPECT_FALSE(h.run("c", { { "v", list({ 1, true, 3 }) } }, &mol));
  EXPECT_FALSE(
    h.run("c", { { "v", list({ 1, QStringLiteral("2"), 3 }) } }, &mol));
  EXPECT_FALSE(h.run("c", { { "v", list({ 1, std::nan(""), 3 }) } }, &mol));
  EXPECT_FALSE(h.run(
    "c", { { "v", list({ std::numeric_limits<double>::infinity(), 1, 3 }) } },
    &mol));
  EXPECT_FALSE(h.run("c", { { "v", QVariantList{ QVariant(), 1, 2 } } }, &mol));
  EXPECT_FALSE(h.last.has("nothing"));
}

TEST(CommandRegistryTest, vector3DefaultAndSchema)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::vector3("v", "A vector.")
                 .withDefault(list({ 0, 0, 1 })),
               CommandArgumentSpec::vector3("w", "Another.").withRequired() });
  EXPECT_FALSE(h.run("c", {}, &mol)); // w is required
  EXPECT_TRUE(h.run("c", { { "w", list({ 1, 2, 3 }) } }, &mol));
  EXPECT_DOUBLE_EQ(h.last.vector3("v").z(), 1.0); // default applied
  EXPECT_FALSE(h.last.vector3("v").isZero());

  const QJsonObject s = h.registry.schema("c");
  const QJsonObject v = s["properties"].toObject()["v"].toObject();
  EXPECT_EQ(v["type"].toString(), "array");
  EXPECT_EQ(v["items"].toObject()["type"].toString(), "number");
  EXPECT_EQ(v["minItems"].toInt(), 3);
  EXPECT_EQ(v["maxItems"].toInt(), 3);
  EXPECT_EQ(v["description"].toString(), "A vector.");
  EXPECT_EQ(v["default"].toArray(), (QJsonArray{ 0, 0, 1 }));
  EXPECT_EQ(s["required"].toArray(), QJsonArray{ "w" });
}

namespace {
// Run a color option and report whether the handler ran.
bool runColor(Harness& h, const QVariant& value, Molecule* mol)
{
  return h.run("c", { { "c", value } }, mol);
}
} // namespace

TEST(CommandRegistryTest, colorAccepted)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::color("c", "A color.") });

  const struct
  {
    QVariant input;
    int r, g, b;
  } good[] = {
    { QStringLiteral("#f00"), 255, 0, 0 },
    { QStringLiteral("#FF0000"), 255, 0, 0 },
    { QStringLiteral("#Ff8000"), 255, 128, 0 },
    { QStringLiteral("red"), 255, 0, 0 },
    { QStringLiteral("steelblue"), 70, 130, 180 },
    { list({ 255, 0, 0 }), 255, 0, 0 },
    { list({ 0.0, 128.0, 255.0 }), 0, 128, 255 },
  };
  for (const auto& c : good) {
    ASSERT_TRUE(runColor(h, c.input, &mol)) << c.input.toString().toStdString();
    const QColor color = h.last.color("c");
    EXPECT_EQ(color.red(), c.r);
    EXPECT_EQ(color.green(), c.g);
    EXPECT_EQ(color.blue(), c.b);
    EXPECT_EQ(color.alpha(), 255);
    EXPECT_TRUE(h.last.has("c"));
  }
}

TEST(CommandRegistryTest, colorRejected)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::color("c", "A color.") });

  const QVariant bad[] = { QStringLiteral("notacolor"),
                           QStringLiteral(""),
                           QStringLiteral("#"),
                           QStringLiteral("#12"),
                           QStringLiteral("#ggg"),
                           QStringLiteral("#ff00008"),
                           QStringLiteral("#ff0000800"),
                           QStringLiteral("transparent"), // alpha not allowed
                           list({ 255, 0, 0, 128 }),
                           list({ 1.5, 0, 0 }),
                           list({ 256, 0, 0 }),
                           list({ -1, 0, 0 }),
                           list({ true, 0, 0 }),
                           list({ QStringLiteral("1"), 0, 0 }),
                           list({ std::nan(""), 0, 0 }),
                           list({ 255, 0 }),
                           list({}),
                           255,
                           true,
                           QVariant() };
  for (const QVariant& value : bad) {
    EXPECT_FALSE(runColor(h, value, &mol)) << value.toString().toStdString();
    ASSERT_EQ(h.failures.size(), 1);
  }

  runColor(h, QStringLiteral("nope"), &mol);
  EXPECT_EQ(h.failures.first(),
            QStringLiteral("c must be a color: \"#RRGGBB\", a color name, or "
                           "[r, g, b] with values 0-255."));
  // 8- and 4-digit hex have a dedicated message without alpha
  for (const char* text : { "#ff000080", "#f008" }) {
    EXPECT_FALSE(runColor(h, QString(text), &mol)) << text;
    EXPECT_EQ(h.failures.first(),
              QStringLiteral("c does not take an alpha channel; give "
                             "\"#RRGGBB\" or [r, g, b]."));
  }
}

TEST(CommandRegistryTest, colorWithAlpha)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::color("c", "A color.").withAlpha() });

  ASSERT_TRUE(
    runColor(h, QStringLiteral("#ff000080"), &mol)); // CSS: alpha last
  QColor c = h.last.color("c");
  EXPECT_EQ(c.red(), 255);
  EXPECT_EQ(c.green(), 0);
  EXPECT_EQ(c.blue(), 0);
  EXPECT_EQ(c.alpha(), 128);

  ASSERT_TRUE(runColor(h, QStringLiteral("#f008"), &mol));
  EXPECT_EQ(h.last.color("c").alpha(), 136); // 0x88
  EXPECT_EQ(h.last.color("c").red(), 255);

  ASSERT_TRUE(runColor(h, list({ 255, 0, 0, 128 }), &mol));
  EXPECT_EQ(h.last.color("c").alpha(), 128);
  ASSERT_TRUE(runColor(h, list({ 1, 2, 3 }), &mol));
  EXPECT_EQ(h.last.color("c").alpha(), 255);
  ASSERT_TRUE(runColor(h, QStringLiteral("transparent"), &mol));
  EXPECT_EQ(h.last.color("c").alpha(), 0);

  EXPECT_FALSE(runColor(h, QStringLiteral("#ff00008"), &mol));   // 7 digits
  EXPECT_FALSE(runColor(h, QStringLiteral("#ff0000800"), &mol)); // 9 digits
  EXPECT_FALSE(runColor(h, list({ 1, 2, 3, 256 }), &mol));
  EXPECT_FALSE(runColor(h, list({ 1, 2, 3, 4, 5 }), &mol));
  EXPECT_EQ(h.failures.first(),
            QStringLiteral("c must be a color: \"#RRGGBB\", a color name, or "
                           "[r, g, b, a] with values 0-255."));
}

TEST(CommandRegistryTest, colorDefaultAndSchema)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c",
        { CommandArgumentSpec::color("plain", "Plain.").withDefault("#00ff00"),
          CommandArgumentSpec::color("alpha", "Alpha.").withAlpha() });
  EXPECT_TRUE(h.run("c", {}, &mol));
  EXPECT_EQ(h.last.color("plain").green(), 255);
  EXPECT_FALSE(h.last.has("alpha"));

  const QJsonObject props = h.registry.schema("c")["properties"].toObject();
  const QJsonObject plain = props["plain"].toObject();
  const QJsonArray plainOne = plain["oneOf"].toArray();
  ASSERT_EQ(plainOne.size(), 2);
  EXPECT_EQ(plainOne[0].toObject()["type"].toString(), "string");
  EXPECT_EQ(plainOne[0].toObject()["x-avogadro-format"].toString(), "color");
  EXPECT_FALSE(plainOne[0].toObject().contains("x-avogadro-hex-order"));
  const QJsonObject list3 = plainOne[1].toObject();
  EXPECT_EQ(list3["type"].toString(), "array");
  EXPECT_EQ(list3["minItems"].toInt(), 3);
  EXPECT_EQ(list3["maxItems"].toInt(), 3);
  EXPECT_EQ(list3["items"].toObject()["type"].toString(), "integer");
  EXPECT_EQ(list3["items"].toObject()["minimum"].toInt(-1), 0);
  EXPECT_EQ(list3["items"].toObject()["maximum"].toInt(), 255);
  EXPECT_EQ(plain["default"].toString(), "#00ff00");
  EXPECT_EQ(plain["description"].toString(), "Plain.");

  const QJsonArray alphaOne = props["alpha"].toObject()["oneOf"].toArray();
  EXPECT_EQ(alphaOne[0].toObject()["x-avogadro-hex-order"].toString(),
            "RRGGBBAA");
  EXPECT_EQ(alphaOne[1].toObject()["maxItems"].toInt(), 4);
}

TEST(CommandRegistryTest, unitInMessagesAndSchema)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c",
        { CommandArgumentSpec::real("x", "x").withRange(0.5, 180).withUnit("°"),
          CommandArgumentSpec::integer("n", "n").withRange(1, 3) });
  EXPECT_FALSE(h.run("c", { { "x", 0.1 } }, &mol));
  EXPECT_EQ(h.failures.first(), QString::fromUtf8("x must be at least 0.5°."));
  EXPECT_FALSE(h.run("c", { { "x", 181 } }, &mol));
  EXPECT_EQ(h.failures.first(), QString::fromUtf8("x must be at most 180°."));
  // no unit: the message is unchanged
  EXPECT_FALSE(h.run("c", { { "n", 4 } }, &mol));
  EXPECT_EQ(h.failures.first(), QStringLiteral("n must be at most 3."));

  const QJsonObject props = h.registry.schema("c")["properties"].toObject();
  EXPECT_EQ(props["x"].toObject()["x-avogadro-unit"].toString(),
            QString::fromUtf8("°"));
  EXPECT_FALSE(props["n"].toObject().contains("x-avogadro-unit"));
}

TEST(CommandRegistryTest, unitSpacing)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c", { CommandArgumentSpec::real("len", "x")
                 .withRange(std::nullopt, 10)
                 .withUnit("Å"),
               CommandArgumentSpec::real("ang", "x")
                 .withRange(std::nullopt, 180)
                 .withUnit("°"),
               CommandArgumentSpec::real("arc", "x")
                 .withRange(std::nullopt, 59)
                 .withUnit("′"),
               CommandArgumentSpec::real("sec", "x")
                 .withRange(std::nullopt, 59)
                 .withUnit("″") });
  // SI-style units take a space...
  EXPECT_FALSE(h.run("c", { { "len", 11 } }, &mol));
  EXPECT_EQ(h.failures.first(), QString::fromUtf8("len must be at most 10 Å."));
  // ...angle symbols do not.
  EXPECT_FALSE(h.run("c", { { "ang", 181 } }, &mol));
  EXPECT_EQ(h.failures.first(), QString::fromUtf8("ang must be at most 180°."));
  EXPECT_FALSE(h.run("c", { { "arc", 60 } }, &mol));
  EXPECT_EQ(h.failures.first(), QString::fromUtf8("arc must be at most 59′."));
  EXPECT_FALSE(h.run("c", { { "sec", 60 } }, &mol));
  EXPECT_EQ(h.failures.first(), QString::fromUtf8("sec must be at most 59″."));
}

TEST(CommandRegistryTest, vector3Unit)
{
  Molecule mol = makeMolecule();
  Harness h;
  h.add("c",
        { CommandArgumentSpec::vector3("pos", "Position.").withUnit("Å") });
  EXPECT_FALSE(h.run("c", { { "pos", list({ 1, 2 }) } }, &mol));
  EXPECT_EQ(h.failures.first(),
            QString::fromUtf8(
              "pos must be a list of 3 finite numbers [x, y, z] in Å."));
  EXPECT_EQ(h.registry.schema("c")["properties"]
              .toObject()["pos"]
              .toObject()["x-avogadro-unit"]
              .toString(),
            QString::fromUtf8("Å"));
}
