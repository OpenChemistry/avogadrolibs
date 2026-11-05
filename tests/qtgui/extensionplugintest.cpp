/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/commandregistry.h>
#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/toolplugin.h>

#include <QtCore/QCoreApplication>

using Avogadro::QtGui::CommandArguments;
using Avogadro::QtGui::CommandArgumentSpec;
using Avogadro::QtGui::CommandSpec;
using Avogadro::QtGui::ExtensionPlugin;
using Avogadro::QtGui::ToolPlugin;

namespace {

class TrivialExtension : public ExtensionPlugin
{
public:
  QString name() const override { return "Trivial"; }
  QString description() const override { return "Trivial"; }
  QList<QAction*> actions() const override { return {}; }
  QStringList menuPath(QAction*) const override { return {}; }
  void setMolecule(Avogadro::QtGui::Molecule* mol) override
  {
    m_molecule = mol;
  }

  void addCommands()
  {
    for (const char* name : { "first", "second" }) {
      CommandSpec spec;
      spec.name = name;
      spec.description = QString("does ") + name;
      spec.arguments = { CommandArgumentSpec::integer("n", "n") };
      spec.handler = [this](const CommandArguments& args) {
        emit commandFinished(QString(), { { "n", args.integer("n") } });
      };
      commandRegistry().add(spec);
    }
  }

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override
  {
    return commandRegistry().handle(command, options, m_molecule);
  }

  Avogadro::QtGui::Molecule* m_molecule = nullptr;
};

class TrivialTool : public ToolPlugin
{
public:
  QString name() const override { return "Trivial"; }
  QString description() const override { return "Trivial"; }
  unsigned char priority() const override { return 0; }
  QAction* activateAction() const override { return nullptr; }
  void setIcon(bool) override {}
  QWidget* toolWidget() const override { return nullptr; }
  void setMolecule(Avogadro::QtGui::Molecule*) override {}
  void addCommand()
  {
    CommandSpec spec;
    spec.name = "toolCommand";
    spec.needsMolecule = false;
    spec.handler = [](const CommandArguments&) {};
    commandRegistry().add(spec);
  }
};

} // namespace

TEST(ExtensionPluginTest, defaultsWithoutRegistry)
{
  TrivialExtension plugin;
  int registered = 0;
  QObject::connect(&plugin, &ExtensionPlugin::registerCommand,
                   [&](QString, QString) { ++registered; });
  plugin.registerCommands();
  EXPECT_EQ(registered, 0);
  EXPECT_TRUE(plugin.commandSchema("anything").isEmpty());
  EXPECT_FALSE(plugin.handleCommand("anything", {}));
}

TEST(ExtensionPluginTest, registryDrivesRegisterCommandsAndSchema)
{
  TrivialExtension plugin;
  plugin.addCommands();

  QStringList names;
  QStringList descriptions;
  QObject::connect(&plugin, &ExtensionPlugin::registerCommand,
                   [&](QString name, QString description) {
                     names << name;
                     descriptions << description;
                   });
  plugin.registerCommands();
  EXPECT_EQ(names, QStringList({ "first", "second" }));
  EXPECT_EQ(descriptions, QStringList({ "does first", "does second" }));

  EXPECT_TRUE(
    plugin.commandSchema("first")["properties"].toObject().contains("n"));
  EXPECT_TRUE(plugin.commandSchema("nope").isEmpty());

  // Failures from the registry arrive as commandFailed().
  QStringList failures;
  QStringList finished;
  QObject::connect(&plugin, &ExtensionPlugin::commandFailed,
                   [&](QString m) { failures << m; });
  QObject::connect(
    &plugin, &ExtensionPlugin::commandFinished,
    [&](QString, QVariantMap r) { finished << r["n"].toString(); });
  Avogadro::QtGui::Molecule mol;
  plugin.setMolecule(&mol);
  EXPECT_TRUE(plugin.handleCommand("first", { { "n", 3 } }));
  EXPECT_EQ(finished, QStringList({ "3" }));
  EXPECT_TRUE(plugin.handleCommand("first", { { "bad", 3 } }));
  EXPECT_EQ(failures.size(), 1);
  EXPECT_FALSE(plugin.handleCommand("third", {}));
}

TEST(ExtensionPluginTest, toolPluginHasTheSameHooks)
{
  TrivialTool tool;
  EXPECT_TRUE(tool.commandSchema("toolCommand").isEmpty());
  tool.addCommand();
  QStringList names;
  QObject::connect(&tool, &ToolPlugin::registerCommand,
                   [&](QString name, QString) { names << name; });
  tool.registerCommands();
  EXPECT_EQ(names, QStringList({ "toolCommand" }));
  EXPECT_FALSE(tool.commandSchema("toolCommand").isEmpty());
}
