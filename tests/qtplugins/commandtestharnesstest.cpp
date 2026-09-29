/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Checks the harness itself: a deliberately misbehaving plugin must produce
// the violations the harness promises to catch.

#include "commandtestharness.h"

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QTimer>

#include <gtest/gtest.h>

using Avogadro::Vector3;
using Avogadro::QtGui::ExtensionPlugin;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;

namespace {

// No Q_OBJECT: it adds no signals or slots of its own.
class MisbehavingPlugin : public ExtensionPlugin
{
public:
  QString name() const override { return QStringLiteral("Misbehaving"); }
  QString description() const override { return name(); }
  QList<QAction*> actions() const override { return {}; }
  QStringList menuPath(QAction*) const override { return {}; }
  void setMolecule(Avogadro::QtGui::Molecule* mol) override
  {
    m_molecule = mol;
  }

  bool handleCommand(const QString& command, const QVariantMap&) override
  {
    if (command == "neverEnds") {
      emit commandStarted();
      return true;
    }
    if (command == "endsTwice") {
      emit commandStarted();
      QTimer::singleShot(0, this, [this]() {
        emit commandFinished();
        emit commandFailed();
      });
      return true;
    }
    if (command == "mutatesAfterFailure") {
      emit commandStarted();
      QTimer::singleShot(0, this, [this]() {
        emit commandFailed(QStringLiteral("gave up"));
        if (m_molecule != nullptr && m_molecule->atomCount() > 0)
          m_molecule->setAtomPosition3d(0, Vector3(9.0, 9.0, 9.0));
      });
      return true;
    }
    if (command == "disownsButSignals") {
      emit commandFailed();
      return false;
    }
    return false;
  }

private:
  Avogadro::QtGui::Molecule* m_molecule = nullptr;
};

bool hasViolation(const CommandOutcome& out, const char* fragment)
{
  for (const QString& v : out.violations) {
    if (v.contains(QLatin1String(fragment)))
      return true;
  }
  return false;
}

} // namespace

TEST(CommandTestHarnessTest, detectsCommandThatNeverTerminates)
{
  MisbehavingPlugin plugin;
  CommandTestHarness harness(200);
  harness.buildMethanol();
  harness.attach(&plugin);

  const CommandOutcome out = harness.run("neverEnds");
  EXPECT_EQ(out.status, CommandStatus::TimedOut);
  EXPECT_TRUE(hasViolation(out, "never terminated"))
    << out.violations.join("; ").toStdString();
}

TEST(CommandTestHarnessTest, detectsCommandThatTerminatesTwice)
{
  MisbehavingPlugin plugin;
  CommandTestHarness harness(200);
  harness.buildMethanol();
  harness.attach(&plugin);

  const CommandOutcome out = harness.run("endsTwice");
  // The first terminal signal decides, as in MainWindow.
  EXPECT_EQ(out.status, CommandStatus::Finished);
  EXPECT_TRUE(hasViolation(out, "terminated 2 times"))
    << out.violations.join("; ").toStdString();
}

TEST(CommandTestHarnessTest, detectsMutationAfterFailure)
{
  MisbehavingPlugin plugin;
  CommandTestHarness harness(200);
  harness.buildMethanol();
  harness.attach(&plugin);

  const CommandOutcome out = harness.run("mutatesAfterFailure");
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QStringLiteral("gave up"));
  EXPECT_TRUE(hasViolation(out, "mutated after commandFailed()"))
    << out.violations.join("; ").toStdString();
}

TEST(CommandTestHarnessTest, detectsSignalsFromUnclaimedCommand)
{
  MisbehavingPlugin plugin;
  CommandTestHarness harness(200);
  harness.buildMethanol();
  harness.attach(&plugin);

  const CommandOutcome out = harness.run("disownsButSignals");
  EXPECT_EQ(out.status, CommandStatus::NotHandled);
  EXPECT_TRUE(hasViolation(out, "returned false"))
    << out.violations.join("; ").toStdString();
}
