/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/interfacescript.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QJsonObject>
#include <QtCore/QTemporaryDir>
#include <QtTest/QSignalSpy>

using Avogadro::QtGui::InterfaceScript;

namespace {

// Ensure a QCoreApplication exists (required to run an event loop while the
// script executes). The test binary uses gtest_main, which does not create one.
QCoreApplication* ensureApp()
{
  if (QCoreApplication::instance())
    return QCoreApplication::instance();
  static int argc = 1;
  static char name[] = "InterfaceScriptTest";
  static char* argv[] = { name, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

} // namespace

TEST(InterfaceScriptTest, RerunDeliversSignalsOnce)
{
  ensureApp();

  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());

  // A minimal command script: one progress envelope, then a result.
  QFile script(temporaryDirectory.filePath("command.py"));
  ASSERT_TRUE(script.open(QIODevice::WriteOnly | QIODevice::Text));
  const QByteArray source(
    "import json, sys\n"
    "sys.stdin.read()\n"
    "print(json.dumps({'avogadro': {'message': 'Working', 'value': 1,"
    " 'maximum': 1}}), flush=True)\n"
    "print(json.dumps({'moleculeFormat': 'cjson'}))\n");
  ASSERT_EQ(script.write(source), source.size());
  script.close();

  InterfaceScript interface(script.fileName());
  // Skip the --print-options round trip; "None" means the molecule is not
  // serialized into the options at all.
  QJsonObject opts;
  opts.insert(QStringLiteral("inputMoleculeFormat"), QStringLiteral("None"));
  interface.setOptionsJson(opts);

  Avogadro::Core::Molecule molecule;

  QSignalSpy finishedSpy(&interface, &InterfaceScript::finished);
  QSignalSpy progressSpy(&interface, &InterfaceScript::progress);

  // First run.
  ASSERT_TRUE(interface.runCommand(QJsonObject(), &molecule));
  ASSERT_TRUE(finishedSpy.wait(30000));
  EXPECT_EQ(finishedSpy.count(), 1);
  EXPECT_EQ(progressSpy.count(), 1);

  // Second run on the same instance. Re-connecting the interpreter's signals
  // must not stack duplicate connections, or each signal would be delivered
  // once per previous run.
  finishedSpy.clear();
  progressSpy.clear();
  ASSERT_TRUE(interface.runCommand(QJsonObject(), &molecule));
  ASSERT_TRUE(finishedSpy.wait(30000));
  EXPECT_EQ(finishedSpy.count(), 1);
  EXPECT_EQ(progressSpy.count(), 1);
}

// A script that returns a molecule Avogadro cannot parse must leave the user's
// molecule alone. The xyz below declares five atoms and supplies one, so the
// reader fails partway through with atoms already added: taking that result
// would swap a water molecule for a lone carbon.
TEST(InterfaceScriptTest, UnreadableMoleculeLeavesMoleculeUntouched)
{
  ensureApp();

  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());

  QFile script(temporaryDirectory.filePath("command.py"));
  ASSERT_TRUE(script.open(QIODevice::WriteOnly | QIODevice::Text));
  const QByteArray source("import json, sys\n"
                          "sys.stdin.read()\n"
                          "print(json.dumps({'moleculeFormat': 'xyz',"
                          " 'xyz': '5\\ntruncated\\nC 0.0 0.0 0.0\\n'}))\n");
  ASSERT_EQ(script.write(source), source.size());
  script.close();

  InterfaceScript interface(script.fileName());
  QJsonObject opts;
  opts.insert(QStringLiteral("inputMoleculeFormat"), QStringLiteral("None"));
  interface.setOptionsJson(opts);

  Avogadro::QtGui::Molecule molecule;
  molecule.addAtom(8).setPosition3d(Avogadro::Vector3(0.0, 0.0, 0.0));
  molecule.addAtom(1).setPosition3d(Avogadro::Vector3(0.76, 0.59, 0.0));
  molecule.addAtom(1).setPosition3d(Avogadro::Vector3(-0.76, 0.59, 0.0));
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(0), molecule.atom(2), 1);

  QSignalSpy finishedSpy(&interface, &InterfaceScript::finished);
  ASSERT_TRUE(interface.runCommand(QJsonObject(), &molecule));
  ASSERT_TRUE(finishedSpy.wait(30000));

  EXPECT_FALSE(interface.processCommand(&molecule));
  EXPECT_TRUE(interface.hasErrors());

  ASSERT_EQ(molecule.atomCount(), 3u);
  EXPECT_EQ(molecule.bondCount(), 2u);
  EXPECT_EQ(molecule.atom(0).atomicNumber(), 8);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
}
