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

namespace {

// A script whose generated file carries @p contents verbatim, so that only
// the keyword replacement is under test.
QString writeGeneratorScript(const QTemporaryDir& directory,
                             const QByteArray& contents)
{
  QFile script(directory.filePath("generator.py"));
  if (!script.open(QIODevice::WriteOnly | QIODevice::Text))
    return QString();
  const QByteArray source(
    "import json, sys\n"
    "sys.stdin.read()\n"
    "print(json.dumps({'files': [{'filename': 'job.inp', 'contents': " +
    contents + "}]}))\n");
  if (script.write(source) != source.size())
    return QString();
  script.close();
  return script.fileName();
}

// Water, bent, with both O-H bonds, so that the z-matrix has a real angle.
Avogadro::Core::Molecule waterMolecule()
{
  Avogadro::Core::Molecule molecule;
  molecule.addAtom(8).setPosition3d(Avogadro::Vector3(0.0, 0.0, 0.0));
  molecule.addAtom(1).setPosition3d(Avogadro::Vector3(0.957, 0.0, 0.0));
  molecule.addAtom(1).setPosition3d(Avogadro::Vector3(-0.2399, 0.9270, 0.0));
  molecule.addBond(0, 1, 1);
  molecule.addBond(0, 2, 1);
  return molecule;
}

// Run @p script over water with the given "Coordinates" value, and hand back
// the generated file. An empty @p coordinates leaves the option out.
QString generatedFile(const QString& scriptFile, const QString& coordinates,
                      QStringList* warnings = nullptr)
{
  InterfaceScript interface(scriptFile);
  QJsonObject settings;
  settings.insert(QStringLiteral("inputMoleculeFormat"),
                  QStringLiteral("None"));
  interface.setOptionsJson(settings);

  QJsonObject userOptions;
  if (!coordinates.isEmpty())
    userOptions.insert(QStringLiteral("Coordinates"), coordinates);
  QJsonObject options;
  options.insert(QStringLiteral("options"), userOptions);

  const Avogadro::Core::Molecule molecule(waterMolecule());
  if (!interface.generateInput(options, molecule))
    return QString();
  if (warnings)
    *warnings = interface.warningList();
  return interface.fileContents(QStringLiteral("job.inp"));
}

// Both geometry keywords, each on its own line, between two markers that show
// whether the unused one took its whole line with it.
const QByteArray bothKeywords(
  "'begin\\n$$coords:Sxyz$$\\n$$zmat:_S_I_R_J_A_K_T$$\\nend\\n'");

} // namespace

// The Cartesian block is written, and the z-matrix keyword goes away along
// with the line it sat on -- a blank line left behind would end the molecule
// specification early in Gaussian.
TEST(InterfaceScriptTest, CartesianOptionSelectsTheCartesianBlock)
{
  ensureApp();
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());
  const QString script(writeGeneratorScript(temporaryDirectory, bothKeywords));
  ASSERT_FALSE(script.isEmpty());

  const QString contents(generatedFile(script, QStringLiteral("Cartesian")));
  EXPECT_EQ(QStringLiteral("begin\n"
                           "O      0.000000    0.000000    0.000000\n"
                           "H      0.957000    0.000000    0.000000\n"
                           "H     -0.239900    0.927000    0.000000\n"
                           "end\n"),
            contents);
}

TEST(InterfaceScriptTest, ZMatrixOptionSelectsTheZMatrixBlock)
{
  ensureApp();
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());
  const QString script(writeGeneratorScript(temporaryDirectory, bothKeywords));
  ASSERT_FALSE(script.isEmpty());

  QStringList warnings;
  const QString contents(
    generatedFile(script, QStringLiteral("Z-Matrix / Internal"), &warnings));
  EXPECT_EQ(QStringLiteral("begin\n"
                           " O  \n"
                           " H    1     0.957000\n"
                           " H    1     0.957539  2   104.509356\n"
                           "end\n"),
            contents);
  // Water needs no reordering and has no linear rows.
  EXPECT_TRUE(warnings.isEmpty())
    << warnings.join(QLatin1Char('\n')).toStdString();
}

// A script that never declared the option keeps the behavior it always had.
TEST(InterfaceScriptTest, NoCoordinatesOptionMeansCartesian)
{
  ensureApp();
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());
  const QString script(writeGeneratorScript(temporaryDirectory, bothKeywords));
  ASSERT_FALSE(script.isEmpty());

  const QString contents(generatedFile(script, QString()));
  EXPECT_TRUE(contents.contains(QStringLiteral("0.957000    0.000000")));
  EXPECT_FALSE(contents.contains(QStringLiteral("$$")));
}

// Where the surrounding syntax differs too much to write both forms, a script
// emits just the one -- and that one is used whatever the option says, rather
// than being deleted and leaving a file with no molecule in it.
TEST(InterfaceScriptTest, LoneKeywordIsUsedWhateverTheOptionSays)
{
  ensureApp();
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());
  const QString script(writeGeneratorScript(
    temporaryDirectory, "'begin\\n$$zmat:_S_I_R_J_A_K_T$$\\nend\\n'"));
  ASSERT_FALSE(script.isEmpty());

  const QString contents(generatedFile(script, QStringLiteral("Cartesian")));
  EXPECT_TRUE(contents.contains(QStringLiteral("104.509356")))
    << contents.toStdString();

  QTemporaryDir cartesianDirectory;
  ASSERT_TRUE(cartesianDirectory.isValid());
  const QString cartesianScript(writeGeneratorScript(
    cartesianDirectory, "'begin\\n$$coords:Sxyz$$\\nend\\n'"));
  ASSERT_FALSE(cartesianScript.isEmpty());

  const QString cartesian(
    generatedFile(cartesianScript, QStringLiteral("Z-Matrix / Internal")));
  EXPECT_TRUE(cartesian.contains(QStringLiteral("0.957000    0.000000")))
    << cartesian.toStdString();
}

// A z-matrix that had to reorder the atoms says so, since the numbering in
// the file is then not the numbering on screen.
TEST(InterfaceScriptTest, ReorderedZMatrixWarns)
{
  ensureApp();
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());
  const QString script(
    writeGeneratorScript(temporaryDirectory, "'$$zmat:_S_I_R_J_A_K_T$$\\n'"));
  ASSERT_FALSE(script.isEmpty());

  // Hydrogen peroxide with the hydrogens numbered first: atom 1 is bonded
  // only to atom 3, so it cannot be written second.
  Avogadro::Core::Molecule molecule;
  molecule.addAtom(1).setPosition3d(Avogadro::Vector3(0.0, 0.0, 0.0));
  molecule.addAtom(1).setPosition3d(Avogadro::Vector3(3.0, 0.9, 0.0));
  molecule.addAtom(8).setPosition3d(Avogadro::Vector3(1.0, 0.0, 0.0));
  molecule.addAtom(8).setPosition3d(Avogadro::Vector3(2.4, 0.4, 0.0));
  molecule.addBond(0, 2, 1);
  molecule.addBond(2, 3, 1);
  molecule.addBond(3, 1, 1);

  InterfaceScript interface(script);
  QJsonObject settings;
  settings.insert(QStringLiteral("inputMoleculeFormat"),
                  QStringLiteral("None"));
  interface.setOptionsJson(settings);

  QJsonObject userOptions;
  userOptions.insert(QStringLiteral("Coordinates"),
                     QStringLiteral("Z-Matrix / Internal"));
  QJsonObject options;
  options.insert(QStringLiteral("options"), userOptions);

  ASSERT_TRUE(interface.generateInput(options, molecule));
  ASSERT_EQ(1, interface.warningList().size());
  EXPECT_TRUE(interface.warningList().first().contains(
    QStringLiteral("different order")));
}
