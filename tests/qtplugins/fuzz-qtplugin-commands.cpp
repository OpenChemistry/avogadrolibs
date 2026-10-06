/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Fuzzes the plugin command boundary in-process: random sequences of
// handleCommand() calls with random option maps on a small molecule, through
// CommandTestHarness (which checks the start/terminate contract and the
// molecule invariants after every call). Any violation aborts, so libFuzzer
// keeps the input as a crash artifact.
//
// Plugins: Select, Bonding, Crystal, AlignTool, MeasureTool, Focus. Surfaces
// is left out on purpose (see tests/qtplugins/CMakeLists.txt).
//
// Input format (all multi-byte values little-endian, reads past the end give
// zeros), read front to back so that seeds can be written by hand; see
// tests/qtplugins/fuzz/generate_seeds.py, which writes the seed corpus:
//
//   u8  molecule: bits 0-1 shape (0 methanol, 1 peroxide chain, 2 methanol in
//       a cubic cell with one atom outside it, 3 peroxide chain in a
//       triclinic cell); bit 2 adds a distance and an angle constraint;
//       bit 3 adds a bond order of 2 to the first bond
//   u8  initial selection, one bit per atom for atoms 0-7
//   u8  operation count - 1, modulo 50 (so 1 to 50 operations)
//   per operation:
//     u8  kind, modulo 16:
//           0-9    a registered command, chosen by the next byte
//           10-11  a command named by a string (the dictionary's route)
//           12     undo        13 redo       14 undo, then redo
//           15     toggle: detach the molecule from every plugin, or
//                  re-attach it
//         (kinds 0-11 are followed by the option map)
//     u8  command index, modulo the number of registered commands (0-9)
//     str command name (10-11)
//     u8  option count, modulo 7, then per option:
//           u8 key: an index into the fixed key set, or past its end a str
//           value: u8 type modulo 14, then its payload (see makeValue):
//             0 int32, 1 u8 - 3, 2 int64, 3 double, 4 special double (u8),
//             5 str, 6 bool (u8), 7 null, 8 uint64, 9 u8 - 3 as text,
//             10 special int (u8), 11 list (u8 length, then each element a
//             u8 type modulo 11 and payload), 12 nested option map,
//             13 float
//   str is a u8 length (modulo 17) followed by that many bytes.

#include <fuzzer/FuzzedDataProvider.h>

#include "commandtestharness.h"

#include "aligntool.h"
#include "bonding.h"
#include "crystal.h"
#include "focus.h"
#include "measuretool.h"
#include "select.h"

#include <avogadro/core/unitcell.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/scene.h>

#include <QtCore/QDebug>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryDir>
#include <QtCore/QVariant>
#include <QtGui/QUndoStack>
#include <QtWidgets/QApplication>

#include <cfloat>
#include <cmath>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace Avogadro;
using QtPluginsTests::CommandOutcome;
using QtPluginsTests::CommandTestHarness;
using QtPluginsTests::MoleculeSnapshot;

namespace Avogadro::QtPluginsTests {

// The harness reports a signal that arrives after the last command settled
// through this hook; the tests turn it into a gtest failure, here it is a
// crash.
void reportLateSignals(const std::string& description)
{
  std::fprintf(stderr, "FUZZ: harness violation: %s\n", description.c_str());
  std::abort();
}

} // namespace Avogadro::QtPluginsTests

namespace {

constexpr int kMaxOperations = 50;
constexpr int kMaxOptions = 6;
constexpr int kMaxListLength = 6;

// The option keys the commands read (atoms, id, index, element, axis, value),
// plus decoys, so that most keys in a map are ones some command looks at.
const char* const kKeys[] = { "atoms",   "id",        "index",     "element",
                              "axis",    "value",     "tolerance", "atom",
                              "indices", "resolution" };
constexpr int kKeyCount = sizeof(kKeys) / sizeof(kKeys[0]);

// Front-to-back reader over FuzzedDataProvider. FuzzedDataProvider's own
// ConsumeIntegral() and ConsumeFloatingPoint() take bytes from the *end* of
// the input, which leaves a seed impossible to write by hand; ConsumeData()
// takes them from the front, so only that is used here.
class Reader
{
public:
  Reader(const uint8_t* data, size_t size) : m_fdp(data, size) {}

  size_t remaining() { return m_fdp.remaining_bytes(); }

  template <typename T>
  T raw()
  {
    T value{};
    // ConsumeData copies fewer bytes at the end of the input; the rest stays
    // zero.
    m_fdp.ConsumeData(&value, sizeof(T));
    return value;
  }

  uint8_t u8() { return raw<uint8_t>(); }

  std::string str()
  {
    const size_t length = u8() % 17;
    std::string text(length, '\0');
    const size_t got = m_fdp.ConsumeData(text.data(), length);
    text.resize(got);
    return text;
  }

private:
  FuzzedDataProvider m_fdp;
};

QVariant makeValue(Reader& r, int depth = 0);

QVariant makeScalar(Reader& r, int type)
{
  static const double specialDoubles[] = {
    std::numeric_limits<double>::quiet_NaN(),
    std::numeric_limits<double>::infinity(),
    -std::numeric_limits<double>::infinity(),
    0.0,
    -0.0,
    DBL_MAX,
    -DBL_MAX,
    4.9406564584124654e-324,
  };
  static const qlonglong specialInts[] = {
    0,
    1,
    -1,
    INT_MAX,
    INT_MIN,
    static_cast<qlonglong>(INT_MAX) + 1,
    static_cast<qlonglong>(INT_MIN) - 1,
    9007199254740993LL,
    LLONG_MAX,
    LLONG_MIN,
  };

  switch (type) {
    case 0:
      return QVariant(r.raw<int32_t>());
    case 1: // a small index, mostly valid
      return QVariant(static_cast<int>(r.u8() % 14) - 3);
    case 2:
      return QVariant(static_cast<qlonglong>(r.raw<int64_t>()));
    case 3:
      return QVariant(r.raw<double>());
    case 4:
      return QVariant(specialDoubles[r.u8() % 8]);
    case 5:
      return QVariant(QString::fromStdString(r.str()));
    case 6:
      return QVariant(r.u8() % 2 == 1);
    case 7:
      return QVariant(); // null
    case 8:
      return QVariant(static_cast<qulonglong>(r.raw<uint64_t>()));
    case 9: // a number written as text
      return QVariant(QString::number(static_cast<int>(r.u8() % 14) - 3));
    default:
      return QVariant(specialInts[r.u8() % 10]);
  }
}

QVariantMap makeOptions(Reader& r, int depth);

// Type modulo 14: 0-10 scalars (see makeScalar), 11 a list of scalars (which
// may repeat), 12 a nested map, 13 a float.
QVariant makeValue(Reader& r, int depth)
{
  const int type = r.u8() % 14;
  if (type <= 10)
    return makeScalar(r, type);
  if (type == 11) {
    QVariantList list;
    const int count = r.u8() % (kMaxListLength + 1);
    for (int i = 0; i < count; ++i)
      list.append(makeScalar(r, r.u8() % 11));
    return list;
  }
  if (type == 12)
    return depth < 1 ? QVariant(makeOptions(r, depth + 1)) : QVariant();
  return QVariant(r.raw<float>());
}

QVariantMap makeOptions(Reader& r, int depth)
{
  QVariantMap options;
  const int count = r.u8() % (kMaxOptions + 1);
  for (int i = 0; i < count; ++i) {
    const int keyIndex = r.u8();
    QString key;
    if (keyIndex < kKeyCount)
      key = QString::fromLatin1(kKeys[keyIndex]);
    else
      key = QString::fromStdString(r.str());
    options.insert(key, makeValue(r, depth));
  }
  return options;
}

void buildMolecule(CommandTestHarness& harness, uint8_t spec, uint8_t selection)
{
  const int shape = spec & 3;
  if (shape == 1 || shape == 3)
    harness.buildPeroxideChain();
  else
    harness.buildMethanol();

  QtGui::Molecule* mol = harness.molecule();
  if (shape == 2) {
    mol->setUnitCell(new Core::UnitCell(
      Vector3(6.0, 0.0, 0.0), Vector3(0.0, 6.0, 0.0), Vector3(0.0, 0.0, 6.0)));
    // One atom outside the cell, so wrapping has something to do.
    mol->setAtomPosition3d(5, Vector3(7.5, -0.5, 3.0));
  } else if (shape == 3) {
    mol->setUnitCell(new Core::UnitCell(
      Vector3(4.0, 0.0, 0.0), Vector3(1.0, 5.0, 0.0), Vector3(0.5, 0.5, 6.0)));
  }
  if (spec & 4) {
    mol->addConstraint(1.5, 0, 1);
    mol->addConstraint(109.5, 1, 0, 2);
  }
  if ((spec & 8) && mol->bondCount() > 0)
    mol->setBondOrder(0, 2);
  for (Index i = 0; i < mol->atomCount() && i < 8; ++i)
    mol->setAtomSelected(i, (selection >> i) & 1);
}

// Behaviours the command tests already record as known deviations from the
// contract (decision 2: an undo step must do something), found again by the
// fuzzer on every run until the plugins are fixed. Listed so that they do not
// bury new findings; delete an entry when its plugin is brought into line.
//   aligntooltest.cpp   knownDeviationNoOpMovePushesUndoEntry
//   crystaltest.cpp     knownDeviationNoOpCrystalEditPushesUndoEntry
//   measuretooltest.cpp knownDeviationNoOpEditPushesUndoEntry
bool isKnownDeviation(const QString& command, const QString& violation)
{
  static const QStringList noOpMoves = {
    "centerAtom",   "alignAtom", "standardCrystalOrientation",
    "editDistance", "editAngle", "editDihedral"
  };
  return violation.startsWith(QLatin1String("changed nothing but pushed an "
                                            "undo entry")) &&
         noOpMoves.contains(command);
}

QString describeOperation(const std::string& command,
                          const QVariantMap& options)
{
  QString text;
  QDebug debug(&text);
  debug.nospace() << QString::fromStdString(command) << ' ' << options;
  return text;
}

[[noreturn]] void fail(const std::vector<std::string>& trace,
                       const std::string& what, const QStringList& violations)
{
  std::fprintf(stderr, "FUZZ: invariant violated after operation %zu: %s\n",
               trace.size(), what.c_str());
  for (const QString& v : violations)
    std::fprintf(stderr, "FUZZ:   %s\n", v.toStdString().c_str());
  std::fprintf(stderr, "FUZZ: operations so far:\n");
  for (size_t i = 0; i < trace.size(); ++i)
    std::fprintf(stderr, "FUZZ:   %zu. %s\n", i + 1, trace[i].c_str());
  std::fflush(stderr);
  std::abort();
}

QTemporaryDir* settingsDirectory()
{
  static QTemporaryDir dir;
  return &dir;
}

void quietMessages(QtMsgType type, const QMessageLogContext&,
                   const QString& message)
{
  // Plugins warn about plenty of bad input, and the fuzzer feeds it nothing
  // else; keep stderr for violations. A Qt fatal still ends the process.
  if (type == QtFatalMsg) {
    std::fprintf(stderr, "FUZZ: Qt fatal: %s\n", message.toStdString().c_str());
    std::abort();
  }
}

// Once per process. libFuzzer calls LLVMFuzzerInitialize() before the first
// input, but not on every platform (see below), so LLVMFuzzerTestOneInput()
// calls this too.
void initialize()
{
  static bool done = false;
  if (done)
    return;
  done = true;

  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    qputenv("QT_QPA_PLATFORM", "offscreen");

  // Settings first: Bonding reads its tolerance from QSettings in its
  // constructor, and the user's own preferences must neither steer nor be
  // overwritten by a fuzz run.
  QStandardPaths::setTestModeEnabled(true);
  QSettings::setDefaultFormat(QSettings::IniFormat);
  if (settingsDirectory()->isValid()) {
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                       settingsDirectory()->path());
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope,
                       settingsDirectory()->path());
  }

  // One QApplication for the process, with its own argv so that libFuzzer's
  // flags do not reach Qt.
  static int argc = 1;
  static char arg0[] = "fuzz_qtplugin_commands";
  static char* argv[] = { arg0, nullptr };
  static QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("OpenChemistry");
  QCoreApplication::setApplicationName("FuzzQtPluginCommands");
  qInstallMessageHandler(quietMessages);
}

} // namespace

// Default visibility: the project builds with hidden visibility, and on macOS
// libFuzzer finds LLVMFuzzerInitialize() with dlsym(), which does not see
// hidden symbols, so the hook would silently never run.
extern "C" __attribute__((visibility("default"))) int LLVMFuzzerInitialize(
  int*, char***)
{
  initialize();
  return 0;
}

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerTestOneInput(
  const uint8_t* data, size_t size)
{
  initialize();

  // Too short to say anything.
  if (size < 3)
    return 0;

  Reader reader(data, size);
  const uint8_t spec = reader.u8();
  const uint8_t selection = reader.u8();
  const int operations = 1 + reader.u8() % kMaxOperations;

  // Plugins are built per input so that nothing (a tool's merge state,
  // Bonding's settings, a camera) carries over from the previous one. They
  // are declared before the harness, which hands them a null molecule as it
  // goes away.
  Rendering::Camera camera;
  Rendering::Scene scene;
  QtPlugins::Select select;
  QtPlugins::Bonding bonding;
  QtPlugins::Crystal crystal;
  QtPlugins::AlignTool alignTool;
  QtPlugins::MeasureTool measureTool;
  QtPlugins::Focus focus;
  focus.setCamera(&camera);
  focus.setScene(&scene);

  // Short waits: nothing here is asynchronous (Surfaces, the one plugin that
  // is, is not included), so a command that starts and does not end should
  // fail quickly rather than hold the input.
  CommandTestHarness harness(100, 0);
  buildMolecule(harness, spec, selection);
  harness.attach(&select);
  harness.attach(&bonding);
  harness.attach(&crystal);
  harness.attach(&alignTool);
  harness.attach(&measureTool);
  harness.attach(&focus);

  std::vector<std::string> trace;
  const QStringList setup = harness.checkInvariants();
  if (!setup.isEmpty())
    fail(trace, "initial molecule", setup);

  const QStringList names = harness.registerCommands().keys();
  if (!harness.registrationViolations().isEmpty())
    fail(trace, "command registration", harness.registrationViolations());

  bool attached = true;
  for (int op = 0; op < operations && (op == 0 || reader.remaining() > 0);
       ++op) {
    const int kind = reader.u8() % 16;
    if (kind <= 11) {
      std::string command;
      if (kind <= 9) {
        const uint8_t pick = reader.u8();
        command = names.isEmpty() ? std::string()
                                  : names[pick % names.size()].toStdString();
      } else {
        command = reader.str();
      }
      const QVariantMap options = makeOptions(reader, 0);
      trace.push_back(describeOperation(command, options).toStdString());

      const CommandOutcome outcome =
        harness.run(QString::fromStdString(command), options);
      QStringList violations;
      for (const QString& v : outcome.violations) {
        if (!isKnownDeviation(QString::fromStdString(command), v))
          violations << v;
      }
      if (!violations.isEmpty())
        fail(trace, QtPluginsTests::describe(outcome), violations);
    } else if (kind == 12) {
      trace.push_back("undo");
      const QStringList v = harness.undo();
      if (!v.isEmpty())
        fail(trace, "after undo", v);
    } else if (kind == 13) {
      trace.push_back("redo");
      const QStringList v = harness.redo();
      if (!v.isEmpty())
        fail(trace, "after redo", v);
    } else if (kind == 14) {
      trace.push_back("undo, redo");
      const bool canUndo =
        harness.molecule()->undoMolecule()->undoStack().canUndo();
      const MoleculeSnapshot before = harness.snapshot();
      QStringList v = harness.undo();
      if (v.isEmpty())
        v = harness.redo();
      if (!v.isEmpty())
        fail(trace, "after undo and redo", v);
      // Redoing what was just undone must give back the very same state.
      const QStringList changed = before.differences(harness.snapshot());
      if (canUndo && !changed.isEmpty()) {
        QStringList detail = changed;
        const MoleculeSnapshot after = harness.snapshot();
        auto bonds = [](const MoleculeSnapshot& s) {
          QString text = QStringLiteral("bonds:");
          for (size_t i = 0; i < s.bondPairs.size(); ++i)
            text += QStringLiteral(" %1-%2/%3")
                      .arg(s.bondPairs[i].first)
                      .arg(s.bondPairs[i].second)
                      .arg(s.bondOrders[i]);
          return text;
        };
        detail << QStringLiteral("before: ") + bonds(before)
               << QStringLiteral("after:  ") + bonds(after);
        fail(trace, "undo then redo did not restore the molecule", detail);
      }
    } else {
      attached = !attached;
      trace.push_back(attached ? "attach molecule" : "detach molecule");
      harness.setPluginMolecule(attached ? harness.molecule() : nullptr);
    }
  }
  return 0;
}
