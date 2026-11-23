/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energywindow.h"
#include "forcefield.h"

#include <avogadro/qtgui/molecule.h>
#include "obmmenergy.h"
#include "scriptenergy.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFile>
#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryDir>
#include <QtCore/QtGlobal>

#include <cmath>

#include <gtest/gtest.h>

using Avogadro::QtPlugins::OBMMEnergy;
using Avogadro::QtPlugins::ScriptEnergy;

namespace {

// Sets AVO_OBMM_EXECUTABLE for one test and restores it afterwards.
class ObmmEnvGuard
{
public:
  explicit ObmmEnvGuard(const char* value)
    : m_hadValue(qEnvironmentVariableIsSet(name)), m_oldValue(qgetenv(name))
  {
    qputenv(name, value);
  }

  ~ObmmEnvGuard()
  {
    if (m_hadValue)
      qputenv(name, m_oldValue);
    else
      qunsetenv(name);
  }

private:
  static constexpr const char* name = "AVO_OBMM_EXECUTABLE";
  bool m_hadValue;
  QByteArray m_oldValue;
};

} // namespace

TEST(ForcefieldCommandTest, obmmMissingAbsoluteOverride)
{
  ObmmEnvGuard guard("/nonexistent/dir/obmm");
  EXPECT_FALSE(OBMMEnergy::isAvailable());
}

TEST(ForcefieldCommandTest, obmmMissingRelativeOverride)
{
  ObmmEnvGuard guard("avogadro-no-such-obmm-binary");
  EXPECT_FALSE(OBMMEnergy::isAvailable());
}

#ifndef _WIN32
TEST(ForcefieldCommandTest, obmmExistingAbsoluteOverride)
{
  ObmmEnvGuard guard("/bin/sh");
  EXPECT_TRUE(OBMMEnergy::isAvailable());
}

TEST(ForcefieldCommandTest, obmmExistingOverrideOnPath)
{
  ObmmEnvGuard guard("sh");
  EXPECT_TRUE(OBMMEnergy::isAvailable());
}

TEST(ForcefieldCommandTest, obmmNonExecutableOverride)
{
  // A directory is not an executable
  ObmmEnvGuard guard("/tmp");
  EXPECT_FALSE(OBMMEnergy::isAvailable());
}
#endif

// --- EnergyWindow ---------------------------------------------------------

using Avogadro::QtPlugins::EnergyWindow;

TEST(EnergyWindowTest, LongChunksAreTheirOwnWindow)
{
  // Chunks >= window: identical to a per-chunk |dE| / chunkRan test.
  EnergyWindow w;
  const double tol = 1e-4;
  EXPECT_FALSE(w.update(20, 100.0, tol));      // first chunk only anchors
  EXPECT_FALSE(w.update(40, 90.0, tol));       // 0.5 per iteration
  EXPECT_TRUE(w.update(60, 90.0 - 1e-3, tol)); // 5e-5 per iteration
}

TEST(EnergyWindowTest, ShortChunksAccumulateToTheWindow)
{
  EnergyWindow w;
  const double tol = 1e-4;
  EXPECT_FALSE(w.update(1, 50.0, tol));
  // One-iteration chunks with a tiny step: no verdict until 10 iterations
  // have passed since the anchor.
  for (unsigned int i = 2; i <= 10; ++i)
    EXPECT_FALSE(w.update(i, 50.0, tol)) << i;
  EXPECT_TRUE(w.update(11, 50.0, tol));
}

TEST(EnergyWindowTest, MeanOverWindowNotLastStep)
{
  // A single tiny step inside a window of real progress must not stop it.
  EnergyWindow w;
  const double tol = 1e-4;
  EXPECT_FALSE(w.update(1, 50.0, tol));
  double e = 50.0;
  for (unsigned int i = 2; i <= 10; ++i) {
    e -= (i == 5) ? 0.0 : 0.01;
    EXPECT_FALSE(w.update(i, e, tol));
  }
  EXPECT_FALSE(w.update(11, e - 0.01, tol)); // 0.09 / 10 per iteration
}

TEST(EnergyWindowTest, AnchorMovesAndResets)
{
  EnergyWindow w;
  const double tol = 1e-4;
  w.update(10, 10.0, tol);
  EXPECT_FALSE(w.update(20, 5.0, tol));
  // The anchor is now (20, 5.0): a flat next window converges.
  EXPECT_TRUE(w.update(30, 5.0, tol));
  w.reset();
  EXPECT_FALSE(w.update(40, 5.0, tol)); // re-anchors rather than testing
}

TEST(EnergyWindowTest, ZeroEnergyStillTested)
{
  EnergyWindow w;
  EXPECT_FALSE(w.update(10, 0.0, 1e-4));
  EXPECT_TRUE(w.update(20, 0.0, 1e-4));
}

TEST(ForcefieldCommandTest, clearingMoleculeDoesNotWarn)
{
  Avogadro::QtGui::Molecule molecule;
  Avogadro::QtPlugins::Forcefield forcefield;
  forcefield.setMolecule(&molecule);

  static QStringList warnings;
  warnings.clear();
  auto previousHandler = qInstallMessageHandler(
    [](QtMsgType type, const QMessageLogContext&, const QString& message) {
      if (type == QtWarningMsg)
        warnings.append(message);
    });
  forcefield.setMolecule(nullptr);
  qInstallMessageHandler(previousHandler);
  EXPECT_TRUE(warnings.isEmpty()) << warnings.join("\n").toStdString();
}

#ifndef _WIN32
namespace {

// A stand-in for a machine-learning energy plugin that speaks binary-v1. Its
// behavior is picked by FAKE_MODE; FAKE_MARKER names a file that lets a mode
// misbehave in the first process only. The "energy" is the sum of the
// coordinates, so a stale reply is recognizable by its value.
const char* const fakePluginSource = R"PY(
import os, struct, sys, time
mode = os.environ["FAKE_MODE"]
marker = os.environ.get("FAKE_MARKER", "")
n = 2
inp, out = sys.stdin.buffer, sys.stdout.buffer
wants_ready = os.environ.get("AVOGADRO_ENERGY_READY") == "1"

def frame(flags, payload=b""):
    return struct.pack("<4sHHII", b"AVB1", 1, flags, n, len(payload)) + payload

def energy(e):
    return frame(0, struct.pack("<d", e))

def first_here():
    if not marker or os.path.exists(marker):
        return False
    open(marker, "w").close()
    return True

def read_request():
    head = inp.read(16)
    if len(head) < 16:
        sys.exit(0)
    plen = struct.unpack("<4sHHII", head)[4]
    return sum(struct.unpack("<%dd" % (plen // 8), inp.read(plen)))

inp.readline()  # the bootstrap JSON

if mode in ("slow_ready", "slow_noready"):
    time.sleep(8)
if wants_ready and mode in ("slow_ready", "late_once", "garbage", "env_probe"):
    out.write(frame(0x10)); out.flush()

first = True
while True:
    total = read_request()
    if mode == "same_chunk" and first:
        first = False
        out.write(frame(0x10) + energy(total)); out.flush()
    elif mode == "late_once" and first_here():
        time.sleep(7)
        out.write(energy(total)); out.flush()
    elif mode == "garbage" and first_here():
        out.write(b"this is not a frame at all"); out.flush()
    elif mode == "env_probe":
        out.write(energy(1.0 if wants_ready else 2.0)); out.flush()
    else:
        out.write(energy(total)); out.flush()
)PY";

// Sets an environment variable for one scope and restores it afterwards.
class EnvGuard
{
public:
  EnvGuard(const char* name, const QByteArray& value)
    : m_name(name), m_had(qEnvironmentVariableIsSet(name)), m_old(qgetenv(name))
  {
    qputenv(name, value);
  }
  ~EnvGuard()
  {
    if (m_had)
      qputenv(m_name, m_old);
    else
      qunsetenv(m_name);
  }

private:
  const char* m_name;
  bool m_had;
  QByteArray m_old;
};

// Two hydrogens driven by the fake plugin above.
class FakePlugin
{
public:
  explicit FakePlugin(const char* mode)
    : m_mode("FAKE_MODE", mode),
      m_marker("FAKE_MARKER", m_dir.filePath("marker").toUtf8())
  {
    ok = false;
    const QString python = QStandardPaths::findExecutable("python3");
    if (python.isEmpty() || !m_dir.isValid())
      return;
    QDir().mkpath(m_dir.filePath(".venv/bin"));
    QFile script(m_dir.filePath(".venv/bin/fakeplugin"));
    if (!script.open(QIODevice::WriteOnly))
      return;
    script.write("#!" + python.toUtf8() + "\n" + fakePluginSource);
    script.setPermissions(script.permissions() | QFileDevice::ExeOwner);
    script.close();

    molecule.addAtom(1);
    molecule.addAtom(1);
    molecule.addBond(0, 1);
    energy.setPackageInfo(m_dir.path(), "fakeplugin", "Fake");
    QVariantMap metadata;
    metadata["identifier"] = "Fake";
    metadata["model-name"] = "Fake";
    metadata["input-format"] = "cjson";
    metadata["protocol"] = "binary-v1";
    energy.readMetaData(metadata);
    energy.setMolecule(&molecule);
    ok = true;
  }

  ~FakePlugin()
  {
    // Let the deleteLater() of killed processes run.
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
  }

  // The fake plugin's answer is the sum of the coordinates.
  static Eigen::VectorXd coords(double scale)
  {
    Eigen::VectorXd x(6);
    x << 1, 2, 3, 4, 5, 6;
    return x * scale;
  }

  bool ok = false;
  Avogadro::Core::Molecule molecule;
  ScriptEnergy energy;

private:
  QTemporaryDir m_dir;
  EnvGuard m_mode;
  EnvGuard m_marker;
};

} // namespace

// An ML plugin needs ~8 s to import its framework and load the model before
// it answers anything; the first call must wait for it.
TEST(ForcefieldCommandTest, scriptEnergyWaitsForReadyFrame)
{
  FakePlugin plugin("slow_ready");
  if (!plugin.ok)
    GTEST_SKIP() << "needs python3 on PATH";
  QElapsedTimer timer;
  timer.start();
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(1.0)), 21.0);
  EXPECT_GE(timer.elapsed(), 7000);
  // After startup the normal per-frame timeout applies, and replies are fast.
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(2.0)), 42.0);
}

// A plugin that predates READY just stays silent while it loads.
TEST(ForcefieldCommandTest, scriptEnergyStartupWithoutReadyFrame)
{
  FakePlugin plugin("slow_noready");
  if (!plugin.ok)
    GTEST_SKIP() << "needs python3 on PATH";
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(1.0)), 21.0);
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(3.0)), 63.0);
}

// A reply that arrives after we gave up must never be read as the answer to
// the next request.
TEST(ForcefieldCommandTest, scriptEnergyLateReplyIsNeverReused)
{
  FakePlugin plugin("late_once");
  if (!plugin.ok)
    GTEST_SKIP() << "needs python3 on PATH";
  EXPECT_TRUE(std::isnan(plugin.energy.value(FakePlugin::coords(1.0))));
  // The plugin was killed and restarted; the new process answers this call
  // for these coordinates, not the old 21.0.
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(10.0)), 210.0);
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(0.5)), 10.5);
}

// READY and the first reply can arrive in one read.
TEST(ForcefieldCommandTest, scriptEnergyReadyAndReplyInOneChunk)
{
  FakePlugin plugin("same_chunk");
  if (!plugin.ok)
    GTEST_SKIP() << "needs python3 on PATH";
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(1.0)), 21.0);
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(2.0)), 42.0);
}

// A malformed frame fails at once (no waiting out a timeout) and the next
// call starts a fresh process.
TEST(ForcefieldCommandTest, scriptEnergyBadFrameRestartsPlugin)
{
  FakePlugin plugin("garbage");
  if (!plugin.ok)
    GTEST_SKIP() << "needs python3 on PATH";
  QElapsedTimer timer;
  timer.start();
  EXPECT_TRUE(std::isnan(plugin.energy.value(FakePlugin::coords(1.0))));
  EXPECT_LT(timer.elapsed(), 4000);
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(2.0)), 42.0);
}

// Avogadro must tell the plugin it understands READY.
TEST(ForcefieldCommandTest, scriptEnergyAdvertisesReadyFrame)
{
  FakePlugin plugin("env_probe");
  if (!plugin.ok)
    GTEST_SKIP() << "needs python3 on PATH";
  EXPECT_DOUBLE_EQ(plugin.energy.value(FakePlugin::coords(1.0)), 1.0);
}
#endif
