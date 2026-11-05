/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Contract tests for every plugin the build produces, found through the
// PluginManager rather than listed by hand, so a new plugin is covered the
// day it is added. One gtest test per plugin and kind of check:
//
//   PluginSmoke/Extension.<id>   construction, names, actions and menu
//                                paths, commands and their schemas, every
//                                molecule fixture, scene and camera, teardown
//   PluginSmoke/Actions.<id>     every enabled action triggered on every
//                                fixture, with modal dialogs dismissed
//   PluginSmoke/Scene.<id>       process() and processEditable() on every
//                                fixture, setup widget, teardown
//   PluginSmoke/Tool.<id>        activation action, icons, tool widget,
//                                draw(), and a fixed sequence of mouse,
//                                wheel and key events through a GLWidget
//
// Every check ends with the CommandTestHarness molecule invariants. These
// tests ask "does it survive and stay consistent", not "is the chemistry
// right"; that is for the per-plugin tests.

#include "commandtestharness.h"
#include "plugintestutils.h"
#include "toolinteractionharness.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/scene.h>

#include <QtCore/QJsonObject>
#include <QtCore/QPointer>
#include <QtCore/QSet>
#include <QtCore/QThreadPool>
#include <QtCore/QTimer>
#include <QtGui/QUndoStack>
#include <QtGui/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDockWidget>
#include <QtWidgets/QWidget>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace Avogadro;
using QtPluginsTests::CommandTestHarness;
using QtPluginsTests::ToolInteractionHarness;

namespace {

// Plugins whose actions reach outside the process -- the network, pip, an
// external program or a Python interpreter -- so triggering them would make
// the test depend on the machine. Everything else about them is still
// tested; only PluginSmoke/Actions skips them.
const QSet<QString> kActionsReachOutside = {
  QStringLiteral("apbs"),                // runs apbs
  QStringLiteral("commands"),            // Python command scripts
  QStringLiteral("ConfigurePython"),     // probes Python environments
  QStringLiteral("FetchPDB"),            // network
  QStringLiteral("ImportPQR"),           // network
  QStringLiteral("MolecularProperties"), // looks the name up online
  QStringLiteral("NetworkDatabases"),    // network
  QStringLiteral("OpenBabel"),           // runs obabel
  QStringLiteral("PackageInstaller"),    // network, pip
  QStringLiteral("PlotXrd"),             // Python script
  QStringLiteral("QuantumInput"),        // Python input generators
  QStringLiteral("ScriptCharges"),       // Python charge scripts
  QStringLiteral("ScriptFileFormats"),   // Python format scripts
  QStringLiteral("Yaehmop"),             // runs yaehmop
};

// Plugins that build Rendering::TextLabels (found with grep TextLabel in
// avogadro/qtplugins), whose constructors call OpenGL and crash without a
// current context. Their scene or tool checks skip when there is none.
const QSet<QString> kBuildsTextLabels = {
  QStringLiteral("AlignTool"),   QStringLiteral("AutoOpt"),
  QStringLiteral("BondCentric"), QStringLiteral("Editor"),
  QStringLiteral("Label"),       QStringLiteral("LabelEditor"),
  QStringLiteral("MeasureTool"), QStringLiteral("TemplateTool"),
};

std::string dataFile(const char* relative)
{
  return std::string(AVOGADRO_DATA_ROOT) + "/data/" + relative;
}

struct Fixture
{
  const char* name;
  std::function<bool(CommandTestHarness&)> build;
};

// Molecules chosen for the plugin code they reach: nothing at all, a small
// organic molecule, a protein (residues, secondary structure), a crystal
// (unit cell, space group), a cube and orbitals, and vibrational modes.
const std::vector<Fixture>& fixtures()
{
  static const std::vector<Fixture> list = {
    { "empty",
      [](CommandTestHarness& h) {
        h.buildEmpty();
        return true;
      } },
    { "methanol",
      [](CommandTestHarness& h) {
        h.buildMethanol();
        return true;
      } },
    { "caffeine",
      [](CommandTestHarness& h) {
        return h.loadFile(dataFile("cjson/caffeine.cjson"));
      } },
    { "crambin",
      [](CommandTestHarness& h) {
        return h.loadFile(dataFile("cjson/1crn.cjson"));
      } },
    { "rutile",
      [](CommandTestHarness& h) {
        return h.loadFile(dataFile("cjson/rutile.cjson"));
      } },
    { "formaldehyde-cube",
      [](CommandTestHarness& h) {
        return h.loadFile(dataFile("cjson/h2co-cube.cjson"));
      } },
    { "raman",
      [](CommandTestHarness& h) {
        return h.loadFile(dataFile("cjson/raman.cjson"));
      } },
  };
  return list;
}

std::string joined(const QStringList& list)
{
  return list.join(QStringLiteral("; ")).toStdString();
}

/**
 * Closes whatever modal dialog is open, every few milliseconds, for as long
 * as it lives: QDialog::exec(), QMessageBox, QFileDialog and QInputDialog all
 * return as if the user had pressed Cancel. Their timers run inside the
 * dialog's own event loop, so this works from within exec().
 */
class ModalDismisser
{
public:
  ModalDismisser()
  {
    QObject::connect(&m_timer, &QTimer::timeout, [this] { dismiss(); });
    m_timer.start(5);
  }

  int dismissed() const { return m_dismissed; }

private:
  void dismiss()
  {
    QWidget* modal = QApplication::activeModalWidget();
    if (modal == nullptr)
      return;
    if (auto* dialog = qobject_cast<QDialog*>(modal))
      dialog->reject();
    else
      modal->close();
    ++m_dismissed;
  }

  QTimer m_timer;
  int m_dismissed = 0;
};

/**
 * Ends the run, with a message naming what was running, if one action stays
 * blocked for a long time. ModalDismisser can only close Qt dialogs; anything
 * else that blocks (a native dialog, a loop waiting on a process) would
 * otherwise hang the whole suite. It runs on its own thread because the main
 * thread, stuck in a nested loop, cannot be relied on to run a timer.
 */
class ActionWatchdog
{
public:
  static constexpr std::chrono::seconds Limit{ 30 };

  ActionWatchdog() : m_thread([this] { watch(); }) {}
  ~ActionWatchdog()
  {
    m_done = true;
    m_thread.join();
  }

  /** Marks one action as running for as long as it lives. */
  class Scope
  {
  public:
    Scope(ActionWatchdog& dog, std::string what) : m_dog(dog)
    {
      std::lock_guard<std::mutex> lock(m_dog.m_mutex);
      m_dog.m_what = std::move(what);
      m_dog.m_start = std::chrono::steady_clock::now();
      m_dog.m_running = true;
    }
    ~Scope()
    {
      std::lock_guard<std::mutex> lock(m_dog.m_mutex);
      m_dog.m_running = false;
    }

  private:
    ActionWatchdog& m_dog;
  };

private:
  void watch()
  {
    while (!m_done) {
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      std::lock_guard<std::mutex> lock(m_mutex);
      if (m_running && std::chrono::steady_clock::now() - m_start > Limit) {
        std::fprintf(stderr,
                     "\n[  HUNG    ] %s was still running after %lld s: "
                     "probably a native dialog or an event loop that nothing "
                     "ends. Add the plugin to kActionsReachOutside if it "
                     "should not run here.\n",
                     m_what.c_str(), static_cast<long long>(Limit.count()));
        std::fflush(stderr);
        std::_Exit(3);
      }
    }
  }

  std::mutex m_mutex;
  std::string m_what;
  std::chrono::steady_clock::time_point m_start;
  bool m_running = false;
  std::atomic<bool> m_done{ false };
  std::thread m_thread;
};

/**
 * Let queued work finish: events, timers that fire soon (debounces), and
 * QtConcurrent jobs on the global pool, which must not outlive the molecule
 * they were started on.
 */
void settle()
{
  for (int i = 0; i < 3; ++i) {
    QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    QThreadPool::globalInstance()->waitForDone(5000);
  }
}

/** Close the windows a test opened, so the next one starts clean. */
void closeNewWindows(const QSet<QWidget*>& before)
{
  for (QWidget* widget : QApplication::topLevelWidgets()) {
    if (!before.contains(widget) && widget->isVisible())
      widget->close();
  }
  settle();
}

QSet<QWidget*> topLevelWidgets()
{
  const QWidgetList list = QApplication::topLevelWidgets();
  return QSet<QWidget*>(list.begin(), list.end());
}

// ---------------------------------------------------------------- extension

void checkExtension(const QString& id)
{
  // The scene and camera come first and the plugin second, so each outlives
  // what points at it: the plugin outlives the harness, whose destructor hands
  // it a null molecule, and the camera outlives the plugin, whose timers
  // (ResetView animates) fire while the harness is destroyed.
  Rendering::Scene scene;
  Rendering::Camera camera;
  auto plugin = QtPluginsTests::createExtension(id);
  ASSERT_NE(plugin, nullptr);
  CommandTestHarness h(2000, 10);
  EXPECT_EQ(plugin->objectName(), id);
  EXPECT_FALSE(plugin->name().isEmpty());

  for (QAction* action : plugin->actions()) {
    ASSERT_NE(action, nullptr);
    if (action->isSeparator())
      continue;
    EXPECT_FALSE(action->text().isEmpty()) << "an action has no text";
    // menuPath() must not crash for any of the plugin's own actions.
    plugin->menuPath(action);
  }
  // Not null (the application never passes that, and many plugins read
  // action->data() unchecked), but an action the plugin did not make.
  QAction stray;
  plugin->menuPath(&stray);

  for (Io::FileFormat* format : plugin->fileFormats()) {
    ASSERT_NE(format, nullptr);
    EXPECT_FALSE(format->identifier().empty());
  }
  for (QDockWidget* dock : plugin->dockWidgets())
    ASSERT_NE(dock, nullptr);

  // Commands: registered once each, with a schema that names them.
  h.attach(plugin.get());
  const QMap<QString, QString> commands = h.registerCommands();
  EXPECT_TRUE(h.registrationViolations().isEmpty())
    << joined(h.registrationViolations());
  for (auto it = commands.cbegin(); it != commands.cend(); ++it) {
    EXPECT_FALSE(it.value().isEmpty()) << it.key().toStdString();
    plugin->commandSchema(it.key());
  }

  // The application hands over its scene and camera, then each molecule the
  // user opens; nothing may break the molecule it is given.
  plugin->setScene(&scene);
  plugin->setCamera(&camera);
  const QSet<QWidget*> windows = topLevelWidgets();
  for (const Fixture& fixture : fixtures()) {
    SCOPED_TRACE(fixture.name);
    ASSERT_TRUE(fixture.build(h)) << "could not load " << fixture.name;
    settle();
    EXPECT_TRUE(h.checkInvariants().isEmpty()) << joined(h.checkInvariants());
    plugin->menuPath(&stray);
    plugin->actions();
  }
  h.setPluginMolecule(nullptr);
  settle();
  closeNewWindows(windows);
}

void checkExtensionActions(const QString& id)
{
  if (kActionsReachOutside.contains(id))
    GTEST_SKIP() << "actions reach outside the process";

  // The scene and camera come first and the plugin second, so each outlives
  // what points at it: the plugin outlives the harness, whose destructor hands
  // it a null molecule, and the camera outlives the plugin, whose timers
  // (ResetView animates) fire while the harness is destroyed.
  Rendering::Scene scene;
  Rendering::Camera camera;
  auto plugin = QtPluginsTests::createExtension(id);
  ASSERT_NE(plugin, nullptr);
  CommandTestHarness h(2000, 10);
  h.attach(plugin.get());

  plugin->setScene(&scene);
  plugin->setCamera(&camera);

  // What MainWindow does with moleculeReady(): read the plugin's molecule
  // into a new one. The result must be a consistent molecule.
  int readFailures = 0;
  QObject context;
  QObject::connect(plugin.get(), &QtGui::ExtensionPlugin::moleculeReady,
                   &context, [&](int) {
                     QtGui::Molecule incoming;
                     if (!plugin->readMolecule(incoming))
                       ++readFailures;
                   });

  const QSet<QWidget*> windows = topLevelWidgets();
  ModalDismisser dismisser;
  ActionWatchdog watchdog;
  int triggered = 0;
  for (const Fixture& fixture : fixtures()) {
    SCOPED_TRACE(fixture.name);
    ASSERT_TRUE(fixture.build(h)) << "could not load " << fixture.name;
    settle();
    // actions() may change with the molecule, and with each trigger.
    const QList<QAction*> actions = plugin->actions();
    for (const QPointer<QAction> action : actions) {
      if (action.isNull() || action->isSeparator() || !action->isEnabled())
        continue;
      SCOPED_TRACE(action->text().toStdString());
      {
        const ActionWatchdog::Scope running(
          watchdog, id.toStdString() + " / " + action->text().toStdString());
        action->trigger();
      }
      ++triggered;
      settle();
      EXPECT_TRUE(h.checkInvariants().isEmpty()) << joined(h.checkInvariants());
    }
    closeNewWindows(windows);
  }
  EXPECT_EQ(readFailures, 0);
  ::testing::Test::RecordProperty("triggered", triggered);
  ::testing::Test::RecordProperty("dismissed", dismisser.dismissed());

  h.setPluginMolecule(nullptr);
  settle();
  closeNewWindows(windows);
}

// -------------------------------------------------------------------- scene

void checkScene(const QString& id)
{
  if (kBuildsTextLabels.contains(id) && !QtPluginsTests::haveGLContext())
    GTEST_SKIP() << "builds text labels, which need an OpenGL context";

  auto harness = std::make_unique<CommandTestHarness>();
  CommandTestHarness& h = *harness;
  auto plugin = QtPluginsTests::createScenePlugin(id);
  ASSERT_NE(plugin, nullptr);
  EXPECT_EQ(plugin->objectName(), id);
  EXPECT_FALSE(plugin->name().isEmpty());

  for (const Fixture& fixture : fixtures()) {
    SCOPED_TRACE(fixture.name);
    ASSERT_TRUE(fixture.build(h)) << "could not load " << fixture.name;
    // The plugin's layer state is per molecule, as the active layer one.
    h.setActiveLayerMolecule(nullptr);
    plugin->setEnabled(true);
    EXPECT_TRUE(plugin->isEnabled());
    plugin->isApplicable();

    Rendering::GroupNode node;
    plugin->process(*h.molecule(), node);
    Rendering::GroupNode editable;
    plugin->processEditable(*h.molecule()->undoMolecule(), editable);

    plugin->setEnabled(false);
    EXPECT_TRUE(h.checkInvariants().isEmpty()) << joined(h.checkInvariants());
  }

  // The setup widget is made on demand; the caller (a dock) owns it.
  QPointer<QWidget> widget = plugin->setupWidget();
  EXPECT_EQ(plugin->hasSetupWidget(), !widget.isNull());
  plugin.reset();
  // The layer data in the molecule may still point at the widget, so delete
  // the widget first: the molecule must not touch it afterwards.
  delete widget.data();
  harness.reset();
  settle();
}

// --------------------------------------------------------------------- tool

void checkTool(const QString& id)
{
  if (kBuildsTextLabels.contains(id) && !QtPluginsTests::haveGLContext())
    GTEST_SKIP() << "draws text labels, which need an OpenGL context";

  // The caller (a dock) owns the tool widget. Declared before the harness so
  // it is deleted after the harness and its tools are gone, on every path.
  struct WidgetDeleter
  {
    QPointer<QWidget> widget;
    ~WidgetDeleter() { delete widget.data(); }
  } toolWidget;

  ToolInteractionHarness h;
  auto ballStick = QtPluginsTests::createScenePlugin("BallStick");
  ASSERT_NE(ballStick, nullptr);
  h.addScenePlugin(ballStick.release());

  auto created = QtPluginsTests::createTool(id);
  ASSERT_NE(created, nullptr);
  QtGui::ToolPlugin* tool = created.get();
  EXPECT_EQ(tool->objectName(), id);
  EXPECT_FALSE(tool->name().isEmpty());
  ASSERT_NE(tool->activateAction(), nullptr);
  EXPECT_FALSE(tool->activateAction()->text().isEmpty());
  tool->setIcon(false);
  tool->setIcon(true);
  toolWidget.widget = tool->toolWidget();
  tool->priority();

  h.setActiveTool(created.release());
  auto navigator = QtPluginsTests::createTool("Navigator");
  ASSERT_NE(navigator, nullptr);
  h.setDefaultTool(navigator.release());

  // A fixed tour of the input a user can give, on and off the molecule.
  // Whatever the tool makes of it, the molecule must stay consistent and
  // undo must take it back to where it started.
  auto tour = [&h] {
    const QPoint atom = h.pointOnAtom(0);
    const QPoint other = h.pointOnAtom(1);
    const QPoint bond = h.pointOnBond(0);
    const QPoint empty = h.emptyPoint();
    const QPoint centre(ToolInteractionHarness::ViewportSize / 2,
                        ToolInteractionHarness::ViewportSize / 2);
    for (Qt::MouseButton button :
         { Qt::LeftButton, Qt::RightButton, Qt::MiddleButton }) {
      for (Qt::KeyboardModifiers modifiers :
           { Qt::KeyboardModifiers(Qt::NoModifier),
             Qt::KeyboardModifiers(Qt::ShiftModifier),
             Qt::KeyboardModifiers(Qt::ControlModifier) }) {
        h.click(atom, button, modifiers);
        h.click(bond, button, modifiers);
        h.click(empty, button, modifiers);
        h.drag(atom, other, button, modifiers);
        h.drag(empty, centre, button, modifiers);
      }
      h.dblClick(atom, button);
      h.dblClick(empty, button);
    }
    h.move(centre);
    h.wheel(centre, 120);
    h.wheel(centre, -240);
    for (int key : { int(Qt::Key_Escape), int(Qt::Key_Delete),
                     int(Qt::Key_Left), int(Qt::Key_Up) }) {
      h.keyPress(key);
      h.keyRelease(key);
    }
    h.keyPress(Qt::Key_C, Qt::NoModifier, QStringLiteral("c"));
    h.keyRelease(Qt::Key_C, Qt::NoModifier, QStringLiteral("c"));
  };

  for (bool peroxide : { false, true }) {
    SCOPED_TRACE(peroxide ? "peroxide" : "methanol");
    if (peroxide)
      h.buildPeroxideChain();
    else
      h.buildMethanol();
    const auto start = h.commands().snapshot();

    tour();
    settle();
    EXPECT_TRUE(h.commands().checkInvariants().isEmpty())
      << joined(h.commands().checkInvariants());

    Rendering::GroupNode node;
    tool->draw(node);

    QUndoStack& stack = h.molecule()->undoMolecule()->undoStack();
    while (stack.canUndo()) {
      const QStringList violations = h.commands().undo();
      EXPECT_TRUE(violations.isEmpty()) << joined(violations);
    }
    EXPECT_TRUE(h.commands().snapshot().differences(start, false).isEmpty())
      << joined(h.commands().snapshot().differences(start, false));
  }

  // An empty molecule: every click lands on nothing.
  h.buildEmpty();
  tour();
  settle();
  EXPECT_TRUE(h.commands().checkInvariants().isEmpty())
    << joined(h.commands().checkInvariants());
}

// ------------------------------------------------------------- registration

class SmokeTest : public ::testing::Test
{
public:
  explicit SmokeTest(std::function<void()> body) : m_body(std::move(body)) {}
  void TestBody() override { m_body(); }

private:
  std::function<void()> m_body;
};

template <typename Factory>
void registerEach(const char* suite, void (*check)(const QString&))
{
  for (const QString& id : QtPluginsTests::pluginIdentifiers<Factory>()) {
    const std::string name = id.toStdString();
    ::testing::RegisterTest(suite, name.c_str(), nullptr, nullptr, __FILE__,
                            __LINE__, [id, check]() -> SmokeTest* {
                              return new SmokeTest([id, check] { check(id); });
                            });
  }
}

} // namespace

namespace Avogadro::QtPluginsTests {

void registerPluginSmokeTests()
{
  registerEach<QtGui::ExtensionPluginFactory>("PluginSmoke/Extension",
                                              &checkExtension);
  registerEach<QtGui::ExtensionPluginFactory>("PluginSmoke/Actions",
                                              &checkExtensionActions);
  registerEach<QtGui::ScenePluginFactory>("PluginSmoke/Scene", &checkScene);
  registerEach<QtGui::ToolPluginFactory>("PluginSmoke/Tool", &checkTool);
}

} // namespace Avogadro::QtPluginsTests
