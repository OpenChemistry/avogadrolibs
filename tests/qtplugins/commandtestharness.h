/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_TESTS_COMMANDTESTHARNESS_H
#define AVOGADRO_TESTS_COMMANDTESTHARNESS_H

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QMap>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>

#include <functional>
#include <iosfwd>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

namespace Avogadro::QtPluginsTests {

/**
 * Everything a command is allowed to change, captured by value so two
 * snapshots can be compared after the fact. Positions are compared exactly:
 * the harness molecules are built in code, so there is no rounding to hide.
 */
struct MoleculeSnapshot
{
  std::vector<unsigned char> atomicNumbers;
  std::vector<Vector3> positions;
  std::vector<std::pair<Index, Index>> bondPairs;
  std::vector<unsigned char> bondOrders;
  std::vector<bool> selected;
  std::vector<size_t> layerIds;
  size_t maxLayer = 0;
  size_t activeLayer = 0;
  // a, b, c, d, value
  std::vector<std::tuple<Index, Index, Index, Index, Real>> constraints;
  size_t coordinateSetCount = 0;
  bool hasUnitCell = false;
  Matrix3 cellMatrix = Matrix3::Zero(); ///< Zero when there is no cell.
  int undoIndex = 0;
  int undoCount = 0;

  static MoleculeSnapshot take(QtGui::Molecule& molecule);

  bool operator==(const MoleculeSnapshot& other) const;
  bool operator!=(const MoleculeSnapshot& other) const
  {
    return !(*this == other);
  }

  /**
   * @return A description of the fields that differ, empty if equal.
   * @param includeUndo Compare undo stack position too. Pass false to ask
   * "is the molecule itself back where it was?" after an undo.
   */
  QStringList differences(const MoleculeSnapshot& other,
                          bool includeUndo = true) const;

  /** @return Indices of the selected atoms, for readable expectations. */
  std::vector<Index> selectedIndices() const;
};

/**
 * Mirrors MainWindow::CommandStatus in avogadroapp, plus TimedOut, which the
 * application reports to the RPC caller as a timeout rather than a status.
 */
enum class CommandStatus
{
  NotHandled, ///< handleCommand() returned false.
  Finished,   ///< Claimed, and finished (or never asked to be waited for).
  Failed,     ///< Claimed, and commandFailed() was emitted.
  TimedOut    ///< commandStarted() with no terminal signal in time.
};

const char* toString(CommandStatus status);

/**
 * The message a recognized command fails with when the plugin has no
 * molecule (design note decision 1: `true` + `commandFailed("No molecule")`).
 */
inline const char* NoMoleculeMessage = "No molecule";

/** Readable gtest failure output instead of a byte dump. */
void PrintTo(const MoleculeSnapshot& snapshot, std::ostream* os);

struct CommandOutcome
{
  bool claimed = false;
  CommandStatus status = CommandStatus::NotHandled;
  bool async = false; ///< commandStarted() was seen.
  QString message;
  QVariantMap result;
  int startedCount = 0;
  int finishedCount = 0;
  int failedCount = 0;

  /**
   * Lifecycle and invariant violations. These are harness findings, not the
   * command's own failure: a command may fail cleanly with none of these.
   */
  QStringList violations;

  bool clean() const { return violations.isEmpty(); }
};

/** "status X, violations: ..." for gtest failure messages. */
std::string describe(const CommandOutcome& outcome);

/**
 * Record, in the test XML, a behaviour that differs from the command
 * contract as decided (design note, "Decisions (Geoff, 2026-09-29)"). A
 * `knownDeviation...` test asserts the *current* behaviour, so it fails --
 * and must be rewritten to the contract -- once the plugin is fixed.
 */
void recordKnownDeviation(const char* what);

/**
 * Record a behaviour the decisions do not settle either way (e.g. a command
 * that silently does nothing when an app-level precondition such as a
 * camera or unit cell is missing). `undecided...` tests pin the current
 * behaviour so that a change to it is noticed.
 */
void recordUndecided(const char* what);

/**
 * Expect @p actual within @p tolerance of @p expected, component-wise.
 * @return Whether it was.
 */
bool expectNear(const Vector3& actual, const Vector3& expected,
                double tolerance, const std::string& what);

/**
 * Drives one plugin's command boundary in-process, the way
 * MainWindow::handleCommand() does, with no MainWindow.
 *
 * The harness owns a deterministic QtGui::Molecule and makes it the active
 * layer molecule. Attach one plugin, then run() commands; every run() and
 * every undo()/redo() is followed by an invariant check, and any finding is
 * reported in CommandOutcome::violations (or the returned list).
 */
class CommandTestHarness
{
public:
  explicit CommandTestHarness(int timeoutMs = 5000);
  ~CommandTestHarness();

  CommandTestHarness(const CommandTestHarness&) = delete;
  CommandTestHarness& operator=(const CommandTestHarness&) = delete;

  /** The owned molecule. Never null. */
  QtGui::Molecule* molecule() const { return m_molecule.get(); }

  /** Replace the molecule with methanol: C0 O1 H2 H3 H4 H5 (H5 on O). */
  void buildMethanol();

  /**
   * Replace the molecule with a hydrogen-peroxide-like chain H0-O1-O2-H3
   * whose geometry makes every measurement easy to check by hand:
   *   H0 (0, 1, 0), O1 (0, 0, 0), O2 (1.5, 0, 0), H3 (1.5, 0, 1)
   * so r(H0-O1) = r(O2-H3) = 1, r(O1-O2) = 1.5, angle H0-O1-O2 =
   * angle O1-O2-H3 = 90 degrees, dihedral H0-O1-O2-H3 = +90 degrees.
   * Bonds 0-1, 1-2, 2-3, all single.
   */
  void buildPeroxideChain();

  /**
   * Replace the molecule with an empty one (the active layer molecule, handed
   * to the plugin) for a test to build its own.
   */
  void buildEmpty();

  /**
   * Make @p molecule the active layer molecule, as MainWindow does when the
   * user switches windows; nullptr makes the harness molecule active again.
   * The plugin keeps whatever molecule it was given.
   */
  void setActiveLayerMolecule(const QtGui::Molecule* molecule);

  /** @return Whether the harness molecule is the active layer molecule. */
  bool harnessMoleculeIsActive() const;

  /**
   * Attach an ExtensionPlugin or ToolPlugin. Only one plugin at a time; the
   * harness does not own it. The molecule is handed over immediately.
   */
  template <typename PluginType>
  void attach(PluginType* plugin);

  /**
   * Hand the plugin a molecule, or nullptr to test the "no active molecule"
   * path. Passing the harness molecule restores the normal state.
   */
  void setPluginMolecule(QtGui::Molecule* molecule);

  /**
   * Call registerCommands() and collect the registerCommand() signals.
   * @return Command name to description. Duplicate registrations are
   * reported in registrationViolations().
   */
  QMap<QString, QString> registerCommands();
  QStringList registrationViolations() const { return m_registrationErrors; }

  /**
   * Run one command to completion: dispatch, wait (bounded) for an async
   * command, allow a grace period for late signals, then check lifecycle
   * rules and molecule invariants.
   */
  CommandOutcome run(const QString& command,
                     const QVariantMap& options = QVariantMap());

  /** Undo/redo on the molecule's stack. @return invariant violations. */
  QStringList undo();
  QStringList redo();

  MoleculeSnapshot snapshot() const;

  /** @return Structural problems with the molecule, empty if none. */
  QStringList checkInvariants() const;

  // TODO: loadMolecule(path) for symmetry sequences, using
  // AVOGADRO_DATA_ROOT (the plugins tested so far build in code).
  // Tool plugins that need a GLWidget or renderer (navigator and similar)
  // are tested through avogadroapp's RPC harness, not here.

private:
  void onRegistered(const QString& command, const QString& description);
  void onStarted();
  void onFinished(const QString& message, const QVariantMap& result);
  void onFailed(const QString& message);
  void settle(bool waitForTerminal);
  void resetMolecule();

  enum class Event
  {
    Started,
    Finished,
    Failed
  };

  std::unique_ptr<QtGui::Molecule> m_molecule;
  // Owns the lifecycle connections, so they die with the harness.
  std::unique_ptr<QObject> m_context;
  QObject* m_plugin = nullptr;
  std::function<bool(const QString&, const QVariantMap&)> m_handle;
  std::function<void()> m_register;
  std::function<void(QtGui::Molecule*)> m_setMolecule;
  int m_timeoutMs;

  QMap<QString, QString> m_registered;
  QStringList m_registrationErrors;

  // State for the command being run; m_active is false between commands, so
  // anything arriving then is a stray signal.
  bool m_active = false;
  std::vector<Event> m_events;
  QStringList m_stray;
  QString m_message;
  QVariantMap m_result;
  std::unique_ptr<MoleculeSnapshot> m_atFailure;
};

template <typename PluginType>
void CommandTestHarness::attach(PluginType* plugin)
{
  m_plugin = plugin;
  m_handle = [plugin](const QString& command, const QVariantMap& options) {
    return plugin->handleCommand(command, options);
  };
  m_register = [plugin]() { plugin->registerCommands(); };
  m_setMolecule = [plugin](QtGui::Molecule* mol) { plugin->setMolecule(mol); };

  QObject* ctx = m_context.get();
  QObject::connect(plugin, &PluginType::registerCommand, ctx,
                   [this](QString command, QString description) {
                     onRegistered(command, description);
                   });
  QObject::connect(plugin, &PluginType::commandStarted, ctx,
                   [this]() { onStarted(); });
  QObject::connect(plugin, &PluginType::commandFinished, ctx,
                   [this](const QString& message, const QVariantMap& result) {
                     onFinished(message, result);
                   });
  QObject::connect(plugin, &PluginType::commandFailed, ctx,
                   [this](const QString& message) { onFailed(message); });

  m_setMolecule(m_molecule.get());
}

} // namespace Avogadro::QtPluginsTests

// Found by argument-dependent lookup, since QString and QList live in the
// global namespace; without these gtest prints Qt values as bytes.
void PrintTo(const QString& string, std::ostream* os);
void PrintTo(const QStringList& list, std::ostream* os);

#endif // AVOGADRO_TESTS_COMMANDTESTHARNESS_H
