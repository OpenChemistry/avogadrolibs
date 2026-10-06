/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include <avogadro/core/constraint.h>
#include <avogadro/core/layer.h>
#include <avogadro/core/moleculeinfo.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/qtgui/rwlayermanager.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QCoreApplication>
#include <QtTest/QTest>

#include <algorithm>
#include <ostream>

#include <cmath>

namespace Avogadro::QtPluginsTests {

namespace {

// addMolecule() is protected; the application reaches it through LayerModel,
// which the harness has no use for otherwise.
class ActiveLayerMolecule : public QtGui::RWLayerManager
{
public:
  using QtGui::RWLayerManager::addMolecule;
  static bool isActive(const Core::Molecule* molecule)
  {
    return molecule != nullptr && activeMoleculeInfo() == molecule->layerInfo();
  }
};

QString eventName(bool started, bool failed)
{
  if (started)
    return QStringLiteral("commandStarted()");
  return failed ? QStringLiteral("commandFailed()")
                : QStringLiteral("commandFinished()");
}

} // namespace

std::string describe(const CommandOutcome& out)
{
  std::string text = std::string("status ") + toString(out.status);
  if (!out.message.isEmpty())
    text += ", message \"" + out.message.toStdString() + "\"";
  text +=
    ", violations: " + out.violations.join(QStringLiteral("; ")).toStdString();
  return text;
}

const char* toString(CommandStatus status)
{
  switch (status) {
    case CommandStatus::NotHandled:
      return "NotHandled";
    case CommandStatus::Finished:
      return "Finished";
    case CommandStatus::Failed:
      return "Failed";
    case CommandStatus::TimedOut:
      return "TimedOut";
  }
  return "Unknown";
}

void PrintTo(const MoleculeSnapshot& s, std::ostream* os)
{
  *os << "{ atoms " << s.atomicNumbers.size() << ", bonds "
      << s.bondPairs.size() << ", selected [";
  for (Index i : s.selectedIndices())
    *os << ' ' << i;
  *os << " ], layers [";
  for (size_t id : s.layerIds)
    *os << ' ' << id;
  *os << " ] max " << s.maxLayer << " active " << s.activeLayer
      << ", constraints " << s.constraints.size() << ", undo " << s.undoIndex
      << '/' << s.undoCount << " }";
}

MoleculeSnapshot MoleculeSnapshot::take(QtGui::Molecule& molecule)
{
  MoleculeSnapshot s;
  const Index n = molecule.atomCount();
  const auto& numbers = molecule.atomicNumbers();
  s.atomicNumbers.assign(numbers.begin(), numbers.end());
  const auto& positions = molecule.atomPositions3d();
  s.positions.assign(positions.begin(), positions.end());
  const auto& pairs = molecule.bondPairs();
  s.bondPairs.assign(pairs.begin(), pairs.end());
  const auto& orders = molecule.bondOrders();
  s.bondOrders.assign(orders.begin(), orders.end());

  const Core::Layer& layer = molecule.layer();
  s.maxLayer = layer.maxLayer();
  s.activeLayer = layer.activeLayer();
  for (Index i = 0; i < n; ++i) {
    s.selected.push_back(molecule.atomSelected(i));
    s.layerIds.push_back(i < layer.atomCount() ? layer.getLayerID(i)
                                               : MaxIndex);
  }

  for (const auto& c : molecule.constraints()) {
    s.constraints.emplace_back(c.aIndex(), c.bIndex(), c.cIndex(), c.dIndex(),
                               c.value());
  }
  s.coordinateSetCount = molecule.coordinate3dCount();
  s.hasUnitCell = molecule.unitCell() != nullptr;
  if (s.hasUnitCell)
    s.cellMatrix = molecule.unitCell()->cellMatrix();

  const QUndoStack& stack = molecule.undoMolecule()->undoStack();
  s.undoIndex = stack.index();
  s.undoCount = stack.count();
  return s;
}

bool MoleculeSnapshot::operator==(const MoleculeSnapshot& other) const
{
  return differences(other).isEmpty();
}

QStringList MoleculeSnapshot::differences(const MoleculeSnapshot& o,
                                          bool includeUndo) const
{
  QStringList d;
  if (atomicNumbers != o.atomicNumbers)
    d << QStringLiteral("atoms/elements");
  if (positions != o.positions)
    d << QStringLiteral("coordinates");
  if (bondPairs != o.bondPairs || bondOrders != o.bondOrders)
    d << QStringLiteral("bonds");
  if (selected != o.selected)
    d << QStringLiteral("selection");
  if (layerIds != o.layerIds || maxLayer != o.maxLayer ||
      activeLayer != o.activeLayer)
    d << QStringLiteral("layers");
  if (constraints != o.constraints)
    d << QStringLiteral("constraints");
  if (coordinateSetCount != o.coordinateSetCount)
    d << QStringLiteral("coordinate sets");
  if (hasUnitCell != o.hasUnitCell || cellMatrix != o.cellMatrix)
    d << QStringLiteral("unit cell");
  if (includeUndo && (undoIndex != o.undoIndex || undoCount != o.undoCount))
    d << QStringLiteral("undo stack (%1/%2 -> %3/%4)")
           .arg(undoIndex)
           .arg(undoCount)
           .arg(o.undoIndex)
           .arg(o.undoCount);
  return d;
}

std::vector<Index> MoleculeSnapshot::selectedIndices() const
{
  std::vector<Index> result;
  for (Index i = 0; i < selected.size(); ++i) {
    if (selected[i])
      result.push_back(i);
  }
  return result;
}

CommandTestHarness::CommandTestHarness(int timeoutMs, int graceMs)
  : m_context(std::make_unique<QObject>()), m_timeoutMs(timeoutMs),
    m_graceMs(graceMs)
{
  resetMolecule();
}

CommandTestHarness::~CommandTestHarness()
{
  // Catch a terminal signal that arrived after the last command settled.
  QCoreApplication::processEvents();
  if (!m_stray.isEmpty()) {
    reportLateSignals("Signals after the last command settled: " +
                      m_stray.join(QStringLiteral("; ")).toStdString());
  }
  // Disconnect before the molecule goes, so nothing reaches a dead harness.
  m_context.reset();
  setAllMolecules(nullptr);
}

void CommandTestHarness::setAllMolecules(QtGui::Molecule* molecule)
{
  for (const Handler& handler : m_handlers)
    handler.setMolecule(molecule);
}

void CommandTestHarness::resetMolecule()
{
  auto fresh = std::make_unique<QtGui::Molecule>();
  // What MainWindow does on a molecule change: make it the molecule the
  // layer GUI and PluginLayerManager act on.
  ActiveLayerMolecule().addMolecule(fresh.get());
  setAllMolecules(fresh.get());
  m_molecule = std::move(fresh);
}

void CommandTestHarness::buildMethanol()
{
  resetMolecule();
  QtGui::Molecule& mol = *m_molecule;
  // Staggered methanol, Angstrom. Only the connectivity and elements matter
  // for selection; the geometry is plausible so geometric commands can reuse
  // it.
  mol.addAtom(6, Vector3(0.000, 0.000, 0.000));    // 0 C
  mol.addAtom(8, Vector3(1.420, 0.000, 0.000));    // 1 O
  mol.addAtom(1, Vector3(-0.360, 1.027, 0.000));   // 2 H (C)
  mol.addAtom(1, Vector3(-0.360, -0.513, 0.889));  // 3 H (C)
  mol.addAtom(1, Vector3(-0.360, -0.513, -0.889)); // 4 H (C)
  mol.addAtom(1, Vector3(1.743, -0.913, 0.000));   // 5 H (O)
  mol.addBond(0, 1);
  mol.addBond(0, 2);
  mol.addBond(0, 3);
  mol.addBond(0, 4);
  mol.addBond(1, 5);
}

void CommandTestHarness::buildPeroxideChain()
{
  resetMolecule();
  QtGui::Molecule& mol = *m_molecule;
  // Not a real H2O2 geometry: chosen so that every distance, angle and
  // dihedral is a round number (see the header).
  mol.addAtom(1, Vector3(0.0, 1.0, 0.0)); // 0 H
  mol.addAtom(8, Vector3(0.0, 0.0, 0.0)); // 1 O
  mol.addAtom(8, Vector3(1.5, 0.0, 0.0)); // 2 O
  mol.addAtom(1, Vector3(1.5, 0.0, 1.0)); // 3 H
  mol.addBond(0, 1);
  mol.addBond(1, 2);
  mol.addBond(2, 3);
}

void CommandTestHarness::buildEmpty()
{
  resetMolecule();
}

void CommandTestHarness::setActiveLayerMolecule(const QtGui::Molecule* molecule)
{
  ActiveLayerMolecule().addMolecule(molecule != nullptr ? molecule
                                                        : m_molecule.get());
}

bool CommandTestHarness::harnessMoleculeIsActive() const
{
  return ActiveLayerMolecule::isActive(m_molecule.get());
}

void CommandTestHarness::setPluginMolecule(QtGui::Molecule* molecule)
{
  setAllMolecules(molecule);
}

QMap<QString, QString> CommandTestHarness::registerCommands()
{
  m_registered.clear();
  m_registrationErrors.clear();
  m_owners.clear();
  for (const Handler& handler : m_handlers)
    handler.registerAll();
  return m_registered;
}

void CommandTestHarness::onRegistered(size_t handler, const QString& command,
                                      const QString& description)
{
  m_owners[command].push_back(handler);
  if (m_registered.contains(command)) {
    m_registrationErrors << QStringLiteral("%1 registered twice").arg(command);
  }
  if (description.trimmed().isEmpty()) {
    m_registrationErrors
      << QStringLiteral("%1 has an empty description").arg(command);
  }
  m_registered.insert(command, description);
}

void CommandTestHarness::onStarted()
{
  if (!m_active) {
    m_stray << eventName(true, false);
    return;
  }
  m_events.push_back(Event::Started);
}

void CommandTestHarness::onFinished(const QString& message,
                                    const QVariantMap& result)
{
  if (!m_active) {
    m_stray << eventName(false, false);
    return;
  }
  // The first terminal signal decides, as it does in MainWindow.
  const bool first = std::none_of(m_events.begin(), m_events.end(),
                                  [](Event e) { return e != Event::Started; });
  m_events.push_back(Event::Finished);
  if (first) {
    m_message = message;
    m_result = result;
  }
}

void CommandTestHarness::onFailed(const QString& message)
{
  if (!m_active) {
    m_stray << eventName(false, true);
    return;
  }
  const bool first = std::none_of(m_events.begin(), m_events.end(),
                                  [](Event e) { return e != Event::Started; });
  m_events.push_back(Event::Failed);
  if (first)
    m_message = message;
  // Anything the molecule does from here on is a mutation after failure.
  if (m_atFailure == nullptr)
    m_atFailure = std::make_unique<MoleculeSnapshot>(snapshot());
}

void CommandTestHarness::settle(bool waitForTerminal)
{
  if (waitForTerminal) {
    // The result is recomputed from m_events in run(); a timeout is not an
    // error here.
    static_cast<void>(QTest::qWaitFor(
      [this]() {
        return std::any_of(m_events.begin(), m_events.end(),
                           [](Event e) { return e != Event::Started; });
      },
      m_timeoutMs));
  }
  QTest::qWait(m_graceMs);
}

CommandOutcome CommandTestHarness::run(const QString& command,
                                       const QVariantMap& options)
{
  CommandOutcome out;
  for (const QString& stray : m_stray) {
    out.violations << QStringLiteral("%1 arrived between commands").arg(stray);
  }
  m_stray.clear();

  if (m_handlers.empty()) {
    out.violations << QStringLiteral("no plugin attached");
    return out;
  }

  const MoleculeSnapshot before = snapshot();
  m_events.clear();
  m_message.clear();
  m_result.clear();
  m_atFailure.reset();
  m_active = true;

  // The plugin(s) that registered the command, or all of them if none did.
  std::vector<size_t> targets;
  const auto owners = m_owners.constFind(command);
  if (owners != m_owners.constEnd()) {
    targets = owners.value();
  } else {
    for (size_t i = 0; i < m_handlers.size(); ++i)
      targets.push_back(i);
  }
  for (size_t target : targets) {
    if (m_handlers[target].handle(command, options))
      out.claimed = true;
  }

  const bool startedInCall = std::find(m_events.begin(), m_events.end(),
                                       Event::Started) != m_events.end();
  const bool endedInCall =
    std::any_of(m_events.begin(), m_events.end(),
                [](Event e) { return e != Event::Started; });

  settle(out.claimed && startedInCall && !endedInCall);
  m_active = false;

  for (Event e : m_events) {
    if (e == Event::Started)
      ++out.startedCount;
    else if (e == Event::Finished)
      ++out.finishedCount;
    else
      ++out.failedCount;
  }
  out.async = out.startedCount > 0 && !endedInCall;
  out.message = m_message;
  out.result = m_result;

  // Classify exactly as MainWindow::endPluginCommand() and the RPC listener
  // do: the first terminal signal wins, and a claimed command that never
  // emitted commandStarted() is finished when the call returns.
  Event first = Event::Started;
  for (Event e : m_events) {
    if (e != Event::Started) {
      first = e;
      break;
    }
  }
  if (!out.claimed)
    out.status = CommandStatus::NotHandled;
  else if (first == Event::Failed)
    out.status = CommandStatus::Failed;
  else if (first == Event::Finished || out.startedCount == 0)
    out.status = CommandStatus::Finished;
  else
    out.status = CommandStatus::TimedOut;

  // Lifecycle rules.
  const int terminals = out.finishedCount + out.failedCount;
  if (!out.claimed && !m_events.empty())
    out.violations << QStringLiteral(
      "returned false (not my command) but emitted lifecycle signals");
  if (out.startedCount > 1)
    out.violations << QStringLiteral("commandStarted() emitted %1 times")
                        .arg(out.startedCount);
  if (terminals > 1)
    out.violations << QStringLiteral("terminated %1 times (%2 finished, %3 "
                                     "failed)")
                        .arg(terminals)
                        .arg(out.finishedCount)
                        .arg(out.failedCount);
  if (out.startedCount > 0 && !m_events.empty() &&
      m_events.front() != Event::Started)
    out.violations << QStringLiteral("commandStarted() after terminating");
  if (out.status == CommandStatus::TimedOut)
    out.violations << QStringLiteral("started and never terminated within "
                                     "%1 ms")
                        .arg(m_timeoutMs);

  // Molecule rules.
  const MoleculeSnapshot after = snapshot();
  if (m_atFailure != nullptr && *m_atFailure != after) {
    out.violations << QStringLiteral("mutated after commandFailed(): %1")
                        .arg(m_atFailure->differences(after).join(", "));
  }
  if (out.status == CommandStatus::Failed && before != after) {
    out.violations << QStringLiteral("failed command changed the molecule: %1")
                        .arg(before.differences(after).join(", "));
  }
  // Decision 2: an undo step must actually do something. A claimed command
  // that left everything the snapshot tracks as it was, yet moved the undo
  // stack, pushed an entry that does nothing. (A command changing something
  // the snapshot does not track, e.g. atom labels, would be misreported
  // here; none of the plugins under test does.)
  if (out.claimed && out.status != CommandStatus::Failed &&
      before.differences(after, false).isEmpty() && before != after) {
    out.violations << QStringLiteral("changed nothing but pushed an undo "
                                     "entry: %1")
                        .arg(before.differences(after).join(", "));
  }
  if (!out.claimed && before != after) {
    out.violations << QStringLiteral("unclaimed command changed the "
                                     "molecule: %1")
                        .arg(before.differences(after).join(", "));
  }
  out.violations << checkInvariants();
  return out;
}

QStringList CommandTestHarness::undo()
{
  m_molecule->undoMolecule()->undoStack().undo();
  return checkInvariants();
}

QStringList CommandTestHarness::redo()
{
  m_molecule->undoMolecule()->undoStack().redo();
  return checkInvariants();
}

MoleculeSnapshot CommandTestHarness::snapshot() const
{
  return MoleculeSnapshot::take(*m_molecule);
}

QStringList CommandTestHarness::checkInvariants() const
{
  QStringList v;
  QtGui::Molecule& mol = *m_molecule;
  const Index n = mol.atomCount();

  if (mol.atomicNumbers().size() != n)
    v << QStringLiteral("atomicNumbers size %1 != atomCount %2")
           .arg(mol.atomicNumbers().size())
           .arg(n);
  const Index nPos = mol.atomPositions3d().size();
  if (nPos != 0 && nPos != n)
    v << QStringLiteral("positions3d size %1 != atomCount %2").arg(nPos).arg(n);
  for (size_t i = 0; i < mol.coordinate3dCount(); ++i) {
    const Index size = mol.coordinate3dRef(i).size();
    if (size != n)
      v << QStringLiteral("coordinate set %1 has %2 positions for %3 atoms")
             .arg(i)
             .arg(size)
             .arg(n);
  }

  // Not a finite position: every distance computed from it is garbage and
  // snapshots no longer compare equal to themselves (NaN != NaN).
  for (Index i = 0; i < nPos; ++i) {
    const Vector3 p = mol.atomPosition3d(i);
    if (!std::isfinite(p.x()) || !std::isfinite(p.y()) || !std::isfinite(p.z()))
      v << QStringLiteral("atom %1 has a non-finite position").arg(i);
  }

  const auto& pairs = mol.bondPairs();
  if (mol.bondOrders().size() != pairs.size())
    v << QStringLiteral("bondOrders size %1 != bondCount %2")
           .arg(mol.bondOrders().size())
           .arg(pairs.size());
  for (Index b = 0; b < pairs.size(); ++b) {
    const auto& p = pairs[b];
    if (p.first >= n || p.second >= n || p.first == p.second)
      v << QStringLiteral("bond %1 joins invalid atoms %2-%3")
             .arg(b)
             .arg(p.first)
             .arg(p.second);
  }

  const Core::Layer& layer = mol.layer();
  if (layer.atomCount() != n)
    v << QStringLiteral("layer tracks %1 atoms, molecule has %2")
           .arg(layer.atomCount())
           .arg(n);
  for (Index i = 0; i < n && i < layer.atomCount(); ++i) {
    if (layer.getLayerID(i) > layer.maxLayer())
      v << QStringLiteral("atom %1 in layer %2 > maxLayer %3")
             .arg(i)
             .arg(layer.getLayerID(i))
             .arg(layer.maxLayer());
  }
  if (layer.activeLayer() > layer.maxLayer())
    v << QStringLiteral("activeLayer %1 > maxLayer %2")
           .arg(layer.activeLayer())
           .arg(layer.maxLayer());
  const auto info = mol.layerInfo();
  if (info->visible.size() <= layer.maxLayer() ||
      info->locked.size() <= layer.maxLayer())
    v << QStringLiteral("visible/locked (%1/%2) shorter than layer count %3")
           .arg(info->visible.size())
           .arg(info->locked.size())
           .arg(layer.maxLayer() + 1);

  for (const auto& c : mol.constraints()) {
    if (!c.isValid(n))
      v << QStringLiteral("constraint %1-%2-%3-%4 is invalid for %5 atoms")
             .arg(c.aIndex())
             .arg(c.bIndex())
             .arg(c.cIndex())
             .arg(c.dIndex())
             .arg(n);
  }
  return v;
}

} // namespace Avogadro::QtPluginsTests

void PrintTo(const QString& string, std::ostream* os)
{
  *os << '"' << string.toStdString() << '"';
}

void PrintTo(const QStringList& list, std::ostream* os)
{
  *os << "[ ";
  for (const QString& s : list)
    *os << '"' << s.toStdString() << "\" ";
  *os << ']';
}
