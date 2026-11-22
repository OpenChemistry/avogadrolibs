# avogadro/qtgui

The Qt layer shared by every plugin and by avogadroapp:

- `QtGui::Molecule`: `Core::Molecule` plus Qt signals and unique atom and
  bond IDs.
- `RWMolecule`, `RWAtom`, `RWBond`: editable wrappers that record every
  change on a `QUndoStack`.
- Plugin base classes: `ExtensionPlugin`, `ToolPlugin`, `ScenePlugin` and
  their factories.
- `CommandRegistry`: typed, validated, self-describing plugin commands used
  by the RPC interface.
- Script plugin support (`InterfaceScript`, `PythonScript`, `PackageManager`),
  threading helpers (`CalcWorker`, `GaussianSetConcurrent`), and widgets
  shared by more than one plugin.

See the top-level [AGENTS.md](../../AGENTS.md) for the module map and the
rules that apply everywhere.

## What belongs here

Put code in `qtgui` when it needs Qt **and** is used by more than one plugin,
or by avogadroapp. Code used by a single plugin stays in that plugin. Code that
does not need Qt goes lower, in `core`, `calc` or `io`, where Python and the
command-line tools can use it too.

The headers here are installed and used by avogadroapp and by plugins built
outside this repository, so changing a public signature or a virtual function
is an API change. Prefer adding over changing, and keep implementation details
in `_p.h` headers.

## Editing a molecule from the GUI

- **Make user-visible edits through `RWMolecule`** (`molecule->undoMolecule()`)
  so that they can be undone. Editing the `Core::Molecule` directly bypasses
  the undo stack.
- Group a multi-step edit into one undo entry with
  `undoStack().beginMacro(tr("..."))` and `endMacro()`. Use
  `setInteractive(true)` while dragging, so that many small moves merge into
  one command.
- To replace the whole molecule with one built elsewhere, use
  `RWMolecule::modifyMolecule()`.
- **After an edit, call `emitChanged()` with accurate flags**, combining an
  object type (`Atoms`, `Bonds`, `UnitCell`, `Selection`, ...) with an
  operation (`Added`, `Removed`, `Modified`, `Moved`, ...). The flags matter:
  structural changes make `emitChanged()` discard derived data (orbitals,
  cubes, meshes, vibrations, partial charges; see
  `Molecule::invalidatesDerivedData()`), so report a coordinate-only change as
  `Moved`, not `Modified`. Read the comments on `MoleculeChange` in
  [molecule.h](molecule.h) before choosing.
- Hold `PersistentAtom`/`PersistentBond` (unique IDs), not indices, across
  edits. Indices change when atoms are removed.

## Threads

Qt widgets and the current `QtGui::Molecule` belong to the main thread. Long
calculations run on a copy: `CalcWorker` takes a `Core::Molecule` snapshot and
returns results through queued signals. Call
`RWMolecule::cancelBackgroundCalculations()` before copying a molecule that
background surface or orbital work may be using.

## Strings

Every user-visible string goes through `tr()`. Avoid building sentences from
fragments; give translators the whole sentence with `%1` placeholders.

## Tests

`tests/qtgui/` uses GoogleTest; a test that needs signals across threads or
widgets creates the `QCoreApplication` or `QApplication` it needs (see
`backgroundfileformattest.cpp`). Undo and redo behavior belongs in
`rwmoleculetest.cpp`, which uses the shadow model in
`tests/core/shadowmolecule.h`.
