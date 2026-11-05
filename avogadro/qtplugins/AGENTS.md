# avogadro/qtplugins

User-facing features, one directory per plugin. Each plugin is one of three
kinds, defined in `qtgui`:

| Base class | What it does | Examples |
|------------|--------------|----------|
| `ExtensionPlugin` | Menu actions, dialogs, dock widgets, file formats, RPC commands | `centroid`, `crystal`, `forcefield`, `surfaces` |
| `ToolPlugin` | Interactive mouse and keyboard tools in the toolbar | `editor`, `manipulator`, `measuretool`, `templatetool` |
| `ScenePlugin` | Display types: turns the molecule into rendering geometry | `ballandstick`, `cartoons`, `label`, `wireframe` |

See the top-level [AGENTS.md](../../AGENTS.md) for the module map and the
rules that apply everywhere, and [qtgui/AGENTS.md](../qtgui/AGENTS.md) for
editing molecules with undo.

## Why plugins are separate

Plugins are the leaves of the dependency graph. Each is its own CMake target
linked against `QtGui` (and whatever else it needs), can be left out of a
build, and is not a public API, so it can change freely. That is why:

- **A plugin never includes another plugin's files.** If two plugins need the
  same helper, move it to `qtgui`, or lower if it needs no Qt.
- **Logic that is not GUI belongs lower down.** A plugin should be a thin
  layer of actions, dialogs and glue over code in `core`, `calc` or `io` that
  can be tested, and used from Python, without the GUI.
- **GPL-licensed code is allowed only here**, behind `BUILD_GPL_PLUGINS`
  (see `qtaim`).
- Plugins are built as **static** libraries by default
  (`BUILD_STATIC_PLUGINS=ON`) and linked into the application. The linker may
  drop static initializers that nothing references, so register formats,
  models and commands from the plugin's constructor, not from globals.

## Is this a C++ plugin at all?

Many features are better as a Python plugin in their own repository: they
install from Avogadro's plugin downloader, are released on their own schedule,
and can use any Python package. This is usually the right choice for wrapping
an external program, file formats from another package, input generators,
charge or energy models, and menu commands. See the
[plugin documentation](https://two.avogadro.cc/develop/plugins/index.html).
The C++ plugins `commandscripts`, `scriptfileformats`, `scriptcharges`,
`quantuminput` and the script energy models in `forcefield` are what run them.

## Adding a C++ plugin

1. Create `qtplugins/<name>/` with the class and a `CMakeLists.txt` that calls
   `avogadro_plugin()`:
   ```cmake
   avogadro_plugin(Centroid          # target name
     "Add centroid and center-of-mass."
     ExtensionPlugin                 # base class
     centroid.h                      # header(s)
     Centroid                        # class to instantiate
     "centroid.cpp"                  # sources
     ""                              # .ui files (optional)
     ""                              # .qrc files (optional)
   )
   ```
   The macro generates the plugin factory and `Q_PLUGIN_METADATA`. Link any
   further libraries with `target_link_libraries(<name> PRIVATE ...)`.
2. Add `add_subdirectory(<name>)` to [CMakeLists.txt](CMakeLists.txt).
3. `centroid` is a small, complete `ExtensionPlugin` to copy from.

## Conventions

- Make edits through `m_molecule->undoMolecule()`, then call `emitChanged()`
  with accurate flags (see [qtgui/AGENTS.md](../qtgui/AGENTS.md)).
- Wrap every user-visible string, including menu paths, in `tr()`. Menu paths
  come from `menuPath()`, for example `{ tr("&Build") }`.
- Handle `setMolecule(nullptr)` and an empty molecule. Many actions are
  triggered with no atoms present.
- Expose commands for scripting and RPC through `CommandRegistry`: add a
  `CommandSpec` in the constructor and forward `handleCommand()` to
  `commandRegistry().handle()` (see `select`, `measuretool`, `constraints`).
  The options are then validated before your handler runs.
- Background work goes through `QtConcurrent` or `CalcWorker` on a copy of the
  molecule, never on the live `QtGui::Molecule` (see
  [qtgui/AGENTS.md](../qtgui/AGENTS.md)).
- **Prefer non-modal dialogs and dock widgets** (`dockWidgets()`). A modal
  dialog blocks the RPC interface, and so scripting and automation, for as
  long as it is open.

## Tests

`tests/qtplugins/` has:

- **Smoke tests** (`pluginsmoketest.cpp`), which find every plugin the build
  produces and check that it constructs, handles every molecule fixture,
  triggers its actions, and tears down cleanly. A new plugin is covered
  automatically; make sure it passes.
- **Command tests** that drive one plugin's `handleCommand()` through
  `CommandTestHarness` with no main window. Add your plugin to the `plugins`
  list in [tests/qtplugins/CMakeLists.txt](../../tests/qtplugins/CMakeLists.txt)
  with a `<name>test.cpp`.
- A tool interaction harness for tools that need mouse events.

These tests need `BUILD_STATIC_PLUGINS=ON`. Tools that need a real renderer
are tested through avogadroapp's RPC harness instead.
