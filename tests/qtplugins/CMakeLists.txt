# Command-boundary tests for qtplugins: each plugin's handleCommand() driven
# in-process through CommandTestHarness, with no MainWindow. See the 2.1
# release plan, section 4.2.
#
# The plugins are linked as static libraries and instantiated directly, so
# this needs BUILD_STATIC_PLUGINS; tests/CMakeLists.txt skips the directory
# otherwise.

find_package(Qt${QT_VERSION} COMPONENTS Widgets Test REQUIRED)

# Plugin targets under test, and the test file for each (lowercased name).
# Only plugins that need nothing but a molecule (and, for Focus, a plain
# Rendering::Camera/Scene); tools needing a GLWidget or renderer are tested
# through avogadroapp's RPC harness instead.
set(plugins
  AlignTool
  Bonding
  Crystal
  Focus
  MeasureTool
  ScriptFileFormats
  Select
  SpaceGroup
  Surfaces
)

set(testSrcs "")
set(pluginTargets "")
set(pluginIncludes "")
foreach(plugin ${plugins})
  if(NOT TARGET ${plugin})
    message(STATUS "QtPlugins tests: no ${plugin} target, skipping it.")
    continue()
  endif()
  message(STATUS "Adding ${plugin} command test.")
  string(TOLOWER ${plugin} pluginname)
  list(APPEND testSrcs ${pluginname}test.cpp)
  list(APPEND pluginTargets ${plugin})
  # The plugin headers are not installed; include them from the source tree.
  get_target_property(pluginDir ${plugin} SOURCE_DIR)
  list(APPEND pluginIncludes "${pluginDir}")
endforeach()

# Scene plugins whose per-layer settings are saved as text, covered together by
# scenepluginserializetest.cpp rather than one test file each.
set(scenePlugins
  BallStick
  Cartoons
  Label
  Licorice
  VanDerWaals
  Wireframe
)
set(haveScenePlugins ON)
foreach(plugin ${scenePlugins})
  if(NOT TARGET ${plugin})
    message(STATUS "QtPlugins tests: no ${plugin} target, skipping the "
                   "scene plugin serialize test.")
    set(haveScenePlugins OFF)
  endif()
endforeach()
if(haveScenePlugins)
  message(STATUS "Adding scene plugin serialize test.")
  list(APPEND testSrcs scenepluginserializetest.cpp)
  foreach(plugin ${scenePlugins})
    list(APPEND pluginTargets ${plugin})
    get_target_property(pluginDir ${plugin} SOURCE_DIR)
    list(APPEND pluginIncludes "${pluginDir}")
  endforeach()
endif()

if(NOT testSrcs)
  return()
endif()

add_executable(AvogadroQtPluginsTests
  qtpluginstestmain.cpp
  commandtestharness.cpp
  commandtestharnessgtest.cpp
  commandtestharnesstest.cpp
  ${testSrcs})
target_include_directories(AvogadroQtPluginsTests PRIVATE ${pluginIncludes})
# Our own main() creates the QApplication, so link gtest without gtest_main.
target_link_libraries(AvogadroQtPluginsTests
  ${pluginTargets}
  Avogadro::QtGui
  ${GTEST_LIBRARIES} ${EXTRA_LINK_LIB}
  Qt${QT_VERSION}::Widgets Qt${QT_VERSION}::Test)

# Plugin headers include rendering headers, and the Focus test builds a
# Camera and Scene of its own.
if(TARGET Avogadro::Rendering)
  target_link_libraries(AvogadroQtPluginsTests Avogadro::Rendering)
endif()

# surfaces.h includes tinycolormap.hpp.
if(TARGET Surfaces AND TARGET tinycolormap)
  target_link_libraries(AvogadroQtPluginsTests tinycolormap)
endif()

set(testNames CommandTestHarness)
foreach(plugin ${pluginTargets})
  if(NOT plugin IN_LIST scenePlugins OR NOT haveScenePlugins)
    list(APPEND testNames ${plugin})
  endif()
endforeach()
if(haveScenePlugins)
  list(APPEND testNames ScenePluginSerialize)
endif()

foreach(plugin ${testNames})
  if(plugin STREQUAL "CommandTestHarness")
    set(filter "CommandTestHarnessTest.*")
  elseif(plugin STREQUAL "ScenePluginSerialize")
    set(filter "*ScenePluginSerializeTest.*")
  else()
    set(filter "${plugin}CommandTest.*")
  endif()
  add_test(NAME "QtPlugins-${plugin}"
    COMMAND AvogadroQtPluginsTests "--gtest_filter=${filter}")
  set_tests_properties("QtPlugins-${plugin}" PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    TIMEOUT 120)
endforeach()

# fuzz_qtplugin_commands: libFuzzer drives random command sequences through
# CommandTestHarness, in-process (2.1 release plan, section 4.2). Same plugins
# as the tests above, minus Surfaces: every Surfaces command starts a worker
# thread and a grid computation sized by a caller-supplied resolution, which is
# neither deterministic nor cheap, so it is exercised by the Surfaces tests
# only. Linux-only in CI: the Windows fuzz job builds with USE_QT=OFF.
if(ENABLE_FUZZ OR DEFINED ENV{LIB_FUZZING_ENGINE})
  set(fuzzPlugins AlignTool Bonding Crystal Focus MeasureTool Select)
  set(fuzzIncludes "")
  set(fuzzReady TRUE)
  foreach(plugin ${fuzzPlugins})
    if(TARGET ${plugin})
      get_target_property(pluginDir ${plugin} SOURCE_DIR)
      list(APPEND fuzzIncludes "${pluginDir}")
    else()
      set(fuzzReady FALSE)
    endif()
  endforeach()

  if(fuzzReady AND TARGET Avogadro::Rendering)
    add_executable(fuzz_qtplugin_commands
      fuzz-qtplugin-commands.cpp
      commandtestharness.cpp)
    target_include_directories(fuzz_qtplugin_commands
      PRIVATE ${fuzzIncludes} ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(fuzz_qtplugin_commands
      PRIVATE ${fuzzPlugins} Avogadro::QtGui Avogadro::Rendering
      Qt${QT_VERSION}::Widgets Qt${QT_VERSION}::Test)
    if(DEFINED ENV{LIB_FUZZING_ENGINE})
      target_link_libraries(fuzz_qtplugin_commands
        PRIVATE $ENV{LIB_FUZZING_ENGINE})
    else()
      target_compile_options(fuzz_qtplugin_commands
        PRIVATE ${AvogadroLibs_FUZZ_COMPILE_OPTIONS})
      target_link_options(fuzz_qtplugin_commands
        PRIVATE ${AvogadroLibs_FUZZ_LINK_OPTIONS})
      target_link_libraries(fuzz_qtplugin_commands
        PRIVATE ${AvogadroLibs_FUZZ_LINK_LIBS})
    endif()
  else()
    message(STATUS "Skipping fuzz_qtplugin_commands: a plugin target is "
      "missing.")
  endif()
endif()
