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
  Select
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

if(NOT testSrcs)
  return()
endif()

add_executable(AvogadroQtPluginsTests
  qtpluginstestmain.cpp
  commandtestharness.cpp
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

foreach(plugin CommandTestHarness ${pluginTargets})
  if(plugin STREQUAL "CommandTestHarness")
    set(filter "CommandTestHarnessTest.*")
  else()
    set(filter "${plugin}CommandTest.*")
  endif()
  add_test(NAME "QtPlugins-${plugin}"
    COMMAND AvogadroQtPluginsTests "--gtest_filter=${filter}")
  set_tests_properties("QtPlugins-${plugin}" PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    TIMEOUT 120)
endforeach()
