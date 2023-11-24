cmake_minimum_required(VERSION 3.1)

project(tinycolormap CXX)
set(CMAKE_CXX_STANDARD 11)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/tinycolormap.hpp DESTINATION include)

add_library(tinycolormap INTERFACE)
target_sources(tinycolormap INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include/tinycolormap.hpp)
target_include_directories(tinycolormap INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

option(TINYCOLORMAP_WITH_EIGEN "Enable Eigen integration" OFF)
if(TINYCOLORMAP_WITH_EIGEN)
	find_package(Eigen3 REQUIRED)
	if((NOT TARGET Eigen3::Eigen) AND (DEFINED EIGEN3_INCLUDE_DIR))
		add_library(AliasEigen3 INTERFACE)
		target_include_directories(AliasEigen3 INTERFACE ${EIGEN3_INCLUDE_DIR})
		add_library(Eigen3::Eigen ALIAS AliasEigen3)
	endif()

	target_link_libraries(tinycolormap INTERFACE Eigen3::Eigen)
	target_compile_definitions(tinycolormap INTERFACE TINYCOLORMAP_WITH_EIGEN)
endif()

option(TINYCOLORMAP_WITH_QT5 "Enable Qt5 integration" OFF)
if(TINYCOLORMAP_WITH_QT5)
	# Append typical paths for Qt for macOS users
	if(APPLE AND EXISTS /usr/local/opt/qt5)
		list(APPEND CMAKE_PREFIX_PATH "/usr/local/opt/qt5")
	endif()
	if(APPLE AND EXISTS /usr/local/opt/qt)
		list(APPEND CMAKE_PREFIX_PATH "/usr/local/opt/qt")
	endif()

	find_package(Qt5 COMPONENTS Gui REQUIRED)
	target_link_libraries(tinycolormap INTERFACE Qt5::Gui)
	target_compile_definitions(tinycolormap INTERFACE TINYCOLORMAP_WITH_QT5)
endif()

option(TINYCOLORMAP_WITH_GLM "Enable GLM integration" OFF)

option(TINYCOLORMAP_BUILD_TOOLS "Build tools" OFF)
if(TINYCOLORMAP_BUILD_TOOLS)
	add_subdirectory(tools/png-exporter)

	enable_testing()
	add_test(NAME png-exporter COMMAND $<TARGET_FILE:png-exporter> ${CMAKE_BINARY_DIR})
endif()
