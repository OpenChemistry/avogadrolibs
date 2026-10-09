# Used to determine the version for OpenChemistry source using "git describe", if git
# is found. On success sets following variables in caller's scope:
#   ${var_prefix}_VERSION
#   ${var_prefix}_VERSION_MAJOR
#   ${var_prefix}_VERSION_MINOR
#   ${var_prefix}_VERSION_PATCH
#   ${var_prefix}_VERSION_PATCH_EXTRA
#   ${var_prefix}_VERSION_IS_RELEASE is patch-extra is empty.
#
# If "git describe" cannot be run successfully (e.g. a shallow clone without
# tags, as made by CI), the version already set in the caller's scope, such as
# 2.0.0, is extended with a date and, if available, the commit hash:
#   2.0.0-20261009-g6d14770
# The date is the date of the HEAD commit if git can provide it, otherwise the
# date (UTC) of the CMake configure step.
#
# When AVOGADRO_RELEASE_BUILD is ON, none of this is done and the version
# already set in the caller's scope is used unchanged. Release builds should
# set it, since they may not be built from a checkout that "git describe" can
# identify as the tagged release.
#
# Arguments are:
#   source_dir : Source directory
#   git_command : git executable
#   var_prefix : prefix for variables e.g. "AvogadroApp".

option(AVOGADRO_RELEASE_BUILD
  "Release build: use the version from CMakeLists.txt without a date or git suffix"
  OFF)

function(determine_version source_dir git_command var_prefix)
  set (major)
  set (minor)
  set (patch)
  set (full)
  set (patch_extra)

  if (AVOGADRO_RELEASE_BUILD)
    message(STATUS "Release build, using version ${${var_prefix}_VERSION}")
    set (${var_prefix}_VERSION_IS_RELEASE TRUE PARENT_SCOPE)
    return()
  endif()

  set (have_git FALSE)
  if (git_command AND EXISTS "${git_command}")
    set (have_git TRUE)
  endif()

  if (have_git)
    execute_process(
      COMMAND ${git_command} describe
      WORKING_DIRECTORY ${source_dir}
      RESULT_VARIABLE result
      OUTPUT_VARIABLE output
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_STRIP_TRAILING_WHITESPACE)
    if (result EQUAL 0)
      string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.([0-9]+)[-]*(.*)"
        version_matches ${output})
      if (CMAKE_MATCH_0)
        message(STATUS "Determined Source Version : ${CMAKE_MATCH_0}")
        set (full ${CMAKE_MATCH_0})
        set (major ${CMAKE_MATCH_1})
        set (minor ${CMAKE_MATCH_2})
        set (patch ${CMAKE_MATCH_3})
        set (patch_extra ${CMAKE_MATCH_4})
      endif()
    endif()
  endif()

  if (NOT full)
    # No usable tag (e.g. a shallow clone), so use a date instead.
    # --date=short is old enough to be everywhere, unlike %cs or format:
    set (date)
    set (hash)
    if (have_git)
      execute_process(
        COMMAND ${git_command} log -1 --format=%cd --date=short
        WORKING_DIRECTORY ${source_dir}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE)
      if (result EQUAL 0 AND output MATCHES "^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])$")
        set (date "${CMAKE_MATCH_1}${CMAKE_MATCH_2}${CMAKE_MATCH_3}")
      endif()

      execute_process(
        COMMAND ${git_command} rev-parse --short HEAD
        WORKING_DIRECTORY ${source_dir}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE)
      if (result EQUAL 0 AND output MATCHES "^[0-9a-f]+$")
        set (hash "${output}")
      endif()
    endif()

    if (NOT date)
      string(TIMESTAMP date "%Y%m%d" UTC)
    endif()

    set (major ${${var_prefix}_VERSION_MAJOR})
    set (minor ${${var_prefix}_VERSION_MINOR})
    set (patch ${${var_prefix}_VERSION_PATCH})
    set (patch_extra "${date}")
    if (hash)
      set (patch_extra "${patch_extra}-g${hash}")
    endif()
    set (full "${major}.${minor}.${patch}-${patch_extra}")
    message(STATUS
      "Could not use git describe to determine source version, using ${full}")
  endif()

  set (${var_prefix}_VERSION ${full} PARENT_SCOPE)
  set (${var_prefix}_VERSION_MAJOR ${major} PARENT_SCOPE)
  set (${var_prefix}_VERSION_MINOR ${minor} PARENT_SCOPE)
  set (${var_prefix}_VERSION_PATCH ${patch} PARENT_SCOPE)
  set (${var_prefix}_VERSION_PATCH_EXTRA ${patch_extra} PARENT_SCOPE)
  if ("${major}.${minor}.${patch}" STREQUAL "${full}")
    set (${var_prefix}_VERSION_IS_RELEASE TRUE PARENT_SCOPE)
  else ()
    set (${var_prefix}_VERSION_IS_RELEASE FALSE PARENT_SCOPE)
  endif()
endfunction()
