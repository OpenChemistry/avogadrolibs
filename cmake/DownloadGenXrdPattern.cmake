# Written by Patrick S. Avery - 2018

# Downloads the executable if it doesn't already exist
macro(DownloadGenXrdPattern)

  # Let's set the name. Windows likes to add '.exe' at the end
  if(WIN32)
    set(GENXRDPATTERN_NAME "genXrdPattern.exe")
  else(WIN32)
    set(GENXRDPATTERN_NAME "genXrdPattern")
  endif(WIN32)

  # If it already exists, don't download it again
  if(NOT EXISTS "${CMAKE_CURRENT_BINARY_DIR}/bin/${GENXRDPATTERN_NAME}")
    set(GENXRDPATTERN_V "1.0-static")
    # Linux
    if(UNIX AND NOT APPLE)
      set(GENXRDPATTERN_DOWNLOAD_LOCATION "https://github.com/psavery/genXrdPattern/releases/download/${GENXRDPATTERN_V}/linux64-genXrdPattern")
      set(MD5 "e1b3c1d6b951ed83a037567490d75f1d")

    # Apple
    elseif(APPLE)
      set(GENXRDPATTERN_DOWNLOAD_LOCATION "https://github.com/psavery/genXrdPattern/releases/download/${GENXRDPATTERN_V}/osx64-genXrdPattern")
      set(MD5 "229b01c8efab981d812043684dae84fe")

    # Windows
    elseif(WIN32 AND NOT CYGWIN)
      set(GENXRDPATTERN_DOWNLOAD_LOCATION "https://github.com/psavery/genXrdPattern/releases/download/${GENXRDPATTERN_V}/win64-genXrdPattern.exe")
      set(MD5 "7b1a1e18a6044773c631189cbfd8b440")

    else()
      message(FATAL_ERROR
              "GenXrdPattern is not supported with the current OS type!")
    endif()

    message(STATUS "Downloading genXrdPattern executable from ${GENXRDPATTERN_DOWNLOAD_LOCATION}")

    # Install to a temporary directory so we can copy and change file
    # permissions
    file(DOWNLOAD "${GENXRDPATTERN_DOWNLOAD_LOCATION}"
         "${CMAKE_CURRENT_BINARY_DIR}/tmp/${GENXRDPATTERN_NAME}"
         SHOW_PROGRESS
         EXPECTED_MD5 ${MD5})

    # We need to change the permissions
    file(COPY "${CMAKE_CURRENT_BINARY_DIR}/tmp/${GENXRDPATTERN_NAME}"
         DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/bin/"
         FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                          GROUP_READ GROUP_EXECUTE
                          WORLD_READ WORLD_EXECUTE)

    # Now remove the temporary directory
    file(REMOVE_RECURSE "${CMAKE_CURRENT_BINARY_DIR}/tmp")

  endif(NOT EXISTS "${CMAKE_CURRENT_BINARY_DIR}/bin/${GENXRDPATTERN_NAME}")

  set(GENXRDPATTERN_DESTINATION "bin")

  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/bin/${GENXRDPATTERN_NAME}"
          DESTINATION "${GENXRDPATTERN_DESTINATION}"
          PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                      GROUP_READ GROUP_EXECUTE
                      WORLD_READ WORLD_EXECUTE)

endmacro(DownloadGenXrdPattern)
