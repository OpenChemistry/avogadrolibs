set(CTEST_CUSTOM_COVERAGE_EXCLUDE
  
  "tests.*.cpp"
  # Exclude all third party code.
  ".*/thirdparty/.*"
  # Exclude MOC files (Qt).
  "moc_"
  )

set(CTEST_CUSTOM_WARNING_EXCEPTION
  
  # Exclude all third party code.
  ".*/thirdparty/.*"
  # Qt5Json snapshot
  ".*/qt5json/.*"
  # Nested Qt foreach loops produce this warning:
  "_container_.* shadows a previous local"
  "shadowed declaration is here"
  )
