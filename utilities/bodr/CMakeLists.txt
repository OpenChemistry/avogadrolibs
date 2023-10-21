add_executable(bodrparse bodrparse.cxx)
target_link_libraries(bodrparse PRIVATE Avogadro::Headers pugixml::pugixml)
