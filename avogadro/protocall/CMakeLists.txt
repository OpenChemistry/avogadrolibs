find_package(Eigen3 REQUIRED)
include_directories(SYSTEM ${EIGEN3_INCLUDE_DIR})

find_package(protobuf REQUIRED NO_MODULE)
include_directories(SYSTEM ${protobuf_INCLUDE_DIRS})

find_package(ProtoCall REQUIRED NO_MODULE)
include_directories(SYSTEM ${ProtoCall_INCLUDE_DIRS})

add_library(AvogadroProtoCall
  moleculeserializer.cpp
  moleculedeserializer.cpp
  matrixserialization.cpp
  )

target_link_libraries(AvogadroProtoCall AvogadroIO protobuf)
