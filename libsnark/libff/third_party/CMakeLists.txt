add_subdirectory(gtest EXCLUDE_FROM_ALL)

# TODO(scripr-lab): upstream these buildsystems to the respective
# projects.

set(CURVE "BN128")
if(${CURVE} STREQUAL "BN128")
  include_directories(ate-pairing/include)
  include_directories(xbyak)
  add_library(
    zm
    STATIC

    ate-pairing/src/zm.cpp
    ate-pairing/src/zm2.cpp
  )
endif()
