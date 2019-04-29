include_directories(.)

install(
  DIRECTORY "" DESTINATION "include/libfqfft"
  FILES_MATCHING
  PATTERN "*.hpp"
  PATTERN "*.tcc"
  PATTERN "logs" EXCLUDE
  PATTERN "tests" EXCLUDE
  PATTERN "tutorials" EXCLUDE
)

