Include(ExternalProject)
set(prefix "${CMAKE_BINARY_DIR}/deps")
set(LIBFQFFT_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}libsnark${CMAKE_STATIC_LIBRARY_PREFIX}")
set(LIBFQFFT_INCLUDE_DIR "{prefix}/include")

ExternalProject_Add(libfqfft
    PREFIX "${prefix}"
    DOWNLOAD_NAME libfqfft.zip
    DOWNLOAD_NO_PROGRESS TRUE
    URL https://github.com/scipr-lab/libfqfft/archive/master.zip
    URL_HASH
    SHA256=5e0b43a965cd3aa3040c0065db1c18782f77915d2bb230e6907db825335efc66
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DCMAKE_INSTALL_LIBDIR=lib
        -DCMAKE_BUILD_TYPE=Release
    BUILD_BYPRODUCTS "${LIBSNARK_LIBRARY}"
)

add_library(LIBFQFFT::libfqfft STATIC IMPORTED)
set_property(TARGET LIBFQFFT::libfqfft PROPERTY IMPORTED_CONFIGURATIONS Release)
set_property(TARGET LIBFQFFT::libfqfft PROPERTY IMPORTED_LOCATION_RELEASE ${LIBFQFFT_LIBRARY})
set_property(TARGET LIBFQFFT::libfqfft PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${LIBFQFFT_INCLUDE_DIR})
add_dependencies(LIBFQFFT::libfqfft fqfft)
