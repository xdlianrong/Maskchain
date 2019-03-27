Include(ExternalProject)
set(prefix "${CMAKE_BINARY_DIR}/deps")
set(LIBSNARK_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}libsnark${CMAKE_STATIC_LIBRARY_PREFIX}")
set(LIBSNARK_INCLUDE_DIR "{prefix}/include")

ExternalProject_Add(libsnark
    PREFIX "${prefix}"
    DOWNLOAD_NAME libsnark.zip
    DOWNLOAD_NO_PROGRESS TRUE
    URL https://github.com/scipr-lab/libsnark/archive/master.zip
    URL_HASH
    SHA256=84be147f4511847947335aa240b1fb53ee2892bcabb6c4c15f69c0a2d1e23a8e
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DCMAKE_INSTALL_LIBDIR=lib
        -DCMAKE_BUILD_TYPE=Release
    BUILD_BYPRODUCTS "${LIBSNARK_LIBRARY}"
)

add_library(LIBSNARK::libsnark STATIC IMPORTED)
set_property(TARGET LIBSNARK::libsnark PROPERTY IMPORTED_CONFIGURATIONS Release)
set_property(TARGET LIBSNARK::libsnark PROPERTY IMPORTED_LOCATION_RELEASE ${LIBSNARK_LIBRARY})
set_property(TARGET LIBSNARK::libsnark PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${LIBSNARK_INCLUDE_DIR})
add_dependencies(LIBSNARK::libsnark snark)