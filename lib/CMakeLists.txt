cmake_minimum_required(VERSION 3.10)
project(pretty-verifier C)

# Use C99 standard
set(CMAKE_C_STANDARD 99)

# Define source files
set(SOURCES src/pretty_verifier.c)

# Create the Shared Library (.so)
add_library(pretty-verifier SHARED ${SOURCES})

# Configure include directories
# This allows including <pretty_verifier.h> inside this project and by consumers
target_include_directories(pretty-verifier PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# --- Installation Rules (sudo make install) ---
include(GNUInstallDirs)

# Install the library binary (libpretty-verifier.so)
install(TARGETS pretty-verifier
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install the header file
install(FILES include/pretty_verifier.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})