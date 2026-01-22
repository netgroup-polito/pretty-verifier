# Copyright 2024-2025 Politecnico di Torino

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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