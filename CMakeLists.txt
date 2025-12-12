cmake_minimum_required(VERSION 3.10)
project(IDS_From_Scratch VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)

# Find pkg-config and libpcap via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

if(PCAP_FOUND)
    message(STATUS "Found libpcap: ${PCAP_LIBRARIES} (includes: ${PCAP_INCLUDE_DIRS})")
else()
    message(FATAL_ERROR "libpcap not found. Install libpcap-dev and retry.")
endif()

# Optional: find Threads and OpenSSL if you will use them
find_package(Threads REQUIRED)
find_package(OpenSSL QUIET)

# Add executable
add_executable(ids
    src/main2.cpp
    src/packet.cpp
    src/queue.cpp
    src/packet_parser.cpp
    src/capture.cpp
    src/worker.cpp
    src/utils.cpp
    src/rule_parser.cpp
    src/rule_matcher.cpp

)

# Use target-specific include/link/compile options (safer)
target_include_directories(ids PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(ids PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_directories(ids PRIVATE ${PCAP_LIBRARY_DIRS})

# Apply compile flags from pkg-config (if any)
if(PCAP_CFLAGS_OTHER)
    # PCAP_CFLAGS_OTHER may contain flags that belong to the compiler invocation
    target_compile_options(ids PRIVATE ${PCAP_CFLAGS_OTHER})
endif()

# Link libpcap
target_link_libraries(ids PRIVATE ${PCAP_LIBRARIES})

# Link Threads (pthread) - good to always add for threaded programs
target_link_libraries(ids PRIVATE Threads::Threads)

# Link OpenSSL if found (for hashing in HIDS)
if(OpenSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
    target_link_libraries(ids PRIVATE OpenSSL::Crypto)
endif()

# Optional: useful install target
install(TARGETS ids RUNTIME DESTINATION bin)
