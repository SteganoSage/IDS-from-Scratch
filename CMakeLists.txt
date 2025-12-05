cmake_minimum_required(VERSION 3.10)
project(IDS_From_Scratch CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# include dirs and link flags from pkg-config
include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})
add_definitions(${PCAP_CFLAGS_OTHER})

add_executable(ids src/main.cpp)

target_link_libraries(ids PRIVATE ${PCAP_LIBRARIES})
# if using threads / ssl later, add those libs as well:
# target_link_libraries(ids PRIVATE ${PCAP_LIBRARIES} OpenSSL::Crypto pthread)
