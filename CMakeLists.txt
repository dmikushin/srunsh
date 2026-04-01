cmake_minimum_required(VERSION 3.14)
project(srunsh VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)

add_library(srunsh_common STATIC
    src/protocol.cpp
    src/crypto.cpp
)
target_include_directories(srunsh_common PUBLIC src)
target_link_libraries(srunsh_common PUBLIC OpenSSL::Crypto)

add_executable(srunsh src/client.cpp)
target_link_libraries(srunsh PRIVATE srunsh_common)

add_executable(srunshd src/server.cpp)
target_link_libraries(srunshd PRIVATE srunsh_common util)

add_executable(srunsh-keygen src/keygen.cpp)
target_link_libraries(srunsh-keygen PRIVATE srunsh_common)

install(TARGETS srunsh srunshd srunsh-keygen DESTINATION bin)
