# Minimum CMake version
cmake_minimum_required(VERSION 3.15)

# Project name and C++ standard
project(SecureConnect)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the executable
add_executable(SecureConnect
    main.cpp
    auth_service.cpp
    subscription_service.cpp
    vpn_server.cpp
    wireguard_manager.cpp
)

# Include directories for dependencies
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)

# Find dependencies using vcpkg
# Specify the directory containing asioConfig.cmake if not found automatically
set(asio_DIR "path/to/asio/cmake/directory")
find_package(asio CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# Link libraries
target_link_libraries(SecureConnect PRIVATE
    asio::asio
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Enable multithreading
if (WIN32)
    target_link_libraries(SecureConnect PRIVATE ws2_32)
else()
    target_link_libraries(SecureConnect PRIVATE pthread)
endif()