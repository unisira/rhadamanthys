cmake_minimum_required(VERSION 3.24)

project(payload-decryptor)

set(CMAKE_BUILD_TYPE Debug)

add_executable(${PROJECT_NAME}
	src/main.cpp
)
