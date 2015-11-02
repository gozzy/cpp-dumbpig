project(cpp-dumbpig)

cmake_minimum_required(VERSION 2.8)
find_package(Boost REQUIRED COMPONENTS program_options)

add_definitions("-Wall -O2 -std=c++11")

add_executable(dumbpig src/arg_checkers.cpp src/rule_checker.cpp src/dumbpig.cpp)
target_link_libraries(dumbpig ${Boost_LIBRARIES})
