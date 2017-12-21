#Standard stuff
cmake_minimum_required(VERSION 2.6)
project(tcp_closer)

set(CMAKE_C_FLAGS "-O1 -Wall -std=gnu99")

find_library(LIBMNL_LIBRARY mnl)

set(SOURCE
    tcp_closer.c
    tcp_closer_proc.c
    tcp_closer_netlink.c
) 

add_executable(${PROJECT_NAME} ${SOURCE})
target_link_libraries(${PROJECT_NAME} ${LIBMNL_LIBRARY})
