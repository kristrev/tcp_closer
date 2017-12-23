#Standard stuff
cmake_minimum_required(VERSION 2.6)
project(tcp_closer)

set(CMAKE_C_FLAGS "-O1 -Wall -std=gnu99 -g")

find_library(LIBMNL_LIBRARY mnl)

set(SOURCE
    tcp_closer.c
    tcp_closer_proc.c
    tcp_closer_netlink.c
    backend_event_loop.c
) 

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Kristian Evensen <kristian.evensen@gmail.com>")
set(CPACK_DEBIAN_PACKAGE_NAME "tcp-closer")
set(CPACK_DEBIAN_PACKAGE_VERSION "0.1-1")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libmnl0")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "tcp_closer is a command-line application for closing sockets based on source and destination port. The main purpose of this tool is to destroy connections that have been idling for too long, for example due to broken application-layer keep-alive protocols or middleboxes that interfer")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog;")
INCLUDE(CPack)

add_executable(${PROJECT_NAME} ${SOURCE})
target_link_libraries(${PROJECT_NAME} ${LIBMNL_LIBRARY})
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION sbin)
