cmake_minimum_required(VERSION 3.12)

add_executable(apix-client-serial apix-client-serial.c)
target_link_libraries(apix-client-serial apix)

add_executable(apix-client-tcp apix-client-tcp.c)
target_link_libraries(apix-client-tcp apix)

add_executable(apix-server apix-server.c)
target_link_libraries(apix-server apix)
