cmake_minimum_required(VERSION 3.12)

add_executable(apix-client-serial-3333 apix-client-serial-3333.c)
target_link_libraries(apix-client-serial-3333 apix)

add_executable(apix-client-tcp-3333 apix-client-tcp-3333.c)
target_link_libraries(apix-client-tcp-3333 apix)

add_executable(apix-client-tcp-8888 apix-client-tcp-8888.c)
target_link_libraries(apix-client-tcp-8888 apix)

add_executable(apix-client apix-client.c opt.c cli.c)
target_link_libraries(apix-client apix readline)

add_executable(apix-server apix-server.c opt.c)
target_link_libraries(apix-server apix)
