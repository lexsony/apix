cmake_minimum_required(VERSION 3.12)

add_executable(apix-cli apix-cli.c opt.c cli.c)
target_link_libraries(apix-cli apix readline tinfo pthread)

add_executable(apix-client-3333 apix-client-3333.c opt.c)
target_link_libraries(apix-client-3333 apix)

add_executable(apix-client-8888 apix-client-8888.c opt.c)
target_link_libraries(apix-client-8888 apix)

add_executable(apix-server apix-server.c opt.c)
target_link_libraries(apix-server apix)
set(TARGET_EXEC ${TARGET_EXEC} apix-server)

add_executable(apix-debugger apix-debugger.c opt.c cli.c)
target_link_libraries(apix-debugger apix readline tinfo pthread)

install(TARGETS ${TARGET_EXEC}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)
