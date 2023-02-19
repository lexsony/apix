cmake_minimum_required(VERSION 3.12)

include_directories(./)

add_executable(apix-cli apix-cli.c opt.c cli.c)
target_link_libraries(apix-cli apix readline tinfo pthread)

install(TARGETS ${TARGET_EXEC}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)
