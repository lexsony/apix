include_directories(./)

add_executable(apix-default apix-default.c opt.c)
target_link_libraries(apix-default apix)

add_executable(apix-cli apix-cli.c opt.c cli.c)
target_link_libraries(apix-cli apix readline tinfo pthread)

install(TARGETS apix-default apix-cli
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)
