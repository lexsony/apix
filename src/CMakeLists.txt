cmake_minimum_required(VERSION 3.12)

file(GLOB SRC *.c)
file(GLOB INC apix.h apix-posix.h srrp.h svcx.h log.h atbuf.h ringbuf.h)

if (BUILD_STATIC)
    add_library(apix-static STATIC ${SRC} ${SRC_POSIX})
    set_target_properties(apix-static PROPERTIES OUTPUT_NAME apix)
    set_target_properties(apix-static PROPERTIES PUBLIC_HEADER "${INC}")
    set(TARGET_STATIC apix-static)
endif ()

if (BUILD_SHARED)
    add_library(apix SHARED ${SRC} ${SRC_POSIX})
    set_target_properties(apix PROPERTIES PUBLIC_HEADER "${INC}")
    set_target_properties(apix PROPERTIES VERSION 0.0.1 SOVERSION 0)
    set(TARGET_SHARED apix)
endif ()

install(TARGETS ${TARGET_STATIC} ${TARGET_SHARED}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/apix
)

install(DIRECTORY "${CMAKE_SOURCE_DIR}/src/ext" # source directory
        DESTINATION "include" # target directory
        FILES_MATCHING # install only matched files
        PATTERN "*.h" # select header files
)
