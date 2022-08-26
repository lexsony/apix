cmake_minimum_required(VERSION 3.12)

add_executable(test-log test_log.c)
target_link_libraries(test-log cmocka apix)
add_test(test-log ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-log)

add_executable(test-opt test_opt.c)
target_link_libraries(test-opt cmocka apix)
add_test(test-opt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-opt)

add_executable(test-ringbuf test_ringbuf.c)
target_link_libraries(test-ringbuf cmocka apix)
add_test(test-ringbuf ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-ringbuf)

add_executable(test-atbuf test_atbuf.c)
target_link_libraries(test-atbuf cmocka apix)
add_test(test-atbuf ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-atbuf)

add_executable(test-srrp test_srrp.c)
target_link_libraries(test-srrp cmocka apix)
add_test(test-srrp ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-srrp)

add_executable(test-json test_json.c)
target_link_libraries(test-json cmocka apix)
add_test(test-json ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-json)

add_executable(test-apix test_apix.c)
target_link_libraries(test-apix cmocka apix pthread)
add_test(test-apix ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-apix)

add_executable(test-svcx test_svcx.c)
target_link_libraries(test-svcx cmocka apix)
add_test(test-svcx ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-svcx)
