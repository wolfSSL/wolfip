cmake_minimum_required(VERSION 3.16)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_C_FLAGS "-Wall -Werror -Wextra -Wdeclaration-after-statement")
set(CMAKE_C_FLAGS_Debug "-g -ggdb")
set(CMAKE_C_FLAGS_Release "-O3")

project(wolfip LANGUAGES C)

if (BUILD_TESTING)
    enable_testing()
    set(TESTS_REQUIRED "REQUIRED")
    set(EXCLUDE_TEST_BINARY )
else()
    set(EXCLUDE_TEST_BINARY EXCLUDE_FROM_ALL)
endif()

find_package(wolfssl ${TESTS_REQUIRED})
find_package(Check ${TESTS_REQUIRED})
find_program(XXD_EXE xxd ${TESTS_REQUIRED})
find_program(OPENSSL_EXE openssl ${TESTS_REQUIRED})

if (NOT wolfssl_FOUND)
    message(STATUS "WolfSSL NOT found! Tests depending on WolfSSL are disabled")
endif()

if (XXD_EXE STREQUAL "XXD_EXE-NOTFOUND")
    message(STATUS "xxd NOT found! Tests depending on certificate support are disabled!")
    set(XXD_FOUND FALSE)
else()
    set(XXD_FOUND TRUE)
endif()

if (OPENSSL_EXE STREQUAL "OPENSSL_EXE-NOTFOUND")
    message(STATUS "openssl NOT found! Tests depending on certificate support are disabled!")
    set(OPENSSL_FOUND FALSE)
else()
    set(OPENSSL_FOUND TRUE)
endif()

string(TOLOWER "${CMAKE_SYSTEM_NAME}" CMAKE_SYSTEM_NAME_LC)

set(WOLFIP_TAP_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/port/posix/tap_${CMAKE_SYSTEM_NAME_LC}.c")

if (NOT EXISTS "${WOLFIP_TAP_SRC}")
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

set(WOLFIP_SRCS src/wolfip.c ${WOLFIP_TAP_SRC})

set(CERT_SRCS
    ${CMAKE_BINARY_DIR}/certs/server_cert.c
    ${CMAKE_BINARY_DIR}/certs/server_key.c
    ${CMAKE_BINARY_DIR}/certs/ca_cert.c
    )

add_custom_command(
    OUTPUT ${CERT_SRCS}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tools/certs/mkcerts.sh ${CMAKE_BINARY_DIR}/certs
    BYPRODUCTS
        ${CMAKE_BINARY_DIR}/certs/ca.crt
        ${CMAKE_BINARY_DIR}/certs/ca.der
        ${CMAKE_BINARY_DIR}/certs/ca.srl
        ${CMAKE_BINARY_DIR}/certs/ca.key
        ${CMAKE_BINARY_DIR}/certs/server.crt
        ${CMAKE_BINARY_DIR}/certs/server.der
        ${CMAKE_BINARY_DIR}/certs/server.csr
        ${CMAKE_BINARY_DIR}/certs/server.key
        ${CMAKE_BINARY_DIR}/certs/server.key.der
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )

add_library(wolfip SHARED ${WOLFIP_SRCS} src/port/posix/bsd_socket.c)
target_include_directories(wolfip PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_library(tcpip STATIC ${WOLFIP_SRCS})
target_link_libraries(tcpip wolfip-core)
target_include_directories(tcpip PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test-evloop ${EXCLUDE_TEST_BINARY}
    src/test/test_eventloop.c
    ${WOLFIP_SRCS}
    )
add_test(NAME evloop COMMAND test-evloop)

add_executable(test-dns ${EXCLUDE_TEST_BINARY}
    src/test/test_dhcp_dns.c
    ${WOLFIP_SRCS}
    )
add_test(NAME dns COMMAND test-dns)

add_executable(tcpecho ${EXCLUDE_TEST_BINARY}
    src/test/tcp_echo.c
    src/port/posix/bsd_socket.c
    ${WOLFIP_SRCS}
    )
add_test(NAME tcpecho COMMAND tcpecho)

add_executable(tcp_netcat_poll ${EXCLUDE_TEST_BINARY}
    src/test/tcp_netcat_poll.c
    src/port/posix/bsd_socket.c
    ${WOLFIP_SRCS}
    )
add_test(NAME tcp_netcat_poll COMMAND tcp_netcat_poll)

add_executable(tcp_netcat_select ${EXCLUDE_TEST_BINARY}
    src/test/tcp_netcat_select.c
    src/port/posix/bsd_socket.c
    ${WOLFIP_SRCS}
    )
add_test(NAME tcp_netcat_select COMMAND tcp_netcat_select)


if (wolfssl_FOUND AND XXD_FOUND AND OPENSSL_FOUND)
    add_executable(test-wolfssl ${EXCLUDE_TEST_BINARY}
        src/test/test_native_wolfssl.c
        ${WOLFIP_SRCS}
        src/port/wolfssl_io.c
        ${CERT_SRCS}
        )
    target_compile_definitions(test-wolfssl PRIVATE -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP)
    target_compile_options(test-wolfssl PRIVATE -Wno-cpp)
    target_link_libraries(test-wolfssl wolfssl)
    add_test(NAME wolfssl COMMAND test-wolfssl)

    add_executable(ipfilter-logger ${EXCLUDE_TEST_BINARY}
        ${WOLFIP_SRCS}
        src/port/wolfssl_io.c
        src/port/posix/bsd_socket.c
        src/test/ipfilter_logger.c
        ${CERT_SRCS}
        )
    target_include_directories(ipfilter-logger PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(ipfilter-logger PRIVATE -DCONFIG_IPFILTER=1 -DWOLFSSL_WOLFIP)
    target_link_libraries(ipfilter-logger wolfssl)
    add_test(NAME ipfilter-logger COMMAND ipfilter-logger)

    add_executable(test-wolfssl-forwarding ${EXCLUDE_TEST_BINARY}
        src/test/test_wolfssl_forwarding.c
        ${WOLFIP_SRCS}
        src/port/wolfssl_io.c
        ${CERT_SRCS}
        )
    target_compile_definitions(test-wolfssl-forwarding PRIVATE -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1)
    target_compile_options(test-wolfssl-forwarding PRIVATE -Wno-cpp)
    target_link_libraries(test-wolfssl-forwarding wolfssl)
    add_test(NAME wolfssl-forwarding COMMAND test-wolfssl-forwarding)

    add_executable(test-httpd ${EXCLUDE_TEST_BINARY}
        src/test/test_httpd.c
        ${WOLFIP_SRCS}
        src/port/wolfssl_io.c
        ${CMAKE_BINARY_DIR}/certs/server_key.c
        ${CMAKE_BINARY_DIR}/certs/server_cert.c
        src/http/httpd.c
        )
    target_include_directories(test-httpd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/http)
    target_compile_definitions(test-httpd PRIVATE -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP)
    target_compile_options(test-httpd PRIVATE -Wno-cpp)
    target_link_libraries(test-httpd wolfssl)
    add_test(NAME httpd COMMAND test-httpd)
endif()

add_executable(test-ttl-expired ${EXCLUDE_TEST_BINARY}
    src/test/test_ttl_expired.c
    src/wolfip.c
    )
target_compile_definitions(test-ttl-expired PRIVATE -DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1)
add_test(NAME ttl-expired COMMAND test-ttl-expired)

if (NOT Check_FOUND)
    add_executable(unit ${EXCLUDE_TEST_BINARY}
        src/test/unit/unit.c
        )
    target_link_libraries(unit PRIVATE check)
    add_test(NAME unit COMMAND unit)
endif()

install(TARGETS wolfip RUNTIME DESTINATION bin)
