cmake_minimum_required(VERSION 3.17)

#include(${CMAKE_CURRENT_LIST_DIR}/../../../hw/bsp/family_support.cmake)
include(${PICO_SDK_PATH}/lib/tinyusb/hw/bsp/family_support.cmake)

# gets PROJECT name for the example (e.g. <BOARD>-<DIR_NAME>)
family_get_project_name(PROJECT ${CMAKE_CURRENT_LIST_DIR})


project(${PROJECT} C CXX ASM)

# Checks this example is valid for the family and initializes the project
family_initialize_project(${PROJECT} ${CMAKE_CURRENT_LIST_DIR})

add_executable(${PROJECT})

# Example source
target_sources(${PROJECT} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/src/main.c
  ${CMAKE_CURRENT_LIST_DIR}/src/rand.c
  ${CMAKE_CURRENT_LIST_DIR}/src/motd.c
  ${CMAKE_CURRENT_LIST_DIR}/src/usb_descriptors.c
  ${CMAKE_CURRENT_LIST_DIR}/../../wolftcp.c
  )

# Example include
target_include_directories(${PROJECT} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/src
  ${CMAKE_CURRENT_LIST_DIR}/../../..
  )

# lib/networking sources
target_sources(${PROJECT} PUBLIC
  )


# due to warnings from other net source, we need to prevent error from some of the warnings options
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
  target_compile_options(${PROJECT} PUBLIC
    -Wno-error=null-dereference
    -Wno-error=conversion
    -Wno-error=sign-conversion
    -Wno-error=sign-compare
    -Wno-error=cast-align
    )
elseif (CMAKE_C_COMPILER_ID STREQUAL "IAR")

endif ()
target_link_libraries(${PROJECT} PUBLIC hardware_adc)

# Configure compilation flags and libraries for the example without RTOS.
# See the corresponding function in hw/bsp/FAMILY/family.cmake for details.
family_configure_device_example(${PROJECT} noos)
