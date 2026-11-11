cmake_minimum_required(VERSION 3.20)
project(babylon_format_parser LANGUAGES CXX)

include(CTest)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(babylon_format_parser STATIC src/format_parser.cpp)
target_include_directories(babylon_format_parser PUBLIC include)

add_executable(babylon-format-parser src/main.cpp)
target_link_libraries(babylon-format-parser PRIVATE babylon_format_parser)

if(MSVC)
  set_property(TARGET babylon_format_parser babylon-format-parser
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  target_compile_options(babylon_format_parser PRIVATE /W4 /WX)
  target_compile_options(babylon-format-parser PRIVATE /W4 /WX)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  target_compile_options(babylon_format_parser PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_compile_options(babylon-format-parser PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_link_options(babylon-format-parser PRIVATE -static-libstdc++ -static-libgcc)
else()
  target_compile_options(babylon_format_parser PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_compile_options(babylon-format-parser PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

install(TARGETS babylon-format-parser RUNTIME DESTINATION .)

if(BUILD_TESTING)
  add_executable(format_parser_tests tests/format_parser_tests.cpp)
  target_link_libraries(format_parser_tests PRIVATE babylon_format_parser)
  if(MSVC)
    set_property(TARGET format_parser_tests
      PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_options(format_parser_tests PRIVATE /W4 /WX)
  else()
    target_compile_options(format_parser_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME format_parser_tests COMMAND format_parser_tests)
endif()
