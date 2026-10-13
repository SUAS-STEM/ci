cmake_minimum_required(VERSION 3.20)
project(SyntheticAdder LANGUAGES CXX)

add_executable(synthetic_adder src/synthetic_adder.cpp)
target_compile_features(synthetic_adder PRIVATE cxx_std_17)

enable_testing()
add_test(NAME public_source_smoke COMMAND synthetic_adder 7 11)
set_tests_properties(public_source_smoke PROPERTIES PASS_REGULAR_EXPRESSION "^18")
