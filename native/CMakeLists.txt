# Android NDK build (referenced from android/app/build.gradle.kts).
cmake_minimum_required(VERSION 3.18)
project(spacecop_crypto C)
add_library(spacecop_crypto SHARED spacecop_crypto.c)
target_compile_options(spacecop_crypto PRIVATE -O3 -std=c99 -Wall -fvisibility=hidden)
