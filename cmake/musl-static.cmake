set(MUSL TRUE)
set(CMAKE_C_COMPILER musl-gcc)
set(CMAKE_CXX_COMPILER musl-gcc)
set(CMAKE_EXE_LINKER_FLAGS "-static")
