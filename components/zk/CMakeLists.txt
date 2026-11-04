set(MCL "${CMAKE_CURRENT_LIST_DIR}/mcl")

idf_component_register(
  SRCS "g16.c" "g16_poseidon.c" "zk_event.c" "${MCL}/src/fp.cpp"
  INCLUDE_DIRS "include" "${MCL}/include"
  PRIV_INCLUDE_DIRS "${MCL}/src"
)

# mcl as portable C++ for one curve: 32-bit limbs, 256-bit fields, no
# assembly, no JIT, no exceptions. The same definitions go to every file that
# includes mcl/bn.h, so they are public.
target_compile_definitions(${COMPONENT_LIB} PUBLIC
  MCL_STANDALONE MCL_SIZEOF_UNIT=4 MCL_FP_BIT=256 MCL_FR_BIT=256 MCL_BINT_ASM=0 MCL_DONT_USE_XBYAK)
target_compile_definitions(${COMPONENT_LIB} PRIVATE NDEBUG)
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
set_source_files_properties("${MCL}/src/fp.cpp" PROPERTIES
  COMPILE_OPTIONS "-fno-exceptions;-fno-rtti;-fno-threadsafe-statics;-std=gnu++17;-Wno-error")
