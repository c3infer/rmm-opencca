
# Consider dependencies only in project.
set(CMAKE_DEPENDS_IN_PROJECT_ONLY OFF)

# The set of languages for which implicit dependencies are needed:
set(CMAKE_DEPENDS_LANGUAGES
  "ASM"
  )
# The set of files for implicit dependencies of each language:
set(CMAKE_DEPENDS_CHECK_ASM
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/src/aarch64/cache_helpers.S" "/home/amir/mica/staging/rmm-private-opencca/build-rk3588-opencca/lib/arch/CMakeFiles/rmm-lib-arch.dir/src/aarch64/cache_helpers.S.obj"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/src/aarch64/simd_helpers.S" "/home/amir/mica/staging/rmm-private-opencca/build-rk3588-opencca/lib/arch/CMakeFiles/rmm-lib-arch.dir/src/aarch64/simd_helpers.S.obj"
  )
set(CMAKE_ASM_COMPILER_ID "GNU")

# Preprocessor definitions for this target.
set(CMAKE_TARGET_DEFINITIONS_ASM
  "COMMIT_INFO=\"319be8b-dirty\""
  "DEBUG"
  "ENABLE_OPENCCA=1"
  "ENABLE_OPENCCA_PERF=0"
  "GRANULE_SHIFT=U(12)"
  "LOG_LEVEL=50"
  "MAX_CPUS=16U"
  "NAME=\"RMM\""
  "RMM_CCA_TOKEN_BUFFER=U(1)"
  "RMM_MAX_GRANULES=U(0x100000)"
  "RMM_NUM_PAGES_PER_STACK=UL(5)"
  "VERSION=\"0.5.0\""
  )

# The include file search paths:
set(CMAKE_ASM_TARGET_INCLUDE_PATH
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/include/aarch64"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/src/aarch64"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/src/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/debug/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/tests"
  "/home/amir/mica/staging/rmm-private-opencca/lib/common/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/common/include/aarch64"
  "/home/amir/mica/staging/rmm-private-opencca/lib/opencca/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/smc/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/libc/include"
  )

# The set of dependency files which are needed:
set(CMAKE_DEPENDS_DEPENDENCY_FILES
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/src/arch_features.c" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/arch_features.c.obj" "gcc" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/arch_features.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/src/pauth.c" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/pauth.c.obj" "gcc" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/pauth.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/src/pmu.c" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/pmu.c.obj" "gcc" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/pmu.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/src/simd.c" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/simd.c.obj" "gcc" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/simd.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/src/vmid.c" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/vmid.c.obj" "gcc" "lib/arch/CMakeFiles/rmm-lib-arch.dir/src/vmid.c.obj.d"
  )

# Targets to which this target links which contain Fortran sources.
set(CMAKE_Fortran_TARGET_LINKED_INFO_FILES
  )

# Targets to which this target links which contain Fortran sources.
set(CMAKE_Fortran_TARGET_FORWARD_LINKED_INFO_FILES
  )

# Fortran module output directory.
set(CMAKE_Fortran_TARGET_MODULE_DIR "")
