
# Consider dependencies only in project.
set(CMAKE_DEPENDS_IN_PROJECT_ONLY OFF)

# The set of languages for which implicit dependencies are needed:
set(CMAKE_DEPENDS_LANGUAGES
  "ASM"
  )
# The set of files for implicit dependencies of each language:
set(CMAKE_DEPENDS_CHECK_ASM
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/aarch64/entry.S" "/home/amir/mica/staging/rmm-private-opencca/build-qemu-smoke/runtime/CMakeFiles/rmm-runtime.dir/core/aarch64/entry.S.obj"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/aarch64/head.S" "/home/amir/mica/staging/rmm-private-opencca/build-qemu-smoke/runtime/CMakeFiles/rmm-runtime.dir/core/aarch64/head.S.obj"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/aarch64/helpers.S" "/home/amir/mica/staging/rmm-private-opencca/build-qemu-smoke/runtime/CMakeFiles/rmm-runtime.dir/core/aarch64/helpers.S.obj"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/aarch64/run-asm.S" "/home/amir/mica/staging/rmm-private-opencca/build-qemu-smoke/runtime/CMakeFiles/rmm-runtime.dir/core/aarch64/run-asm.S.obj"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/aarch64/vectors.S" "/home/amir/mica/staging/rmm-private-opencca/build-qemu-smoke/runtime/CMakeFiles/rmm-runtime.dir/core/aarch64/vectors.S.obj"
  )
set(CMAKE_ASM_COMPILER_ID "GNU")

# Preprocessor definitions for this target.
set(CMAKE_TARGET_DEFINITIONS_ASM
  "ATTEST_EL3_TOKEN_SIGN=0"
  "COMMIT_INFO=\"319be8b-dirty\""
  "DEBUG"
  "ENABLE_OPENCCA=OFF"
  "ENABLE_OPENCCA_PERF=OFF"
  "GRANULE_SHIFT=U(12)"
  "LOG_LEVEL=50"
  "MAX_CPUS=32U"
  "MBEDTLS_CONFIG_FILE=<rmm_mbedtls_config.h>"
  "NAME=\"RMM\""
  "RMM_CCA_TOKEN_BUFFER=U(1)"
  "RMM_MAX_GRANULES=U(0x100000)"
  "RMM_NUM_PAGES_PER_STACK=UL(5)"
  "RSI_LOG_LEVEL=40"
  "VERSION=\"0.5.0\""
  "XLAT_GRANULARITY_SIZE_SHIFT=UL(12)"
  )

# The include file search paths:
set(CMAKE_ASM_TARGET_INCLUDE_PATH
  "/home/amir/mica/staging/rmm-private-opencca/runtime/include"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/tests"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/arch/include/aarch64"
  "/home/amir/mica/staging/rmm-private-opencca/lib/common/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/common/include/aarch64"
  "/home/amir/mica/staging/rmm-private-opencca/lib/opencca/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/debug/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/allocator/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/attestation/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/measurement/include"
  "/home/amir/mica/staging/rmm-private-opencca/configs/mbedtls"
  "/home/amir/mica/staging/rmm-private-opencca/ext/mbedtls/include"
  "/home/amir/mica/staging/rmm-private-opencca/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/smc/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/t_cose/include"
  "/home/amir/mica/staging/rmm-private-opencca/ext/t_cose/inc"
  "/home/amir/mica/staging/rmm-private-opencca/ext/t_cose/crypto_adapters"
  "/home/amir/mica/staging/rmm-private-opencca/ext/qcbor/inc"
  "/home/amir/mica/staging/rmm-private-opencca/lib/console/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/gic/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/granule/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/granule/include/aarch64"
  "/home/amir/mica/staging/rmm-private-opencca/lib/rmm_el3_ifc/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/s2tt/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/slot_buf/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/xlat/include"
  "/home/amir/mica/staging/rmm-private-opencca/lib/libc/include"
  )

# The set of dependency files which are needed:
set(CMAKE_DEPENDS_DEPENDENCY_FILES
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/app_compat.c" "runtime/CMakeFiles/rmm-runtime.dir/core/app_compat.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/core/app_compat.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/exit.c" "runtime/CMakeFiles/rmm-runtime.dir/core/exit.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/core/exit.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/handler.c" "runtime/CMakeFiles/rmm-runtime.dir/core/handler.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/core/handler.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/init.c" "runtime/CMakeFiles/rmm-runtime.dir/core/init.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/core/init.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/inject_exp.c" "runtime/CMakeFiles/rmm-runtime.dir/core/inject_exp.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/core/inject_exp.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/run.c" "runtime/CMakeFiles/rmm-runtime.dir/core/run.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/core/run.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/sysregs.c" "runtime/CMakeFiles/rmm-runtime.dir/core/sysregs.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/core/sysregs.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/core/timers.c" "runtime/CMakeFiles/rmm-runtime.dir/core/timers.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/core/timers.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/feature.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/feature.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/feature.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/granule.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/granule.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/granule.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/private_shared_table.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/private_shared_table.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/private_shared_table.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/psr_hpa_share_table.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/psr_hpa_share_table.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/psr_hpa_share_table.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/realm.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/realm.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/realm.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/realm_add_meta.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/realm_add_meta.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/realm_add_meta.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/rec.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/rec.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/rec.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/rmi_rsi_count.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/rmi_rsi_count.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/rmi_rsi_count.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/rtt.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/rtt.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/rtt.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/rtt_unknown_shared.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/rtt_unknown_shared.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/rtt_unknown_shared.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/run.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/run.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/run.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rmi/version.c" "runtime/CMakeFiles/rmm-runtime.dir/rmi/version.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rmi/version.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/config.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/config.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/config.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/feature.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/feature.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/feature.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/host_call.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/host_call.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/host_call.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/logger.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/logger.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/logger.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/memory.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/memory.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/memory.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/policy.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/policy.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/policy.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/policy_parser.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/policy_parser.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/policy_parser.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/policy_validator.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/policy_validator.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/policy_validator.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/policy_validator_actions.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/policy_validator_actions.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/policy_validator_actions.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/psci.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/psci.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/psci.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/realm_attest.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/realm_attest.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/realm_attest.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/realm_attest_group.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/realm_attest_group.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/realm_attest_group.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/realm_ipa_helper.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/realm_ipa_helper.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/realm_ipa_helper.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/sgt.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/sgt.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/sgt.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/sgt_granules.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/sgt_granules.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/sgt_granules.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/transition_table.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/transition_table.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/transition_table.c.obj.d"
  "/home/amir/mica/staging/rmm-private-opencca/runtime/rsi/version.c" "runtime/CMakeFiles/rmm-runtime.dir/rsi/version.c.obj" "gcc" "runtime/CMakeFiles/rmm-runtime.dir/rsi/version.c.obj.d"
  )

# Targets to which this target links which contain Fortran sources.
set(CMAKE_Fortran_TARGET_LINKED_INFO_FILES
  )

# Targets to which this target links which contain Fortran sources.
set(CMAKE_Fortran_TARGET_FORWARD_LINKED_INFO_FILES
  )

# Fortran module output directory.
set(CMAKE_Fortran_TARGET_MODULE_DIR "")
