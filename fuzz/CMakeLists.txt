cmake_minimum_required(VERSION 3.4)

project(Fuzzer LANGUAGES C)

set(CMAKE_C_STANDARD 11)

add_compile_options(-g -ggdb2 -O3)

set(RADIX_DIR "../src")
set(UTIL_DIR "../unit-tests/util")

add_compile_definitions(APPNETWORK=1)

# Build with code coverage generation
if(CODE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "(Apple)?[Cc]lang")
        add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
        add_link_options(-fprofile-instr-generate -fcoverage-mapping)
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
        add_compile_options(-fprofile-arcs -ftest-coverage)
        link_libraries(gcov)
    else()
        message(FATAL_ERROR "Unsupported compiler used with code coverage generation")
    endif()
endif()

add_library(radix
    ${RADIX_DIR}/common/read.c
    ${RADIX_DIR}/common/bech32_encode.c
    ${RADIX_DIR}/instruction/instruction.c
    ${RADIX_DIR}/instruction/substate/substate.c
    ${RADIX_DIR}/instruction/substate/substate_type.c
    ${RADIX_DIR}/instruction/substate/substate_id.c
    ${RADIX_DIR}/instruction/substate/tokens.c
    ${RADIX_DIR}/instruction/instruction_type.c
    ${RADIX_DIR}/instruction/substate/validator_allow_delegation_flag.c
    ${RADIX_DIR}/instruction/substate/validator_owner_copy.c
    ${RADIX_DIR}/instruction/substate/prepared_unstake.c
    ${RADIX_DIR}/instruction/substate/prepared_stake.c
    ${RADIX_DIR}/instruction/substate/stake_ownership.c
    ${RADIX_DIR}/instruction/substate/substate.c
    ${RADIX_DIR}/transaction/transaction.c
    ${RADIX_DIR}/transaction/transaction_parser.c
    ${RADIX_DIR}/types/bip32_path.c
    ${RADIX_DIR}/types/buffer.c
    ${RADIX_DIR}/types/hasher.c
    ${RADIX_DIR}/types/public_key.c
    ${RADIX_DIR}/types/re_address.c
    ${RADIX_DIR}/types/re_address_type.c
    ${RADIX_DIR}/types/re_bytes.c
    ${RADIX_DIR}/types/uint256.c
    ${UTIL_DIR}/sha256.c
)

add_executable(fuzz_tx_parser fuzz_tx_parser.c)
add_executable(fuzz_bip32_path fuzz_bip32_path.c)

target_link_libraries(fuzz_tx_parser PUBLIC radix)
target_compile_options(fuzz_tx_parser PUBLIC -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)
target_link_options(fuzz_tx_parser PUBLIC -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

target_link_libraries(fuzz_bip32_path PUBLIC radix)
target_compile_options(fuzz_bip32_path PUBLIC -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)
target_link_options(fuzz_bip32_path PUBLIC -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)