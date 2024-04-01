#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/transaction/transaction_parser.h"
#include "../unit-tests/util/sha256.h"

static SHA256_CTX sha256_ctx;

uint8_t pub_key_bytes[PUBLIC_KEY_COMPRESSED_LEN];

static bool always_derive_44_536_2_1_3(derived_public_key_t *key) {
    key->address.address_type = RE_ADDRESS_PUBLIC_KEY;
    memmove(key->address.public_key.compressed, pub_key_bytes, PUBLIC_KEY_COMPRESSED_LEN);
    return true;
}

static void init_sha256_hasher() {
    sha256_init(&sha256_ctx);
}

static bool update_sha256_hasher_hash(buffer_t *buf, bool final, uint8_t *out) {
    sha256_update(&sha256_ctx, buf->ptr, buf->size);
    if (final) {
        sha256_final(&sha256_ctx, out);
    }
    return true;  // never fails
}

void *memmem(const void *haystack, size_t n1, const void *needle, size_t n2) {
    const unsigned char *p1 = haystack;
    const unsigned char *p2 = needle;

    if (n2 == 0) return (void *) p1;
    if (n2 > n1) return NULL;

    const unsigned char *p3 = p1 + n1 - n2 + 1;
    for (const unsigned char *p = p1; (p = memchr(p, *p2, p3 - p)) != NULL; p++) {
        if (!memcmp(p, p2, n2)) return (void *) p;
    }

    return NULL;
}

// FROM: https://gist.github.com/vi/dd3b5569af8a26b97c8e20ae06e804cb
void hex_to_bin(const char *str, uint8_t *bytes, size_t blen) {
    uint8_t pos;
    uint8_t idx0;
    uint8_t idx1;

    // mapping of ASCII characters to hex values
    const uint8_t hashmap[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  // 01234567
        0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 89:;<=>?
        0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,  // @ABCDEFG
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // HIJKLMNO
    };

    memset(bytes, 0, blen);
    for (pos = 0; ((pos < (blen * 2)) && (pos < strlen(str))); pos += 2) {
        idx0 = ((uint8_t) str[pos + 0] & 0x1F) ^ 0x10;
        idx1 = ((uint8_t) str[pos + 1] & 0x1F) ^ 0x10;
        bytes[pos / 2] = (uint8_t) (hashmap[idx0] << 4) | hashmap[idx1];
    };
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    hex_to_bin("0356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb7",
               pub_key_bytes,
               PUBLIC_KEY_COMPRESSED_LEN);

    // =============================================
    // Split input into multiple instructions based on separator == "deadbeef"
    // =============================================
    uint8_t *haystack = (uint8_t*)Data;
    size_t haystack_len = Size;
    // sep = 0x 64 65 61 64 62 65 65 66 => deadbeef in ascii
    const uint8_t separator[] = {0x64, 0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66};
    int separator_len = 8;

    int tx_byte_count = 0;
    int total_number_of_instructions = 0;
    const int max_splits = 500;
    const int max_instruction_size = 5000;
    uint8_t splits[max_splits][max_instruction_size];  // will never have more than 50 instructions
    size_t split_sizes[max_splits];

    while (1) {
        uint8_t *separator_start = memmem(haystack, haystack_len, separator, separator_len);

        if (separator_start != NULL) {
            // compute index of where separator was found
            int separator_index = separator_start - haystack;
            size_t split_size = separator_index;

            if (split_size > 0) {
                memcpy(splits[total_number_of_instructions], haystack, split_size);

                split_sizes[total_number_of_instructions] = split_size;
                tx_byte_count += split_size;
                total_number_of_instructions += 1;
            }

            // advance haystack to next part
            haystack = haystack + separator_index + separator_len;
            haystack_len -= (separator_index + separator_len);
        } else {
            break;
        }
    }

    // if we didn't find any split, pass the whole input as a transaction
    if (tx_byte_count == 0) {
        tx_byte_count = Size;
        total_number_of_instructions = 1;
        memcpy(splits[0], Data, Size);
        split_sizes[0] = Size;
    }

    // =============================================
    // Init transaction metadata
    // =============================================
    transaction_parser_t tx_parser;
    parse_and_process_instruction_outcome_t outcome;

    memset(&tx_parser, 0, sizeof(tx_parser));

    const bip32_path_t bip32_path = (bip32_path_t){
        .path = {0x8000002C, 0x80000218, 0x80000002, 1, 3},
        .path_len = 5,
    };

    transaction_metadata_t transaction_metadata = (transaction_metadata_t){
        .tx_byte_count = tx_byte_count,
        .tx_bytes_received_count = (uint32_t) 0,
        .total_number_of_instructions = total_number_of_instructions,
        .number_of_instructions_received = (uint16_t) 0,
        .hrp_non_native_token = {0x00},
        .hrp_non_native_token_len = (uint8_t) 0,
    };

    instruction_display_config_t ins_display_config = (instruction_display_config_t){
        .display_substate_contents = true,
        .display_tx_summary = true,
    };

    init_transaction_parser_config_t tx_parser_config = (init_transaction_parser_config_t){
        .transaction_metadata = transaction_metadata,
        .instruction_display_config = ins_display_config,
        .bip32_path = bip32_path,
    };

    init_tx_parser_outcome_t init_tx_parser_outcome;

    const bool init_tx_parser_successful = init_tx_parser_with_config(&tx_parser,
                                                                      &always_derive_44_536_2_1_3,
                                                                      &update_sha256_hasher_hash,
                                                                      &init_sha256_hasher,
                                                                      &tx_parser_config,
                                                                      &init_tx_parser_outcome);
    memset(&outcome, 0, sizeof(outcome));

    // =============================================
    // Parse each instruction
    // =============================================
    for (int i = 0; i < total_number_of_instructions; i++) {
        buffer_t buf;
        buf.offset = 0;
        buf.size = split_sizes[i];
        buf.ptr = splits[i];
        parse_and_process_instruction_from_buffer(&buf, &tx_parser, &outcome);
    }

    return 0;
}
