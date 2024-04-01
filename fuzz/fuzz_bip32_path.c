#include <string.h>

#include "../src/transaction/transaction_parser.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    char output[UINT256_DEC_STRING_MAX_LENGTH] = {0};

    bip32_path_t bip32_path = {0};
    bip32_path.path_len = Size/4;
    
    memcpy(bip32_path.path, Data, MIN(MAX_BIP32_PATH * 4, Size));
    bip32_path_format(&bip32_path, output, sizeof(output));
    
    return 0;
}
