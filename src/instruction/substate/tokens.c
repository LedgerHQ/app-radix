#include "tokens.h"
#include "../../sw.h"
#include "../../bridge.h"  // PRINTF
// #include "../macros.h"  // ASSERT

bool parse_tokens(buffer_t *buffer, parse_tokens_outcome_t *outcome, tokens_t *tokens) {
    parse_address_failure_reason_e parse_address_failure;

    // Parse field 'rri'
    if (!parse_re_address(buffer, &parse_address_failure, &tokens->rri)) {
        PRINTF("Failed to parse 'rri' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_RRI;
        outcome->rri_parse_failure_reason = parse_address_failure;
        return false;
    }

    // Parse field 'owner'
    if (!parse_re_address(buffer, &parse_address_failure, &tokens->owner)) {
        PRINTF("Failed to parse 'owner' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_OWNER;
        outcome->owner_parse_failure_reason = parse_address_failure;
        return false;
    }

    // Parse field 'amount'
    if (!uint256_from_buffer(buffer, &tokens->amount)) {
        PRINTF("Failed to parse 'amount' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_AMOUNT;
        return false;
    }

    outcome->outcome_type = PARSE_TOKENS_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_tokens(parse_tokens_outcome_e failure_reason) {
    switch (failure_reason) {
        case PARSE_TOKENS_OK:
            return SW_OK;
        case PARSE_TOKENS_FAILURE_PARSE_RRI:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_RRI_FAILURE;
        case PARSE_TOKENS_FAILURE_PARSE_OWNER:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_OWNER_FAILURE;
        case PARSE_TOKENS_FAILURE_PARSE_AMOUNT:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_AMOUNT_FAILURE;
    }

    return ERR_BAD_STATE;  // should never happen
}