#include "hookapi.h"
#include <stdint.h>

#define DONE(msg)\
    return accept(msg, sizeof(msg),__LINE__)

/**
    All integer values are marked for size and endianness

    High value Payments Block Hook
        Parameter Name: 485644 (HVD)
        Parameter Value: <8 byte xfl of drops threshold to block LE>
        Parameter Name: 485644 (HDT)
        Parameter Value: <8 byte xfl of trustline threshold to block LE>
**/

uint8_t drops_key[3] = {'H', 'V', 'D'};
uint8_t tl_key[3] = {'H', 'V', 'T'};
uint8_t amount_buf[8];

int64_t hook(uint32_t r)
{
    _g(1,1);

    // pass anything that isn't a payment
    if (otxn_type() != 0)
        DONE("High value: Passing non-Payment txn");

    // get the account ids
    uint8_t otxn_acc[20];
    otxn_field(SBUF(otxn_acc), sfAccount);

    uint8_t hook_acc[20];
    hook_account(SBUF(hook_acc));

    // if the account is the sender
    if (!BUFFER_EQUAL_20(hook_acc, otxn_acc))
        DONE("High value: Ignoring incoming Payment");

    otxn_slot(1);
    slot_subfield(1, sfAmount, 2);

    int64_t threshold;
    if (hook_param(&threshold, sizeof(threshold), slot_type(2, 1) == 1 ? drops_key : tl_key, 3) != sizeof(threshold))
        DONE("High value: Passing outgoing Payment txn for which no threshold is set");

    if (float_compare(threshold, slot_float(2), COMPARE_LESS) == 1)
        rollback(SBUF("High value: Payment exceeds threshold. Use Invoke to send."), __LINE__);

    DONE("High value: Paying outgoing Payment less than threshold.");
}
