#include "hookapi.h"
#include <stdint.h>
#define HAS_CALLBACK

#define ASSERT(x)\
{\
    if (!(x))\
        rollback(0,0,__LINE__);\
}

#define DONE()\
    accept(0,0,__LINE__)

/**
    This hook is an omnibus hook that contains 2 different hooks' functionalities. Each of these
    can be enabled or disabled and configured using the provided install-time hook parameter as
    described below:

    All integer values are little endian unless otherwise marked

    1. Blocklist Hook
        Parameter Name: 0x42 ('B')
        Parameter Value: <20 byte AccountID of blocklist provider>

    2. Firewall Hook
        If enabled HookOn must be uint256max
        Parameter Name: 0x4649 ('FI')
        Parameter Value: <uint256 bit field of allowable transaction types in>
        Parameter Name: 0x464F ('FO')
        Parameter Value: <uint256 bit field of allowable transaction types out>
        Parameter Name: 0x4644 ('FD')
        Parameter Value: minimum drops threshold for incoming XRP payments (xfl LE)
        Parameter Name: 0x4654 ('FT')
        Parameter Value: minimum threshold for incoming trustline payments (xfl LE)

**/

int64_t hook(uint32_t r)
{
    _g(1,1);

    uint8_t otxn_account[20];
    otxn_field(SBUF(otxn_account), sfAccount);

    // get the account id
    uint8_t account_field[20];
    ASSERT(otxn_field(SBUF(account_field), sfAccount) == 20);

    uint8_t hook_acc[20];
    hook_account(SBUF(hook_acc));

    uint8_t outgoing = BUFFER_EQUAL_20(hook_acc, account_field);

    uint8_t ttbuf[16];
    otxn_field(SBUF(ttbuf), sfTransactionType);
    uint32_t tt = ((uint32_t)(ttbuf[0]) << 16U) + ((uint32_t)(ttbuf[1]));
    uint64_t ttmask[4];
    ttmask[tt / 8] = 1 << (tt % 8);

    // get flags
    uint32_t flags = 0;
    {
        uint8_t flagbuf[4];
        otxn_field(SBUF(flagbuf), sfFlags);
        flags = UINT32_FROM_BUF(flagbuf);
    }

    // get the relevant amount, if any
    int64_t amount = -1;
    int64_t amount_native = 0;
    otxn_slot(1);
    if (slot_subfield(1, sfAmount, 1) == 1)
    {
        amount = slot_float(1);
        amount_native = slot_size(1) == 8;
    }


    // Blocklist
    {
        uint8_t param_name[1] = {0x42U};
        uint8_t provider[20];
        if (hook_param(SBUF(provider), SBUF(param_name)) == sizeof(provider))
        {
            uint8_t ns[32];
            uint8_t tx[32];
            if (state_foreign(SBUF(tx), SBUF(otxn_account), SBUF(ns), SBUF(provider)) == 32)
                rollback(SBUF("Blocklist match"), __LINE__);
        }
    }

    // Firewall
    {
        // check allowable txn types
        {
            uint8_t param_name[2] = {0x46U, 0x4FU};
            if (!outgoing)
                param_name[1] = 0x49U;
            uint64_t tts[4] =
            {
                0xFFFFFFFFFFFFFFFFULL,
                0xFFFFFFFFFFFFFFFFULL,
                0xFFFFFFFFFFFFFFFFULL,
                0xFFFFFFFFFFFFFFFFULL
            };
            int64_t result = hook_param(tts, 32, SBUF(param_name));

            ASSERT(result == 32 || result == DOESNT_EXIST);

            // check if its on the list of blocked txn types
            if (!((ttmask[0] & tts[0]) |
                (ttmask[1] & tts[1]) |
                (ttmask[2] & tts[2]) |
                (ttmask[3] & tts[3])))
                rollback(SBUF("Firewall blocked txn type"), __LINE__);

        }

        // if its an incoming payment ensure it passes the threshold
        if (!outgoing && amount >= 0)
        {
            if (flags & 0x00020000UL)
                rollback(SBUF("Firewall blocked partial payment"), __LINE__);

            // threshold for drops
            uint8_t param_name[2] = {0x46U, 0x44U};

            // if it was a tl amount then change to threshold for trustline
            if (!amount_native)
                param_name[1] = 0x54U;

            uint64_t threshold;
            if (hook_param(&threshold, 8, SBUF(param_name)) == 8)
                if (float_compare(amount, threshold, COMPARE_LESS) == 1)
                    rollback(SBUF("Firewall blocked amount below threshold"), __LINE__);

        }


        // OK!
    }

    accept(0,0,0);
}

