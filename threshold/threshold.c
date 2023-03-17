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

// credit for date contribution algorithm: https://stackoverflow.com/a/42936293 (Howard Hinnant)
#define SETUP_CURRENT_MONTH()\
uint16_t current_month = 0;\
{\
    int64_t s = ledger_last_time() + 946684800;\
    int64_t z = s / 86400 + 719468;\
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;\
    uint64_t doe = (uint64_t)(z - era * 146097);\
    uint64_t yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;\
    int64_t y = (int64_t)(yoe) + era * 400;\
    uint64_t doy = doe - (365*yoe + yoe/4 - yoe/100);\
    uint64_t mp = (5*doy + 2)/153;\
    uint64_t d = doy - (153*mp+2)/5 + 1;\
    uint64_t m = mp + (mp < 10 ? 3 : -9);\
    y += (m <= 2);\
    current_month = y * 12 + m;\
    TRACEVAR(y);\
    TRACEVAR(m);\
    TRACEVAR(d);\
    TRACEVAR(current_month);\
}

/*
 * RH TODO: if a pull payment fails then decrement the used allowance so it can be retried
int64_t cbak(uint32_t w)
{
    if (w != 1)
        return 0;

    // we only want to handle the case where an emitted txn failed
    SETUP_CURRENT_MONTH(); // populates a uint16_t current_month variable


}
 */


/**
    This hook is an omnibus hook that contains 4 different hooks' functionalities. Each of these
    can be enabled or disabled and configured using the provided install-time hook parameter as
    described below:

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
        Parameter Value: minimum drops threshold for incoming XRP payments (uint64)
        Parameter Name: 0x4654 ('FT')
        Parameter Value: minimum threshold for incoming trustline payments (xfl)

    3. High-Value Payment Hook
        Parameter Name: 0x4844 ('HD')
        Parameter Value: trigger threshold for outgoing xrp payments (uint64)
        Parameter Name: 0x4854 ('HT')
        Parameter Value: trigger threshold for outgoing trustline payments (xfl format)

    4. Savings Hook
        Parameter Name: 0x53444F ('SDO')
        Parameter Value: <trigger threshold for outgoing xrp payments (uint64)><% as uint16>
        Parameter Name: 0x534449 ('SDI')
        Parameter Value: <trigger threshold for incoming xrp payments (uint64)><% as uint16>
        Parameter Name: 0x53444F ('STO')
        Parameter Value: <trigger threshold for outgoing trustline payments (xfl)><% as uint16>
        Parameter Name: 0x534449 ('STI')
        Parameter Value: <trigger threshold for incoming trustline payments (xfl)><% as uint16>
        Parameter Name: 0x5341 ('SA')
        Parameter Value: <20 byte AccountID of savins destination>
**/

int64_t hook(uint32_t r)
{
    _g(1,1);

    uint8_t otxn_account[20];
    otxn_field(SBUF(otxn_account), sfAccount);

    // get the account id
    uint8_t account_field[20];
    ASSERT(otxn_field(SBUF(account_field), sfAccount) == 20);

    uint8_t hook_accid[20];
    hook_account(SBUF(hook_accid));
    
    uint8_t outgoing = BUFFER_EQUAL_20(hook_accid, account_field);

    uint8_t ttbuf[16];
    otxn_field(SBUF(ttbuf), sfTransactionType);
    uint32_t tt = ((uint32_t)(ttbuf[0]) << 16U) + ((uint32_t)(ttbuf[1]));
    uint64_t ttmask[4];
    ttmask[tt / 8] = 1 << (tt % 8);

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
        uint64_t tts[4] = {
            0xFFFFFFFFFFFFFFFFULL, 
            0xFFFFFFFFFFFFFFFFULL, 
            0xFFFFFFFFFFFFFFFFULL, 
            0xFFFFFFFFFFFFFFFFULL };
        int64_t result = 32;
        if (outgoing)
        {
            uint8_t param_name[2] = {0x46U, 0x4FU};
            result = hook_param(tts, 32, SBUF(param_name));
            
        }
        else
        {
            uint8_t param_name[2] = {0x46U, 0x49U};
            result = hook_param(tts, 32, SBUF(param_name));
        }
        
        ASSERT(result == 32 || result == DOESNT_EXIST);
            
        if(
                (ttmask[0] & tts[0]) |
                (ttmask[1] & tts[1]) |
                (ttmask[2] & tts[2]) | 
                (ttmask[3] & tts[3]))
        {
            // pass
        }
        else
            rollback(SBUF("Firewall blocked txn type"), __LINE__);


        // RH UPTO:
        //    load thresholds, check thresholds
    }



    // HV-Payment


    // Savings


    accept(0,0,0);
}

