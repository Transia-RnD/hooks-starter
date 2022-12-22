#include "hookapi.h"
#include <stdint.h>

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
 *
int64_t cbak(uint32_t w)
{
    if (w != 1)
        return 0;

    // we only want to handle the case where an emitted txn failed
    SETUP_CURRENT_MONTH(); // populates a uint16_t current_month variable


}
*/

int64_t hook(uint32_t r)
{
    _g(1,1);

    uint8_t ttbuf[16];
    int64_t br = otxn_field(SBUF(ttbuf), sfTransactionType);
    uint32_t txntype = ((uint32_t)(ttbuf[0]) << 16U) + ((uint32_t)(ttbuf[1]));

    // pass anything that isn't a ttINVOKE
    if (txntype != 98)
        DONE();

    // get the account id
    uint8_t account_field[20];
    ASSERT(otxn_field(SBUF(account_field), sfAccount) == 20);

    uint8_t hook_accid[20];
    hook_account(SBUF(hook_accid));

    // pass outgoing txns
    if (BUFFER_EQUAL_20(hook_accid, account_field))
        DONE();

    // hook has two modes: un/set and request
    // to set use hook parameter name=accountid, value=monthly authorized amount
    // to unset set authorized amount to 0
    // to request perform a blank invoke with a requested amount encoded in the invoice ID field

    SETUP_CURRENT_MONTH(); // populates a uint16_t current_month variable

    otxn_slot(1);

    int params = slot_subfield(1, sfHookParameters, 2) == 2;
    int invoice = slot_subfield(1, sfInvoiceID, 3) == 3;

    // must specify exactly one
    ASSERT(params || invoice);
    ASSERT(!(params && invoice));

    if (params)
    {
        // set/unset mode
        ASSERT(slot_subarray(2, 0, 4) == 4);
        ASSERT(slot_subfield(4, sfHookParameterName, 5)  == 5);
        ASSERT(slot_subfield(4, sfHookParameterValue, 6) == 6);

        uint8_t k[21];
        ASSERT(slot(SBUF(k), 5) == 21);

        // packed data in value field starting from byte 0:
        // monthly allowance: uint64_t      0 - 7
        // month last claim : uint16_t      8 - 9
        // amount claimed   : uint64_t     10 - 17
        //
        // RH NOTE: v[0] == the length of the field due to serialization
        uint8_t vbuf[18];
        ASSERT(slot(SBUF(vbuf), 6) == 9);

        uint8_t* v = vbuf+1;

        // check if account exists on the ledger

        uint8_t kl[34];
        ASSERT(util_keylet(SBUF(kl), KEYLET_ACCOUNT, k+1, 20, 0,0,0,0) == 34);

        ASSERT(slot_set(SBUF(kl), 7) == 7);

        // it does, now check if the value is zero
        if (*((uint64_t*)(k+1)) == 0)
        {
            // this is the unset operation
            ASSERT(state_set(0,0, k+1, 20) == 0);
        }
        else
        {
            // this is the set operation
            // configure the rest of the v buffer
            *(v+8) = (current_month >> 8U);
            *(v+9) = current_month & 0xFFU;
            // remaining bytes are zero which is what we want
            ASSERT(state_set(v, 18, k+1, 20) == 18);
        }

        DONE();
    }

    // execution to here is pull mode

    // first check if they have an entry (authorization)
    uint8_t packed[18];
    ASSERT(state(SBUF(packed), SBUF(account_field)) == 18);

    // get the requested amount from invoice id
    uint8_t inv[32];
    ASSERT(slot(SBUF(inv), 3) == 32);

    // the low bytes in big endian are the requested amount
    int64_t requested_amount =
        UINT64_FROM_BUF(inv + 24);

    // RH TODO: it would be good to check account's balance here
    // but it requires computing the reserve which requires looking up the fees object
    // which is quite a lot of additional instructions and no guarentee the txn won't fail anyway
    // so better to catch overdraft in the callback

    int64_t already_requested =
        UINT64_FROM_BUF(packed + 10);

    int64_t allowance = 
        UINT64_FROM_BUF(packed);

    uint16_t already_requested_month =
        UINT16_FROM_BUF(packed + 8);

    if (already_requested_month != current_month)
    {
        already_requested = 0;
        packed[8] = (uint8_t)((current_month >> 8) & 0xFFU);
        packed[9] = (uint8_t)((current_month >> 0) & 0xFFU);
    }
    
    int64_t after = already_requested + requested_amount;

    // catch overflow
    ASSERT(after > already_requested && after > requested_amount);

    // catch overspend
    ASSERT(after <= allowance);

    // execution to here means the request is OK

    // update the state
    UINT64_TO_BUF(packed + 10, after);
    ASSERT(state_set(SBUF(packed), SBUF(account_field)) == 18);
   
    // emit the txn 
    uint8_t tx[PREPARE_PAYMENT_SIMPLE_SIZE];                                                                           
    PREPARE_PAYMENT_SIMPLE(tx, requested_amount, account_field, 0, 0);                                                     
                                                                                                                       
    // emit the transaction                                                                                            
    uint8_t emithash[32];                                                                                              
    int64_t emit_result = emit(SBUF(emithash), SBUF(tx));                                                              
    ASSERT(emit_result > 0);

    TRACEVAR(emit_result);     

    accept(0,0,0);
}
