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
    This hook is an omnibus hook that contains 4 different hooks' functionalities. Each of these
    can be enabled or disabled and configured using the provided install-time hook parameter as
    described below:

    All integer values are little endian unless otherwise marked

    1. High-Value Payment Hook
        Parameter Name: 0x4844 ('HD')
        Parameter Value: trigger threshold for outgoing xrp payments (xfl LE)
        Parameter Name: 0x4854 ('HT')
        Parameter Value: trigger threshold for outgoing trustline payments (xfl LE)

    2. Savings Hook
        Parameter Name: 0x53444F ('SDO')
        Parameter Value: <trigger threshold for outgoing xrp payments (uint64)><% as xfl LE>
        Parameter Name: 0x534449 ('SDI')
        Parameter Value: <trigger threshold for incoming xrp payments (uint64)><% as xfl LE>
        Parameter Name: 0x53544F ('STO')
        Parameter Value: <trigger threshold for outgoing trustline payments (xfl)><% as xfl LE>
        Parameter Name: 0x535449 ('STI')
        Parameter Value: <trigger threshold for incoming trustline payments (xfl)><% as xfl LE>
        Parameter Name: 0x5341 ('SA')
        Parameter Value: <20 byte AccountID of savins destination><4 byte dest tag BE>
**/

uint8_t txn[284 /* for trustline, and 244 for drops */] =
{
/*   3 */       0x12U, 0x00U, 0x01U,                                /* tt = Payment */
/*   5 */       0x22U, 0x80U, 0x00U, 0x00U, 0x00U,                  /* flags = tfCanonical */
/*   5 */       0x24U, 0x00U, 0x00U, 0x00U, 0x00U,                  /* sequence = 0 */
/*   6 */       0x20U, 0x14U, 0x00U, 0x00U, 0x00U, 0x00U,           /* dtag, flipped */
/*   6 */       0x20U, 0x26U, 0x00U, 0x00U, 0x00U, 0x00U,           /* first ledger seq */
/*   6 */       0x20U, 0x27U, 0x00U, 0x00U, 0x00U, 0x00U            /* last ledger seq */
                /* rest must be populated in code because here the amount may be 8 or 48 */
};



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
    uint8_t amount_buf[48];
    otxn_slot(1);
    if (slot_subfield(1, sfAmount, 1) == 1)
    {
        amount = slot_float(1);
        amount_native = slot_size(1) == 8;
        ASSERT(otxn_field(SBUF(amount_buf), sfAmount) > 0);
    }


    // partial payments not supported
    if (flags & 0x00020000UL)
        return accept(SBUF("Savings: Passing partial payment"), __LINE__);


    {
        uint8_t param_name[3] = {0x53U, 0x41U, 0};
        uint8_t savings_acc[24];
        uint8_t kl[34];
        if (hook_param(SBUF(savings_acc), param_name, 2) == 24)
        do
        {
            GUARD(1);

            ASSERT(util_keylet(SBUF(kl), KEYLET_ACCOUNT, savings_acc, 20, 0,0,0,0) == 34);

            if (slot_set(SBUF(kl), 2) != 2)
                break;

            // destination exists
            param_name[1] = amount_native   ? 0x44U : 0x54U; // D / T
            param_name[2] = outgoing        ? 0x4FU : 0x49U; // O / I

            uint8_t threshold_raw[10];
            if (!(hook_param(threshold_raw, 10, SBUF(param_name)) == 10 &&
                float_compare(*((uint64_t*)threshold_raw), amount, COMPARE_LESS) == 1))
                break;

            uint64_t threshold = *((uint64_t*)threshold_raw);
            uint64_t percent =  *(((uint64_t*)(threshold_raw)) + 1);

            int64_t tosend_xfl =
                float_multiply(amount, percent);

            ASSERT(tosend_xfl >= 0);

            if (tosend_xfl == 0)
                break;

            // savings thrshold met
            etxn_reserve(1);

            if (!amount_native)
            {
                // check if destination has a trustline for the currency

                // first generate the keylet
                ASSERT(
                    util_keylet(SBUF(kl), KEYLET_LINE,
                        SBUF(savings_acc),
                        amount + 28, 20,         /* issuer */
                        amount +  8, 20) == 34); /* currency code */

                // then check it on the ledger
                if (slot_set(SBUF(kl), 3) != 3)
                    break;

            }

            // prepare the payment

#define FLIP_ENDIAN(n) ((uint32_t) (((n & 0xFFU) << 24U) | \
                                    ((n & 0xFF00U) << 8U) | \
                                    ((n & 0xFF0000U) >> 8U) | \
                                    ((n & 0xFF000000U) >> 24U)));

            uint32_t fls = (uint32_t)ledger_seq() + 1;
            uint32_t lls = fls + 4 ;
            uint64_t txn_size = amount_native ? 244 : 284;

            // dest tag
            *((uint32_t*)(txn + 15)) = *((uint32_t*)(savings_acc + 20));

            // fls
            *((uint32_t*)(txn + 19)) = FLIP_ENDIAN(fls);

            // lls
            *((uint32_t*)(txn + 32)) = FLIP_ENDIAN(lls);


/*  49 */
/*or 9 */
            uint8_t* upto = txn + 31;
            if (amount_native)
            {
                uint64_t drops = float_int(tosend_xfl, 6, 1);
                _06_01_ENCODE_DROPS_AMOUNT(upto, drops);
            }
            else
            {
                ASSERT(float_sto(upto, 48, amount_buf + 28, 20, amount_buf + 8, 20, tosend_xfl, sfAmount) == 49);
                upto += 49;
            }
            uint8_t* fee_ptr = upto;
/*   9 */   _06_08_ENCODE_DROPS_FEE (upto, 0);
/*  35 */   _07_03_ENCODE_SIGNING_PUBKEY_NULL(upto);
/*  22 */   _08_01_ENCODE_ACCOUNT_SRC(upto, hook_acc);
/*  22 */   _08_03_ENCODE_ACCOUNT_DST(upto, savings_acc);
/* 116 */
            int64_t edlen = etxn_details((uint32_t)upto, txn_size);
            int64_t fee = etxn_fee_base(txn, txn_size);
            _06_08_ENCODE_DROPS_FEE(fee_ptr, fee);

            trace(SBUF("savings txn"), txn, txn_size, 1);

            // emit the transaction
            uint8_t emithash[32];
            int64_t emit_result = emit(SBUF(emithash), txn, txn_size);
            ASSERT(emit_result > 0);

            trace(SBUF("savings hash"), SBUF(emithash), 1);

        } while (0);

    }

    // HV-Payment
    {

    }


    accept(0,0,0);
}

