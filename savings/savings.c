#include "hookapi.h"
#include <stdint.h>
#define HAS_CALLBACK

#define DONE()\
    accept(0,0,__LINE__)

/**
    All integer values are marked for size and endianness

    Savings Hook
        Parameter Name: 0x53444F ('SDO')
        Parameter Value: <trigger threshold for outgoing xrp payments (uint64)><% as xfl LE>
        Parameter Name: 0x534449 ('SDI')
        Parameter Value: <trigger threshold for incoming xrp payments (uint64)><% as xfl LE>
        Parameter Name: 0x53544F ('STO')
        Parameter Value: <trigger threshold for outgoing trustline payments (xfl)><% as xfl LE>
        Parameter Name: 0x535449 ('STI')
        Parameter Value: <trigger threshold for incoming trustline payments (xfl)><% as xfl LE>
        Parameter Name: 0x5341 ('SA')
        Parameter Value: <20 byte AccountID of savins destination>
        Parameter Name: 0x5344 ('SD')
        Parameter Value: <4 byte dest tag BE>
**/

#define DEBUG 0

uint8_t txn[283] =
{
/* size,upto */
/*   3,  0 */       0x12U, 0x00U, 0x00U,                                /* tt = Payment */
/*   5,  3*/       0x22U, 0x80U, 0x00U, 0x00U, 0x00U,                   /* flags = tfCanonical */
/*   5,  8 */       0x24U, 0x00U, 0x00U, 0x00U, 0x00U,                  /* sequence = 0 */
/*   5, 13 */       0x99U, 0x99U, 0x99U, 0x99U, 0x99U,                  /* dtag, flipped */
/*   6, 18 */       0x20U, 0x1AU, 0x00U, 0x00U, 0x00U, 0x00U,           /* first ledger seq */
/*   6, 24 */       0x20U, 0x1BU, 0x00U, 0x00U, 0x00U, 0x00U,           /* last ledger seq */
/*  49, 30 */   0x61U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, /* amount field 9 or 49 bytes */
                0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U,
                0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U,
                0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U,
                0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U,
                0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99U, 0x99,
/*   9, 79 */   0x68U, 0x40U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,                      /* fee      */
/*  35, 88 */   0x73U, 0x21U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,    /* pubkey   */
/*  22,123 */   0x81U, 0x14U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                            /* src acc  */
/*  22,145 */   0x83U, 0x14U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                            /* dst acc  */
/* 116,167 */   /* emit details */
/*   0,283 */
};

#define FLS_OUT (txn + 20U)
#define LLS_OUT (txn + 26U)
#define DTAG_OUT (txn + 14U)
#define AMOUNT_OUT (txn + 30U)
#define HOOK_ACC (txn + 125U)
#define SAVINGS_ACC (txn + 147U)
#define EMIT_OUT (txn + 167U)
#define FEE_OUT (txn + 80U)

uint8_t errmsg[] = "Savings: Threshold doesn't exist   ";

//
// RH TODO: partial payments via AAW
//

int64_t hook(uint32_t r)
{
    _g(1,1);

    if (otxn_type() != 0)
        accept(SBUF("Savings: Passing non-payment txn"), __LINE__);

    uint8_t otxn_account[20];
    otxn_field(SBUF(otxn_account), sfAccount);

    // get the account id
    uint8_t account_field[20];
    if (otxn_field(SBUF(account_field), sfAccount) != 20)
        accept(SBUF("Savings: Could not get account field!"), __LINE__);

    hook_account(HOOK_ACC, 20);

    uint8_t outgoing = BUFFER_EQUAL_20(HOOK_ACC, account_field);

    uint8_t dest_account[20];
    if (otxn_field(SBUF(dest_account), sfDestination) != 20)
        accept(SBUF("Savings: No destination"), __LINE__);

    // get flags
    uint32_t flags = 0;
    {
        uint8_t flagbuf[4];
        otxn_field(SBUF(flagbuf), sfFlags);
        flags = UINT32_FROM_BUF(flagbuf);
    }
   
    // get the relevant amount, if any
    int64_t amount_native = 0;
    uint8_t amount_buf[48];
    otxn_slot(1);

    // only use sendmax as the target currency if it's an outgoing payment and sendmax is present, otherwise use amt
    if (!(outgoing && slot_subfield(1, sfSendMax, 10) == 10))
        slot_subfield(1, sfAmount, 10);

    amount_native = slot_size(10) == 8;
    if (slot(SBUF(amount_buf), 10) <= 0)
        accept(SBUF("Savings: Could not get amount"), __LINE__);

    int64_t balance, prior_balance;

    // we need to check balance mutation before and after successful application of the payment txn
    // we do that by getting the balance of the relevant currency and saving it in ephemeral state
    {
        uint8_t balkl[34];
        if (amount_native)
            util_keylet(SBUF(balkl), KEYLET_ACCOUNT, HOOK_ACC, 20, 0,0,0,0);
        else
            util_keylet(SBUF(balkl), KEYLET_LINE, otxn_account, 20, dest_account, 20, amount_buf + 28, 20);

        if (slot_set(SBUF(balkl), 20) != 20 || slot_subfield(20, sfBalance, 20) != 20)
            accept(SBUF("Savings: Could not load target balance"), __LINE__);

        balance = slot_float(20);
    }
    
    uint8_t key;
    if (r == 0)
    {
        hook_again();
        // we'll store this for the weak execution
        state_set(&balance, sizeof(balance), &key, 1);
        accept(SBUF("Savings: requesting weak execution."), __LINE__);
    }
    else
    {
        // load the amount before exeuction
        state(&prior_balance, sizeof(prior_balance), &key, 1);
        state_set(0,0, &key, 1);
    }

    // compute and normalize mutation
    int64_t amount = float_sum(float_negate(balance), prior_balance);
    if (float_compare(amount, 0, COMPARE_LESS) == 1)
        amount = float_negate(amount);

    uint8_t param_name[3] = {0x53U, 0x41U, 0};
    uint8_t kl[34];
    if (hook_param(SAVINGS_ACC, 20, param_name, 2) != 20)
        accept(SBUF("Savings: No account set"), __LINE__);

    if (util_keylet(SBUF(kl), KEYLET_ACCOUNT, SAVINGS_ACC, 20, 0,0,0,0) != 34)
        accept(SBUF("Savings: Could not generate keylet"), __LINE__);

    if (slot_set(SBUF(kl), 2) != 2)
        accept(SBUF("Savings: Dest account doesn't exist"), __LINE__);

    // destination exists
    param_name[1] = amount_native   ? 0x44U : 0x54U; // D / T
    param_name[2] = outgoing        ? 0x4FU : 0x49U; // O / I

    errmsg[33] = param_name[1];
    errmsg[34] = param_name[2];

    uint8_t threshold_raw[16];
    if (hook_param(threshold_raw, 16, SBUF(param_name)) != 16)
        accept(SBUF(errmsg), __LINE__); 
           
    if (float_compare(*((uint64_t*)threshold_raw), amount, COMPARE_LESS) == 1)
        accept(SBUF("Savings: Threshold not met"), __LINE__); 

    uint64_t threshold = *((uint64_t*)threshold_raw);
    uint64_t percent =  *(((uint64_t*)(threshold_raw)) + 1);

    if (DEBUG)
    {
        trace_num(SBUF("threshold"), threshold);
        trace_num(SBUF("percent"), percent);
    }

    int64_t tosend_xfl =
        float_multiply(amount, percent);

    if (tosend_xfl <= 0)
        accept(SBUF("Savings: Skipping 0 / invalid send."), __LINE__);

    // savings thrshold met
    etxn_reserve(1);

    if (!amount_native)
    {
        // check if destination has a trustline for the currency

        // first generate the keylet
        if (
            util_keylet(SBUF(kl), KEYLET_LINE,
                SAVINGS_ACC, 20,
                amount_buf + 28, 20,         /* issuer */
                amount_buf +  8, 20) != 34   /* currency code */
        ||
        // then check it on the ledger
        slot_set(SBUF(kl), 3) != 3)
            accept(SBUF("Savings: Trustline missing on dest account"), __LINE__);

    }

    // prepare the payment

#define FLIP_ENDIAN(n) ((uint32_t) (((n & 0xFFU) << 24U) | \
                            ((n & 0xFF00U) << 8U) | \
                            ((n & 0xFF0000U) >> 8U) | \
                            ((n & 0xFF000000U) >> 24U)));

    uint32_t fls = (uint32_t)ledger_seq() + 1;
    uint32_t lls = fls + 4 ;

    // fls
    *((uint32_t*)(FLS_OUT)) = FLIP_ENDIAN(fls);

    // lls
    *((uint32_t*)(LLS_OUT)) = FLIP_ENDIAN(lls);

    // if they specified a destination tag then fill it
    param_name[1] = 'D';
    if (hook_param(DTAG_OUT, 4, param_name, 2) == 4)
        *(DTAG_OUT-1) = 0x2EU;
        

/*  49 */
/*or 9 */
    if (amount_native)
    {
        uint64_t drops = float_int(tosend_xfl, 6, 1);
        uint8_t* b = AMOUNT_OUT + 1;
        *b++ = 0b01000000 + (( drops >> 56 ) & 0b00111111 );                                                   
        *b++ = (drops >> 48) & 0xFFU;                                                                          
        *b++ = (drops >> 40) & 0xFFU;                                                                          
        *b++ = (drops >> 32) & 0xFFU;                                                                          
        *b++ = (drops >> 24) & 0xFFU;                                                                          
        *b++ = (drops >> 16) & 0xFFU;                                                                          
        *b++ = (drops >>  8) & 0xFFU;                                                                          
        *b++ = (drops >>  0) & 0xFFU;            
    }
    else
    {
        if (float_sto(AMOUNT_OUT, 49, amount_buf + 28, 20, amount_buf + 8, 20, tosend_xfl, sfAmount) != 49)
            accept(SBUF("Savings: Generating amount failed"), __LINE__);
    }
    
    etxn_details(EMIT_OUT, 116U);

    // fee
    {
        int64_t fee = etxn_fee_base(SBUF(txn));
        if (DEBUG)
            TRACEVAR(fee);
        uint8_t* b = FEE_OUT;
        *b++ = 0b01000000 + (( fee >> 56 ) & 0b00111111 );                                                   
        *b++ = (fee >> 48) & 0xFFU;                                                                          
        *b++ = (fee >> 40) & 0xFFU;                                                                          
        *b++ = (fee >> 32) & 0xFFU;                                                                          
        *b++ = (fee >> 24) & 0xFFU;                                                                          
        *b++ = (fee >> 16) & 0xFFU;                                                                          
        *b++ = (fee >>  8) & 0xFFU;                                                                          
        *b++ = (fee >>  0) & 0xFFU;            
    }


    // emit the transaction
    
    uint8_t emithash[32];
    int64_t emit_result = emit(SBUF(emithash), SBUF(txn));
    if (emit_result > 0)
        accept(SBUF("Savings: Successfully emitted"), __LINE__);
   
    if (DEBUG)
        trace(SBUF("txnraw"), SBUF(txn), 1); 
    return accept(SBUF("Savings: Emit unsuccessful"), __LINE__);
}

