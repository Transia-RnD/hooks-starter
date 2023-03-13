if (process.argv.length < 5)
{
    console.log("Usage: node allowance <seed> <allowed account> <allowed amount in whole xrp>")
    process.exit(1)
}
const keypairs = require('ripple-keypairs');
const secret  = process.argv[2];
const address = keypairs.deriveAddress(keypairs.deriveKeypair(secret).publicKey)


const r = require('ripple-address-codec');
const accid = r.decodeAccountID(process.argv[3]).toString('hex').toUpperCase();

let amount = (BigInt(process.argv[4]) * 1000000n).toString(16).toUpperCase()
amount = '0'.repeat(16 - amount.length) + amount;

let txn = 
{
    Account: address,
    TransactionType: "Invoke"
};

if (process.argv.length > 4)
{
    txn["HookParameters"] = 
    [
        {
            HookParameter:
            {
                HookParameterName: accid,
                HookParameterValue: amount
            }
        }
    ];
}


console.dir(txn, {depth:5});

require('./utils-tests.js').TestRig('ws://localhost:6005').then(t=>
{
        t.feeSubmit(secret, txn).then(x=>
        {
            t.assertTxnSuccess(x)
            console.log(x);
            process.exit(0);
        }).catch(t.err);

})
