if (process.argv.length < 3)
{
    console.log("Usage: node invoke <source family seed> <destination account> <key> <value>")
    process.exit(1)
}
const keypairs = require('ripple-keypairs');
const secret  = process.argv[2];
const address = keypairs.deriveAddress(keypairs.deriveKeypair(secret).publicKey)


let txn = 
{
    Account: address,
    TransactionType: "Invoke"
};

if (process.argv.length > 3)
{
    const dest = process.argv[3];
    txn["Destination"] = dest;
}

if (process.argv.length > 4)
{
    txn["HookParameters"] = 
    [
        {
            HookParameter:
            {
                HookParameterName: process.argv[4],
                HookParameterValue: process.argv[5]
            }
        }
    ];
}


require('./utils-tests.js').TestRig('ws://localhost:6005').then(t=>
{
        t.feeSubmit(secret, txn).then(x=>
        {
            t.assertTxnSuccess(x)
            console.log(x);
            process.exit(0);
        }).catch(t.err);

})
