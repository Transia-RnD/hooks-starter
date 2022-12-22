if (process.argv.length < 5)
{
    console.log("Usage: node request <seed> <requestee account> <amount in whole XRP>")
    process.exit(1)
}
const keypairs = require('ripple-keypairs');
const secret  = process.argv[2];
const address = keypairs.deriveAddress(keypairs.deriveKeypair(secret).publicKey)


const acc = process.argv[3]

let amount = (1000000n * BigInt(process.argv[4])).toString(16).toUpperCase()
amount = '0'.repeat(64 - amount.length) + amount;

let txn = 
{
    Account: address,
    TransactionType: "Invoke",
    Destination: acc,
    InvoiceID: amount
};



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
