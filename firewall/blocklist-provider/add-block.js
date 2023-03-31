console.log("Usage: " + process.argv[1] + " seed endpoint network_id (+|-)account1 [(+|-)account2 ...]");
let endpoint = process.argv[3];
let network_id = process.argv[4];


require('../utils-tests.js').TestRig(endpoint).then(t=>
{
    let seed = process.argv[2];
    let acc = t.fromSeed(seed);

    // encode blob
    let blob = "";
    for (let i = 5; i < process.argv.length; ++i)
    {
        let entry = process.argv[i];
        if (entry.charCodeAt(0) == 43)
        {
            // +, add the acc
            blob += '00';
        }
        else if (entry.charCodeAt(0) == 45)
        {
            // -, remove the acc
            blob += '01';
        }
        blob += t.rac.decodeAccountID(entry.substr(1)).toString('hex').toUpperCase();
    }

    let txn = 
    {
        Account: acc.classicAddress,
        TransactionType: "Invoke",
        Blob: blob,
        NetworkID: parseInt(''+network_id)
    };

    t.feeSubmit(seed, txn).then(x=>
    {
        t.assertTxnSuccess(x)
        console.log(x);
        process.exit(0);
    }).catch(t.err);
})



