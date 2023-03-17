console.log("Usage: " + process.argv[1] + " [seed def=genesis] [endpoint def=localhost:6006] [network_id def=blank]");
let network_id = ''
let endpoint = 'ws://localhost:6006'
if (process.argv.length > 3)
    endpoint = process.argv[3];
if (process.argv.length > 4)
    network_id = process.argv[4];

let wasmfn = "";
const fs = require('fs');
fs.readdirSync('./').forEach(file => {
    if (file.match(/.wasm$/))
    {
        wasmfn = file;
        return false;
    }
});

if (wasmfn == "")
{
    console.log("Could not find a .wasm file in the cwd.");
    process.exit(1);
}

require('./utils-tests.js').TestRig(endpoint).then(t=>
{
    let seed = t.genesis.seed;
    if (process.argv.length > 2)
        seed = process.argv[2];

    let acc = t.fromSeed(seed);

    let txn = 
    {
        Account: acc.classicAddress,
        TransactionType: "SetHook",
        Hooks:
        [
            {
                Hook:
                {
                    Flags: 1,
                    CreateCode: t.wasm(wasmfn), 
                    HookApiVersion: 0,
                    HookNamespace: "0000000000000000000000000000000000000000000000000000000000000000",
                    HookOn: "0000000000000000000000000000000000000000000000000000000000000000"
                },
            }
        ]
    };
    if (network_id != "")
        txn["NetworkID"] = parseInt(''+network_id) ;

    t.feeSubmit(seed, txn).then(x=>
    {
        t.assertTxnSuccess(x)
        console.log(x);
        process.exit(0);
    }).catch(t.err);
})



