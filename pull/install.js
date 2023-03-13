require('./utils-tests.js').TestRig('ws://localhost:6006').then(t=>
{
    t.feeSubmit(t.genesis.seed,
    {
        Account: t.genesis.classicAddress,
        TransactionType: "SetHook",
        Hooks:
        [
            {
                Hook:
                {
                    Flags: 1,
                    CreateCode: t.wasm("pull.wasm"), 
                    HookApiVersion: 0,
                    HookNamespace: "3A3FCBCD07A8B97DE46E88E04C63397146EE3A1C7D8CE90C52DBCAD2198672F0",
                    HookOnLegacy: "0000000000000000"
                },
            }
        ]
    }).then(x=>
    {
        t.assertTxnSuccess(x)
        console.log(x);
        process.exit(0);
    }).catch(t.err);
})



