SMART_CONTRACT_EXTENSIONS = (
    '.sol', '.tsol', '.vy', '.rs', '.move', '.cairo',
    '.fc', '.func', '.circom', 
    '.yul', '.ligo', '.mligo', '.religo', '.jsligo',
    '.tz', '.arl', '.scilla', '.daml', '.plutus', '.hs',
    '.aes', '.rho', '.clar', '.clarity', '.ink',
    '.zok', '.leo', '.noir', '.nr', '.aleo', '.ark'
)

SMART_CONTRACT_LANGUAGES = {
    '.sol': 'Solidity',
    '.tsol': 'Solidity (experimental/typed)',
    '.vy': 'Vyper',
    '.rs': 'Rust (Solana, CosmWasm, ink!)',
    '.move': 'Move (Aptos, Sui)',
    '.cairo': 'Cairo (StarkNet)',

    '.fc': 'FunC (TON)',
    '.func': 'FunC (TON)',
    '.circom': 'Circom (ZK circuits)',
    '.yul': 'Yul (EVM IR)',

    '.ligo': 'LIGO (Tezos)',
    '.mligo': 'LIGO (OCaml syntax)',
    '.religo': 'LIGO (ReasonML syntax)',
    '.jsligo': 'LIGO (JavaScript syntax)',
    '.tz': 'Michelson (Tezos)',
    '.arl': 'Archetype (Tezos)',

    '.scilla': 'Scilla (Zilliqa)',
    '.daml': 'DAML (Digital Asset)',
    '.plutus': 'Plutus (Cardano)',
    '.hs': 'Haskell (Plutus contracts)',

    '.aes': 'Sophia (Aeternity)',
    '.rho': 'Rholang (RChain)',
    '.clar': 'Clarity (Stacks)',
    '.clarity': 'Clarity (Stacks)',
    '.ink': 'ink! (Rust for Polkadot)',

    '.zok': 'ZoKrates (ZK circuits)',
    '.leo': 'Leo (Aleo)',
    '.noir': 'Noir (Aztec ZK)',
    '.nr': 'Noir (Aztec ZK)',
    '.aleo': 'Aleo instructions',
    '.ark': 'Arkworks (Rust ZK library)',
}


OTHER_EXTENSIONS = (
    '.go', '.ts',
)