# Testnet deployments

This document is the public deployment index for the Confi.cash proof of
concept on Stellar testnet. Testnet units have no value, and the deployment has
not been independently audited.

- Network: Stellar testnet
- Network passphrase: `Test SDF Network ; September 2015`
- Last live verification: 2026-07-26
- [Current public pool source](https://github.com/Confihub/confibatch_pool/commit/eabfa9e81acaa4fe832778b73be98d2509566574)
- [Current public verifier source](https://github.com/Confihub/groth16_verifier/commit/39c58a3126d2da839915367637d3176f2d83d2df)

The public source repositories contain the latest contract implementations.
The live pool below is version 10 and predates the current version 12 standalone
source snapshot, so the source links above are references, not a claim that
building current `main` reproduces the historical deployed pool byte-for-byte.
The contract IDs and hashes below are the independently checkable on-chain
deployment record.

## Shielded pool

| Contract | Version | WASM SHA-256 | Contract ID |
| --- | ---: | --- | --- |
| `confibatch_pool` | 10 | `eb8d65863bfab504211a09f7856d9058fce22eb16fd594a8919079b484f62a8c` | [`CARJLFBCWXXC2756U77XAIWIQPQCE56N4OQR7RIVUXVO3D3UFPO4WVDY`](https://stellar.expert/explorer/testnet/contract/CARJLFBCWXXC2756U77XAIWIQPQCE56N4OQR7RIVUXVO3D3UFPO4WVDY) |

## Groth16 proof verifiers

The deployment uses 11 instances of the same generic verifier WASM. Each
instance is initialized with a different circuit verifying key; the
verifying-key SHA-256 distinguishes those instances.

| Circuit | WASM SHA-256 | Verifying-key SHA-256 | Contract ID |
| --- | --- | --- | --- |
| Deposit | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `5216265aeafc7967a04c77ffd814d3ce395833c7b39f67f0f71335053b7398fd` | [`CBL4BLOGFBZDPUM46WB4LXWN5WAW73QRSN3VFNRIJESOBSUUZ754A5YS`](https://stellar.expert/explorer/testnet/contract/CBL4BLOGFBZDPUM46WB4LXWN5WAW73QRSN3VFNRIJESOBSUUZ754A5YS) |
| Transfer | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `77e2f33b161b528320cf364a76787736023ec9c10d2fd6afc62569b32aeb7f94` | [`CA5DS5RRMU575TI2QAHEIVTY7PFNBX22SZQ32VF7C7DMXTWRI57F5ZI2`](https://stellar.expert/explorer/testnet/contract/CA5DS5RRMU575TI2QAHEIVTY7PFNBX22SZQ32VF7C7DMXTWRI57F5ZI2) |
| Withdraw | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `d1c52187c575cd39be33c1158c9f1d7748c9d5e51180de9eb88b35b1f07c4e0a` | [`CCRXWPQJRZ5ZFU3GKHVRULHMK6DKIEU7G75LMFROBBESHYVY7NJIIKBF`](https://stellar.expert/explorer/testnet/contract/CCRXWPQJRZ5ZFU3GKHVRULHMK6DKIEU7G75LMFROBBESHYVY7NJIIKBF) |
| Batch | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `530b553d2f5feb9485123c1c86e549023b1e8ddec4571ad8f3cc1048f6c70de5` | [`CBPS6VQGBRSIJHCA5WUPBZELCM6LP4MRFYDCCNPZRICQJLDFQ2FW75YK`](https://stellar.expert/explorer/testnet/contract/CBPS6VQGBRSIJHCA5WUPBZELCM6LP4MRFYDCCNPZRICQJLDFQ2FW75YK) |
| Withdraw with change | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `a77203e34b9802af2540fa7b113afc4639c7af9594be2675a125554ee9f8a52b` | [`CB5DO2R2XRXVMIGXQWEPN5V44TAZFZ4CYF7PCWWHJWRP57QHTHG3H7RF`](https://stellar.expert/explorer/testnet/contract/CB5DO2R2XRXVMIGXQWEPN5V44TAZFZ4CYF7PCWWHJWRP57QHTHG3H7RF) |
| Order spend | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `2e4cf6bb8bf3a0c90f4ca15f3476268993c4f4249f3e823dfadeabaa096d7436` | [`CC5MMY45QUC5CR7ATKY5ELQWGKG5ZXE6PSNXFVAQVVB7TVHEPJYYPVXG`](https://stellar.expert/explorer/testnet/contract/CC5MMY45QUC5CR7ATKY5ELQWGKG5ZXE6PSNXFVAQVVB7TVHEPJYYPVXG) |
| Clearing | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `43518a90946875c9bfa754e76fa2761c1a3663080040ac976c75a5974bcac3e0` | [`CCYLLLIA7PNDHBUUTCLXCKEGPZY6O6BC2OZJQMLHWWSX2MXKLBOY22JO`](https://stellar.expert/explorer/testnet/contract/CCYLLLIA7PNDHBUUTCLXCKEGPZY6O6BC2OZJQMLHWWSX2MXKLBOY22JO) |
| Clearing N-buy | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `ea599a13ed3ff9de963f75e9b800cbbfd3061fcf8763fb12d09a30f28d792369` | [`CCCRLHZNUMNHJ7KWTE3GOKCNO6ZPMQRHR2WKYPHUBCWXCVWAUA6G3TQN`](https://stellar.expert/explorer/testnet/contract/CCCRLHZNUMNHJ7KWTE3GOKCNO6ZPMQRHR2WKYPHUBCWXCVWAUA6G3TQN) |
| Split | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `b5dcd1ef314b7408179cca6aea4f3d1cad7e2ce482131c0e829af007247f0de7` | [`CAP23SR64226Y2GZWAUBW3PX2IOFTES2SDC3RKM6ZPOISZPXZS6Z7TU7`](https://stellar.expert/explorer/testnet/contract/CAP23SR64226Y2GZWAUBW3PX2IOFTES2SDC3RKM6ZPOISZPXZS6Z7TU7) |
| Bound swap commit | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `8e5e41146962246f394501424b236506c4cc941475e27a830b1a6715d8a40095` | [`CAKDQEYW3AQFMZVWG3RA67UL4XAKJDSX47CIDR4PYPG3M6S57RXTDSS6`](https://stellar.expert/explorer/testnet/contract/CAKDQEYW3AQFMZVWG3RA67UL4XAKJDSX47CIDR4PYPG3M6S57RXTDSS6) |
| Swap claim | `856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb` | `d3ba3090430daaf0f9bc757af9dd514fc94c2ff0a7b52bd4e817501b4060bc75` | [`CBWCH7SIHY2J4QT67E6FHS3LQ7G62DEBKL7VHPX6TOF7H6KWDHGF3IAD`](https://stellar.expert/explorer/testnet/contract/CBWCH7SIHY2J4QT67E6FHS3LQ7G62DEBKL7VHPX6TOF7H6KWDHGF3IAD) |

## Verify a contract's deployed WASM

With Stellar CLI 25:

```sh
stellar contract fetch \
  --id CARJLFBCWXXC2756U77XAIWIQPQCE56N4OQR7RIVUXVO3D3UFPO4WVDY \
  --network testnet \
  --out-file pool.wasm

shasum -a 256 pool.wasm
```

Replace the contract ID and output filename to verify any verifier row. The
result must equal the row's WASM SHA-256. Verifying-key hashes are calculated
from the canonical serialized value returned by each verifier's on-chain
`vk()` read.
