#!/usr/bin/env node

import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const sourceAccount = process.env.SOURCE_ACCOUNT || process.argv[2];

if (!sourceAccount) {
  console.error(
    'Usage: SOURCE_ACCOUNT=<existing-testnet-G-address> node scripts/verify-deployments.mjs',
  );
  process.exit(2);
}

const pool = {
  name: 'pool',
  id: 'CARJLFBCWXXC2756U77XAIWIQPQCE56N4OQR7RIVUXVO3D3UFPO4WVDY',
  wasm: 'eb8d65863bfab504211a09f7856d9058fce22eb16fd594a8919079b484f62a8c',
};

const verifiers = [
  {
    name: 'deposit',
    id: 'CBL4BLOGFBZDPUM46WB4LXWN5WAW73QRSN3VFNRIJESOBSUUZ754A5YS',
    vk: '5216265aeafc7967a04c77ffd814d3ce395833c7b39f67f0f71335053b7398fd',
  },
  {
    name: 'transfer',
    id: 'CA5DS5RRMU575TI2QAHEIVTY7PFNBX22SZQ32VF7C7DMXTWRI57F5ZI2',
    vk: '77e2f33b161b528320cf364a76787736023ec9c10d2fd6afc62569b32aeb7f94',
  },
  {
    name: 'withdraw',
    id: 'CCRXWPQJRZ5ZFU3GKHVRULHMK6DKIEU7G75LMFROBBESHYVY7NJIIKBF',
    vk: 'd1c52187c575cd39be33c1158c9f1d7748c9d5e51180de9eb88b35b1f07c4e0a',
  },
  {
    name: 'batch',
    id: 'CBPS6VQGBRSIJHCA5WUPBZELCM6LP4MRFYDCCNPZRICQJLDFQ2FW75YK',
    vk: '530b553d2f5feb9485123c1c86e549023b1e8ddec4571ad8f3cc1048f6c70de5',
  },
  {
    name: 'withdraw-change',
    id: 'CB5DO2R2XRXVMIGXQWEPN5V44TAZFZ4CYF7PCWWHJWRP57QHTHG3H7RF',
    vk: 'a77203e34b9802af2540fa7b113afc4639c7af9594be2675a125554ee9f8a52b',
  },
  {
    name: 'order-spend',
    id: 'CC5MMY45QUC5CR7ATKY5ELQWGKG5ZXE6PSNXFVAQVVB7TVHEPJYYPVXG',
    vk: '2e4cf6bb8bf3a0c90f4ca15f3476268993c4f4249f3e823dfadeabaa096d7436',
  },
  {
    name: 'clearing',
    id: 'CCYLLLIA7PNDHBUUTCLXCKEGPZY6O6BC2OZJQMLHWWSX2MXKLBOY22JO',
    vk: '43518a90946875c9bfa754e76fa2761c1a3663080040ac976c75a5974bcac3e0',
  },
  {
    name: 'clearing-nbuy',
    id: 'CCCRLHZNUMNHJ7KWTE3GOKCNO6ZPMQRHR2WKYPHUBCWXCVWAUA6G3TQN',
    vk: 'ea599a13ed3ff9de963f75e9b800cbbfd3061fcf8763fb12d09a30f28d792369',
  },
  {
    name: 'split',
    id: 'CAP23SR64226Y2GZWAUBW3PX2IOFTES2SDC3RKM6ZPOISZPXZS6Z7TU7',
    vk: 'b5dcd1ef314b7408179cca6aea4f3d1cad7e2ce482131c0e829af007247f0de7',
  },
  {
    name: 'bound-swap-commit',
    id: 'CAKDQEYW3AQFMZVWG3RA67UL4XAKJDSX47CIDR4PYPG3M6S57RXTDSS6',
    vk: '8e5e41146962246f394501424b236506c4cc941475e27a830b1a6715d8a40095',
  },
  {
    name: 'swap-claim',
    id: 'CBWCH7SIHY2J4QT67E6FHS3LQ7G62DEBKL7VHPX6TOF7H6KWDHGF3IAD',
    vk: 'd3ba3090430daaf0f9bc757af9dd514fc94c2ff0a7b52bd4e817501b4060bc75',
  },
].map((verifier) => ({
  ...verifier,
  wasm: '856b0a615f21f11c40923a0ebaebfa44112f1cf05dbc06542651ab2be281bbcb',
}));

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function normalize(value) {
  if (typeof value === 'string') return value.toLowerCase();
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, normalize(value[key])]),
    );
  }
  return value;
}

function canonicalVk(value) {
  return JSON.stringify(normalize(value));
}

async function fetchWasm(contract, directory) {
  const file = join(directory, `${contract.name}.wasm`);
  await execFile(
    'stellar',
    [
      'contract',
      'fetch',
      '--id',
      contract.id,
      '--network',
      'testnet',
      '--out-file',
      file,
    ],
    { maxBuffer: 16 * 1024 * 1024 },
  );
  const actual = sha256(await readFile(file));
  if (actual !== contract.wasm) {
    throw new Error(`${contract.name}: WASM ${actual}, expected ${contract.wasm}`);
  }
  return actual;
}

async function readVk(verifier) {
  const { stdout } = await execFile(
    'stellar',
    [
      'contract',
      'invoke',
      '--id',
      verifier.id,
      '--source-account',
      sourceAccount,
      '--network',
      'testnet',
      '--',
      'vk',
    ],
    { maxBuffer: 16 * 1024 * 1024 },
  );
  const json = stdout
    .trim()
    .split('\n')
    .map((line) => line.trim())
    .findLast((line) => line.startsWith('{'));
  if (!json) throw new Error(`${verifier.name}: vk() returned no JSON object`);
  return JSON.parse(json);
}

const directory = await mkdtemp(join(tmpdir(), 'confi-deployments-'));

try {
  const poolWasm = await fetchWasm(pool, directory);
  console.log(`OK ${pool.name.padEnd(18)} wasm ${poolWasm}`);

  const liveVkHashes = new Set();
  for (const verifier of verifiers) {
    const wasm = await fetchWasm(verifier, directory);
    const vk = sha256(Buffer.from(canonicalVk(await readVk(verifier)), 'utf8'));
    if (vk !== verifier.vk) {
      throw new Error(`${verifier.name}: VK ${vk}, expected ${verifier.vk}`);
    }
    liveVkHashes.add(vk);
    console.log(`OK ${verifier.name.padEnd(18)} wasm ${wasm} vk ${vk}`);
  }
  if (liveVkHashes.size !== verifiers.length) {
    throw new Error(
      `Verifier keys are not distinct: ${liveVkHashes.size} hashes for ${verifiers.length} contracts`,
    );
  }

  console.log(
    `Verified the pool and ${verifiers.length} distinct verifier keys on Stellar testnet.`,
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
