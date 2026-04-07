const bignum  = require('bignum');
const base58  = require('base58-native');
const bech32  = require('bech32');
const bitcoin = require('bitcoinjs-lib');

const diff1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

function reverseBuffer(buff) {
  let reversed = Buffer.alloc(buff.length);
  for (let i = buff.length - 1; i >= 0; i--) reversed[buff.length - i - 1] = buff[i];
  return reversed;
}

function reverseByteOrder(buff) {
  for (let i = 0; i < 8; i++) buff.writeUInt32LE(buff.readUInt32BE(i * 4), i * 4);
  return reverseBuffer(buff);
}

function packInt32LE(num) {
  let buff = Buffer.alloc(4);
  buff.writeInt32LE(num, 0);
  return buff;
}

function packInt32BE(num) {
  let buff = Buffer.alloc(4);
  buff.writeInt32BE(num, 0);
  return buff;
}

function packUInt16LE(num) {
  let buff = Buffer.alloc(2);
  buff.writeUInt16LE(num, 0);
  return buff;
}

function packUInt32LE(num) {
  let buff = Buffer.alloc(4);
  buff.writeUInt32LE(num, 0);
  return buff;
}

function packUInt32BE(num) {
  let buff = Buffer.alloc(4);
  buff.writeUInt32BE(num, 0);
  return buff;
}

function packInt64LE(num){
  let buff = Buffer.alloc(8);
  buff.writeUInt32LE(num % Math.pow(2, 32), 0);
  buff.writeUInt32LE(Math.floor(num / Math.pow(2, 32)), 4);
  return buff;
}

// Defined in bitcoin protocol here:
// https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
function varIntBuffer(n) {
  if (n < 0xfd) {
    return Buffer.from([n]);
  } else if (n <= 0xffff) {
    let buff = Buffer.alloc(3);
    buff[0] = 0xfd;
    buff.writeUInt16LE(n, 1);
    return buff;
  } else if (n <= 0xffffffff) {
    let buff = Buffer.alloc(5);
    buff[0] = 0xfe;
    buff.writeUInt32LE(n, 1);
    return buff;
  } else{
    let buff = Buffer.alloc(9);
    buff[0] = 0xff;
    packUInt16LE(n).copy(buff, 1);
    return buff;
  }
}

// "serialized CScript" formatting as defined here:
// https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki#specification
// Used to format height and date when putting into script signature:
// https://en.bitcoin.it/wiki/Script
function serializeNumber(n) {
  // New version from TheSeven
  if (n >= 1 && n <= 16) return Buffer.from([0x50 + n]);
  var l = 1;
  var buff = Buffer.alloc(9);
  while (n > 0x7f) {
      buff.writeUInt8(n & 0xff, l++);
      n >>= 8;
  }
  buff.writeUInt8(l, 0);
  buff.writeUInt8(n, l++);
  return buff.slice(0, l);
}

// Used for serializing strings used in script signature
function serializeString(s) {
  if (s.length < 253) {
    return Buffer.concat([ Buffer.from([s.length]), Buffer.from(s) ]);
  } else if (s.length < 0x10000) {
    return Buffer.concat([ Buffer.from([253]), packUInt16LE(s.length), Buffer.from(s) ]);
  } else if (s.length < 0x100000000) {
    return Buffer.concat([ Buffer.from([254]), packUInt32LE(s.length), Buffer.from(s) ]);
  } else {
    return Buffer.concat([ Buffer.from([255]), packUInt16LE(s.length), Buffer.from(s) ]);
  }
}

// An exact copy of python's range feature. Written by Tadeck:
// http://stackoverflow.com/a/8273091
function range(start, stop, step) {
  if (typeof stop === 'undefined') {
    stop = start;
    start = 0;
  }
  if (typeof step === 'undefined') {
    step = 1;
  }
  if ((step > 0 && start >= stop) || (step < 0 && start <= stop)) {
    return [];
  }
  let result = [];
  for (let i = start; step > 0 ? i < stop : i > stop; i += step) {
    result.push(i);
  }
  return result;
}

function uint256BufferFromHash(hex) {
  let fromHex = Buffer.from(hex, 'hex');
  if (fromHex.length != 32) {
    let empty = Buffer.alloc(32);
    empty.fill(0);
    fromHex.copy(empty);
    fromHex = empty;
  }
  return reverseBuffer(fromHex);
}

function getTransactionBuffers(txs) {
  let txHashes = txs.map(function(tx) {
    if (tx.txid !== undefined) {
      return uint256BufferFromHash(tx.txid);
    }
    return uint256BufferFromHash(tx.hash);
  });
  return [null].concat(txHashes);
}

function addressToScript(addr) {
  let decoded;
  try {
    decoded = base58.decode(addr);
  } catch(err) {}
  if (!decoded || decoded.length != 25) {
    const decoded2 = Buffer.from(bech32.bech32.fromWords(bech32.bech32.decode(addr).words.slice(1)));
    if (decoded2.length != 20) throw new Error('Invalid address ' + addr);
    return Buffer.concat([Buffer.from([0x0, 0x14]), decoded2]);
  }
  const pubkey = decoded.slice(1, -4);
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), pubkey, Buffer.from([0x88, 0xac])]);
}

function createTransactionOutput(amount, payee, rewardToPool, reward, txOutputBuffers, payeeScript) {
  const payeeReward = amount;
  if (!payeeScript) payeeScript = addressToScript(payee);
  txOutputBuffers.push(Buffer.concat([
    packInt64LE(payeeReward),
    varIntBuffer(payeeScript.length),
    payeeScript
  ]));
  return { reward: reward - amount, rewardToPool: rewardToPool - amount };
}

function generateTransactionOutputs(rpcData, poolAddress) {
  let reward       = rpcData.coinbasevalue + (rpcData.coinbasedevreward ? rpcData.coinbasedevreward.value : 0);
  let rewardToPool = reward;
  let txOutputBuffers = [];

  if (rpcData.coinbasedevreward) {
    const rewards = createTransactionOutput(rpcData.coinbasedevreward.value, null, rewardToPool, reward, txOutputBuffers, Buffer.from(rpcData.coinbasedevreward.scriptpubkey, 'hex'));
    reward        = rewards.reward;
    rewardToPool  = rewards.rewardToPool;
  }

  if (rpcData.smartnode) {
    if (rpcData.smartnode.payee) {
      const rewards = createTransactionOutput(rpcData.smartnode.amount, rpcData.smartnode.payee, rewardToPool, reward, txOutputBuffers);
      reward        = rewards.reward;
      rewardToPool  = rewards.rewardToPool;
    } else if (Array.isArray(rpcData.smartnode)) {
      for (let i in rpcData.smartnode) {
        const rewards = createTransactionOutput(rpcData.smartnode[i].amount, rpcData.smartnode[i].payee, rewardToPool, reward, txOutputBuffers);
	reward        = rewards.reward;
        rewardToPool  = rewards.rewardToPool;
      }
    } 
  }

  if (rpcData.superblock) {
    for (let i in rpcData.superblock) {
      const rewards = createTransactionOutput(rpcData.superblock[i].amount, rpcData.superblock[i].payee, rewardToPool, reward, txOutputBuffers);
      reward        = rewards.reward;
      rewardToPool  = rewards.rewardToPool;
    }
  }

  if (rpcData.founder_payments_started && rpcData.founder) {
    const founderReward = rpcData.founder.amount || 0;
    const rewards = createTransactionOutput(founderReward, rpcData.founder.payee, rewardToPool, reward, txOutputBuffers);
    reward        = rewards.reward;
    rewardToPool  = rewards.rewardToPool;
  }

  createTransactionOutput(rewardToPool, null, rewardToPool, reward, txOutputBuffers, Buffer.from(addressToScript(poolAddress), "hex"));

  if (rpcData.default_witness_commitment) {
    createTransactionOutput(0, null, rewardToPool, reward, txOutputBuffers, Buffer.from(rpcData.default_witness_commitment, 'hex'));
    txOutputBuffers.push(Buffer.concat([
      varIntBuffer(1),
      varIntBuffer(32),
      Buffer.alloc(32, 0)
    ]));
  }

  return Buffer.concat([ varIntBuffer(rpcData.default_witness_commitment ? txOutputBuffers.length - 1 : txOutputBuffers.length), Buffer.concat(txOutputBuffers)]);
}

module.exports.RtmBlockTemplate = function(rpcData, poolAddress) {
  const extraNoncePlaceholderLength = 17;
  const coinbaseVersion = rpcData.coinbasedevreward ? Buffer.concat([packUInt16LE(1), packUInt16LE(0)]) : Buffer.concat([packUInt16LE(3), packUInt16LE(5)]);

  const scriptSigPart1 = Buffer.concat([
    serializeNumber(rpcData.height),
    Buffer.from(rpcData.coinbaseaux.flags ? rpcData.coinbaseaux.flags : "", 'hex'),
    serializeNumber(Date.now() / 1000 | 0),
    Buffer.from([extraNoncePlaceholderLength])
  ]);

  const scriptSigPart2 = serializeString('/nodeStratum/');

  const is_witness = rpcData.default_witness_commitment !== undefined;

  const blob1 = Buffer.concat([
    coinbaseVersion,
    // transaction input
    Buffer.from(is_witness ? "0001" : "", 'hex'),
    varIntBuffer(1), // txInputsCount
    uint256BufferFromHash(""), // txInPrevOutHash
    packUInt32LE(Math.pow(2, 32) - 1), // txInPrevOutIndex
    varIntBuffer(scriptSigPart1.length + extraNoncePlaceholderLength + scriptSigPart2.length),
    scriptSigPart1
  ]);

  let blob2 = Buffer.concat([
    scriptSigPart2,
    packUInt32LE(0), // txInSequence
    // end transaction input
    // transaction output
    generateTransactionOutputs(rpcData, poolAddress, is_witness),
    // end transaction ouput
    packUInt32LE(0) // txLockTime
  ]);

  if (rpcData.coinbase_payload) {
     blob2 = Buffer.concat([
       blob2,
       varIntBuffer(rpcData.coinbase_payload.length / 2),
       Buffer.from(rpcData.coinbase_payload, 'hex')
     ]);
  }

  const prev_hash = reverseBuffer(Buffer.from(rpcData.previousblockhash, 'hex')).toString('hex');
  const version = packInt32LE(rpcData.version).toString('hex');
  const curtime = packUInt32LE(rpcData.curtime).toString('hex');
  let bits = Buffer.from(rpcData.bits, 'hex');
  bits.writeUInt32LE(bits.readUInt32BE());
  let txs = [];
  // skip version 1 transaction because they contain some OP_RETURN(0x6A) opcode in the beginning of
  // tx input scripts instead of size of script part so not sure how to parse them
  // just drop them for now
  // example: https://explorer.raptoreum.com/tx/1461d70fa8362b0896e2e9be6312521f2684f22c9b0f9152695f33f67d9f9d3f
  rpcData.transactions.forEach(function(tx) {
    if (tx.version != 1) {
      try {
        bitcoin.Transaction.fromBuffer(Buffer.from(tx.data, 'hex'), false, false);
      } catch(err) {
        console.error("Skip RTM tx due to parse error: " + tx.data);
        return; // skip transaction if it is not parsed OK (varint coding seems to be different for RTM)
      }
      txs.push(tx);
    } else {
      console.error("Skip RTM v1 tx: " + tx.data);
    }
  });
  const txn = varIntBuffer(txs.length + 1);

  return {
    difficulty:         parseFloat((diff1 / bignum(rpcData.target, 16).toNumber()).toFixed(9)),
    height:             rpcData.height,
    prev_hash:          prev_hash,
    blocktemplate_blob: version + prev_hash + Buffer.alloc(32, 0).toString('hex') + curtime + bits.toString('hex') + Buffer.alloc(4, 0).toString('hex') +
                        txn.toString('hex') + blob1.toString('hex') + Buffer.alloc(extraNoncePlaceholderLength, 0xCC).toString('hex') + blob2.toString('hex')  +
                        Buffer.concat(txs.map(function(tx) { return Buffer.from(tx.data, 'hex'); })).toString('hex'),
    reserved_offset:    80 + txn.length + blob1.length
  }
}
