#include <cmath>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <string>
#include <algorithm>
#include "cryptonote_core/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "common/base58.h"
#include "serialization/binary_utils.h"
#include <nan.h>

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

using namespace node;
using namespace v8;
using namespace cryptonote;

const size_t TX_EXTRA_FIELD_TAG_BYTES = 1;
const size_t TX_MM_FIELD_SIZE_BYTES = 1;
const size_t MAX_VARINT_SIZE = 9;
const size_t TX_MM_TAG_MAX_BYTES = MAX_VARINT_SIZE + sizeof(crypto::hash);
const size_t MERGE_MINING_TAG_RESERVED_SIZE = TX_EXTRA_FIELD_TAG_BYTES  + TX_MM_FIELD_SIZE_BYTES + TX_MM_TAG_MAX_BYTES;
const size_t POOL_NONCE_SIZE = 19;

blobdata uint64be_to_blob(uint64_t num) {
    blobdata res = "        ";
    res[0] = num >> 56 & 0xff;
    res[1] = num >> 48 & 0xff;
    res[2] = num >> 40 & 0xff;
    res[3] = num >> 32 & 0xff;
    res[4] = num >> 24 & 0xff;
    res[5] = num >> 16 & 0xff;
    res[6] = num >> 8  & 0xff;
    res[7] = num       & 0xff;
    return res;
}


                             
static bool fillExtra(cryptonote::block& block1, const cryptonote::block& block2) {
    cryptonote::tx_extra_merge_mining_tag mm_tag;
    mm_tag.depth = 0;
    if (!cryptonote::get_block_header_hash(block2, mm_tag.merkle_root)) return false;

    block1.miner_tx.extra.clear();
    if (!cryptonote::append_mm_tag_to_extra(block1.miner_tx.extra, mm_tag)) return false;

    return true;
}


static bool fillExtraMM(cryptonote::block& block1, const cryptonote::block& block2)
{
    if (block2.timestamp > block1.timestamp) { // get the most recent timestamp (solve duplicated timestamps on child coin)
        block1.timestamp = block2.timestamp;
    }
    
    size_t MERGE_MINING_TAG_RESERVED_SIZE_EX = MERGE_MINING_TAG_RESERVED_SIZE + POOL_NONCE_SIZE;
    std::vector<uint8_t>& extra = block1.miner_tx.extra;
    std::string extraAsString(reinterpret_cast<const char*>(extra.data()), extra.size());

    std::string extraNonceTemplate;
    extraNonceTemplate.push_back(TX_EXTRA_NONCE);
    extraNonceTemplate.push_back(MERGE_MINING_TAG_RESERVED_SIZE_EX);
    extraNonceTemplate.append(MERGE_MINING_TAG_RESERVED_SIZE, '\0');

    size_t extraNoncePos = extraAsString.find(extraNonceTemplate);
    if (std::string::npos == extraNoncePos) {
        return false;
    }

    cryptonote::tx_extra_merge_mining_tag tag;
    tag.depth = 0;
    if (!cryptonote::get_block_header_hash(block2, tag.merkle_root)) {
        return false;
    }

    std::vector<uint8_t> extraNonceReplacement;
    if (!cryptonote::append_mm_tag_to_extra(extraNonceReplacement, tag)) {
        return false;
    }

    if (MERGE_MINING_TAG_RESERVED_SIZE < extraNonceReplacement.size()) {
        return false;
    }

    size_t diff = (extraNonceTemplate.size() + POOL_NONCE_SIZE) - extraNonceReplacement.size();
    if (0 < diff) {
        extraNonceReplacement.push_back(TX_EXTRA_NONCE);
        extraNonceReplacement.push_back(static_cast<uint8_t>(diff - 2));
    }

    std::copy(extraNonceReplacement.begin(), extraNonceReplacement.end(), extra.begin() + extraNoncePos);

    return true;
}


static bool mergeBlocks(const cryptonote::block& block1, cryptonote::block& block2, const std::vector<crypto::hash>& branch2) {
    block2.timestamp = block1.timestamp;
    block2.parent_block.major_version = block1.major_version;
    block2.parent_block.minor_version = block1.minor_version;
    block2.parent_block.prev_id = block1.prev_id;
    block2.parent_block.nonce = block1.nonce;
    block2.parent_block.miner_tx = block1.miner_tx;
    block2.parent_block.number_of_transactions = block1.tx_hashes.size() + 1;
    block2.parent_block.miner_tx_branch.resize(crypto::tree_depth(block1.tx_hashes.size() + 1));
    std::vector<crypto::hash> transactionHashes;
    transactionHashes.push_back(cryptonote::get_transaction_hash(block1.miner_tx));
    std::copy(block1.tx_hashes.begin(), block1.tx_hashes.end(), std::back_inserter(transactionHashes));
    tree_branch(transactionHashes.data(), transactionHashes.size(), block2.parent_block.miner_tx_branch.data());
    block2.parent_block.blockchain_branch = branch2;
    return true;
}

static bool construct_parent_block(const cryptonote::block& b, cryptonote::block& parent_block) {
    parent_block.major_version = 1;
    parent_block.minor_version = 0;
    parent_block.timestamp = b.timestamp;
    parent_block.prev_id = b.prev_id;
    parent_block.nonce = b.parent_block.nonce;
    parent_block.miner_tx.version = CURRENT_TRANSACTION_VERSION;
    parent_block.miner_tx.unlock_time = 0;

    return fillExtra(parent_block, b);
}


NAN_METHOD(get_merge_mining_tag_reserved_size) {
    Local<Integer> returnValue = Nan::New(static_cast<uint32_t>(MERGE_MINING_TAG_RESERVED_SIZE + POOL_NONCE_SIZE));
    info.GetReturnValue().Set(returnValue);
}

/*
 * var blob = convert_blob (parentBlockBuffer, cnBlobType, [childBlockBuffer], [PoW])
 */
NAN_METHOD(convert_blob) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    enum BLOB_TYPE blob_type = BLOB_TYPE_CRYPTONOTE;
    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        blob_type = static_cast<enum BLOB_TYPE>(Nan::To<int>(info[1]).FromMaybe(0));
    }

    enum POW_TYPE pow_type = POW_TYPE_NOT_SET;
    if (info.Length() >= 4) {
        if (!info[3]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 4 should be a number");
        pow_type = static_cast<enum POW_TYPE>(Nan::To<int>(info[3]).FromMaybe(0));
    }

    //convert
    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(input, b)) return THROW_ERROR_EXCEPTION("Failed to parse block");

    block b2 = AUTO_VAL_INIT(b2);
    if (info.Length() > 2 && !info[2]->IsNumber()) { // MM
        b2.set_blob_type(BLOB_TYPE_FORKNOTE2); // Only forknote 2 blob types support being mm as child coin
        Local<Object> child_target = info[2]->ToObject();
        blobdata child_input = std::string(Buffer::Data(child_target), Buffer::Length(child_target));
        if (!Buffer::HasInstance(child_target)) return THROW_ERROR_EXCEPTION("convert_blob: Argument (Child block) should be a buffer object.");
        if (!parse_and_validate_block_from_blob(child_input, b2)) return THROW_ERROR_EXCEPTION("convert_blob: Failed to parse child block");
    }

    if (blob_type == BLOB_TYPE_FORKNOTE2) {
        block parent_block;
        if (POW_TYPE_NOT_SET != pow_type) b.minor_version = pow_type;
        if (!construct_parent_block(b, parent_block)) return THROW_ERROR_EXCEPTION("convert_blob: Failed to construct parent block");
        if (!get_block_hashing_blob(parent_block, output)) return THROW_ERROR_EXCEPTION("convert_blob: Failed to create mining block");
    } else {
        if (BLOB_TYPE_CRYPTONOTE == blob_type && info.Length() > 2 && !info[2]->IsNumber()) { // MM
            if (!fillExtraMM(b, b2)) {
                return THROW_ERROR_EXCEPTION("convert_blob: Failed to add merged mining tag to parent block extra");
            }
        }
        if (!get_block_hashing_blob(b, output)) return THROW_ERROR_EXCEPTION("convert_blob: Failed to create mining block");
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(get_block_id) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    enum BLOB_TYPE blob_type = BLOB_TYPE_CRYPTONOTE;
    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        blob_type = static_cast<enum BLOB_TYPE>(Nan::To<int>(info[1]).FromMaybe(0));
    }

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(input, b)) return THROW_ERROR_EXCEPTION("Failed to parse block");

    crypto::hash block_id;
    if (!get_block_hash(b, block_id)) return THROW_ERROR_EXCEPTION("Failed to calculate hash for block");

    char *cstr = reinterpret_cast<char*>(&block_id);
    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(cstr, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

/*
 * var shareBuffer = construct_block_blob(parentBlockTemplateBuffer, nonceBuffer, cnBlobType, [childBlockTemplateBuffer], [PoW]);
 */
NAN_METHOD(construct_block_blob) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> block_template_buf = info[0]->ToObject();
    Local<Object> nonce_buf = info[1]->ToObject();

    if (!Buffer::HasInstance(block_template_buf) || !Buffer::HasInstance(nonce_buf)) return THROW_ERROR_EXCEPTION("Both arguments should be buffer objects.");
    if (Buffer::Length(nonce_buf) != 4) return THROW_ERROR_EXCEPTION("Nonce buffer has invalid size.");

    uint32_t nonce = *reinterpret_cast<uint32_t*>(Buffer::Data(nonce_buf));
    blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
    blobdata output = "";

    enum BLOB_TYPE blob_type = BLOB_TYPE_CRYPTONOTE;
    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        blob_type = static_cast<enum BLOB_TYPE>(Nan::To<int>(info[2]).FromMaybe(0));
    }

    enum POW_TYPE pow_type = POW_TYPE_NOT_SET;
    if (info.Length() >= 5) {
        if (!info[4]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 5 should be a number");
        pow_type = static_cast<enum POW_TYPE>(Nan::To<int>(info[4]).FromMaybe(0));
    }

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(blob_type);
    if (!parse_and_validate_block_from_blob(block_template_blob, b)) return THROW_ERROR_EXCEPTION("Failed to parse block");

    block b2 = AUTO_VAL_INIT(b2);
    if (info.Length() > 3 && !info[3]->IsNumber()) { // MM
        b2.set_blob_type(BLOB_TYPE_FORKNOTE2); // Only forknote 2 blob types support being mm as child coin
        Local<Object> child_target = info[3]->ToObject();
        blobdata child_input = std::string(Buffer::Data(child_target), Buffer::Length(child_target));
        if (!Buffer::HasInstance(child_target)) return THROW_ERROR_EXCEPTION("Argument (Child block) should be a buffer object.");
        if (!parse_and_validate_block_from_blob(child_input, b2)) return THROW_ERROR_EXCEPTION("Failed to parse child block");
    }

    b.nonce = nonce;
    if (blob_type == BLOB_TYPE_FORKNOTE2) {
        block parent_block;
        b.parent_block.nonce = nonce;
        if (POW_TYPE_NOT_SET != pow_type) b.minor_version = pow_type;
        if (!construct_parent_block(b, parent_block)) return THROW_ERROR_EXCEPTION("Failed to construct parent block");
        if (!mergeBlocks(parent_block, b, std::vector<crypto::hash>())) return THROW_ERROR_EXCEPTION("Failed to postprocess mining block");
    } else if (BLOB_TYPE_CRYPTONOTE == blob_type && info.Length() > 3 && !info[3]->IsNumber()) { // MM
            if (!fillExtraMM(b, b2)) {
                return THROW_ERROR_EXCEPTION("Failed to add merged mining tag to parent block extra");
            }
        }

    if (!block_to_blob(b, output)) return THROW_ERROR_EXCEPTION("Failed to convert block to blob");

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}


NAN_METHOD(address_decode) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");
    
    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    blobdata data;
    uint64_t prefix;
    if (!tools::base58::decode_addr(input, prefix, data)) {
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    account_public_address adr;
    if (!::serialization::parse_binary(data, adr) || !crypto::check_key(adr.m_spend_public_key) || !crypto::check_key(adr.m_view_public_key)) {
        if (!data.length()) {
            info.GetReturnValue().Set(Nan::Undefined());
            return;
        }
        data = uint64be_to_blob(prefix) + data;
        v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)data.data(), data.size()).ToLocalChecked();
        info.GetReturnValue().Set(returnValue);
    } else {
        info.GetReturnValue().Set(Nan::New(static_cast<uint32_t>(prefix)));
    }
}

NAN_METHOD(address_decode_integrated) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    blobdata data;
    uint64_t prefix;
    if (!tools::base58::decode_addr(input, prefix, data)) {
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    integrated_address iadr;
    if (!::serialization::parse_binary(data, iadr) || !crypto::check_key(iadr.adr.m_spend_public_key) || !crypto::check_key(iadr.adr.m_view_public_key)) {
        if (!data.length()) {
            info.GetReturnValue().Set(Nan::Undefined());
            return;
        }
        data = uint64be_to_blob(prefix) + data;
        v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)data.data(), data.size()).ToLocalChecked();
        info.GetReturnValue().Set(returnValue);
    } else {
        info.GetReturnValue().Set(Nan::New(static_cast<uint32_t>(prefix)));
    }
}


/**
 * var mmShareBuffer = merge_blocks(shareBuffer, childBlockTemplate, [PoW] );
 */
NAN_METHOD(merge_blocks) {

    if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments (shareBuffer, block2).");

    Local<Object> block_template_buf = info[0]->ToObject();
    Local<Object> child_block_template_buf = info[1]->ToObject();

    if (!Buffer::HasInstance(block_template_buf))
        return THROW_ERROR_EXCEPTION("First argument should be a buffer object.");
    
    if (!Buffer::HasInstance(child_block_template_buf))
        return THROW_ERROR_EXCEPTION("Second argument should be a buffer object.");

    enum POW_TYPE pow_type = POW_TYPE_NOT_SET;
    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        pow_type = static_cast<enum POW_TYPE>(Nan::To<int>(info[2]).FromMaybe(0));
    }

    blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
    blobdata child_block_template_blob = std::string(Buffer::Data(child_block_template_buf), Buffer::Length(child_block_template_buf));
    blobdata output = "";

    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(BLOB_TYPE_CRYPTONOTE);
    if (!parse_and_validate_block_from_blob(block_template_blob, b)) return THROW_ERROR_EXCEPTION("Failed to parse parent block (merge_blocks)");

    block b2 = AUTO_VAL_INIT(b2);
    b2.set_blob_type(BLOB_TYPE_FORKNOTE2);
    if (!parse_and_validate_block_from_blob(child_block_template_blob, b2)) return THROW_ERROR_EXCEPTION("Failed to parse child block (merge_blocks)");

    if (!mergeBlocks(b, b2, std::vector<crypto::hash>()))
            return THROW_ERROR_EXCEPTION("mergeBlocks(b,b2): Failed to postprocess mining block");
    if (POW_TYPE_NOT_SET != pow_type) b2.minor_version = pow_type;
    
    if (!block_to_blob(b2, output)) {
        return THROW_ERROR_EXCEPTION("Failed to convert block to blob (merge_blocks)");
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}


NAN_METHOD(fill_extra) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide two arguments (parentBlock, childBlock).");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");
    Local<Object> child_target = info[1]->ToObject();
    if (!Buffer::HasInstance(child_target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata child_input = std::string(Buffer::Data(child_target), Buffer::Length(child_target));
    blobdata output = "";

    //convert
    block b = AUTO_VAL_INIT(b);
    b.set_blob_type(BLOB_TYPE_CRYPTONOTE);
    if (!parse_and_validate_block_from_blob(input, b)) return THROW_ERROR_EXCEPTION("Failed to parse block");

    block b2 = AUTO_VAL_INIT(b2);
    b.set_blob_type(BLOB_TYPE_FORKNOTE2);
    if (!parse_and_validate_block_from_blob(child_input, b2)) return THROW_ERROR_EXCEPTION("Failed to parse child block");


    
    if (!fillExtraMM(b, b2)) {
        return THROW_ERROR_EXCEPTION("Failed to add merged mining tag to parent block extra (convert_blob)");
    }
    if (!get_block_hashing_blob(b, output)) return THROW_ERROR_EXCEPTION("Failed to create mining block");

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}


NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("construct_block_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(construct_block_blob)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_block_id").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_block_id)).ToLocalChecked());
    Nan::Set(target, Nan::New("convert_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob)).ToLocalChecked());
    Nan::Set(target, Nan::New("address_decode").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode)).ToLocalChecked());
    Nan::Set(target, Nan::New("address_decode_integrated").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode_integrated)).ToLocalChecked());

    Nan::Set(target, Nan::New("merge_blocks").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(merge_blocks)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_merge_mining_tag_reserved_size").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_merge_mining_tag_reserved_size)).ToLocalChecked());
    Nan::Set(target, Nan::New("fill_extra").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(fill_extra)).ToLocalChecked());
}

NODE_MODULE(cryptoforknote, init)