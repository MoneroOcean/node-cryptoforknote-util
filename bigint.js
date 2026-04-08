"use strict";

const BASE_DIFF = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

function parseBigInt(value, base) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(Math.trunc(value));
  if (Buffer.isBuffer(value)) return BigInt(`0x${value.toString("hex") || "00"}`);
  if (typeof value === "string") {
    return BigInt(base === 16 ? `0x${value}` : value);
  }
  if (value && typeof value === "object") {
    if (typeof value.value === "bigint") return value.value;
    if (typeof value.toString === "function") {
      const stringValue = value.toString(base || 10);
      return BigInt(base === 16 ? `0x${stringValue}` : stringValue);
    }
  }
  return BigInt(value || 0);
}

module.exports = {
  BASE_DIFF,
  parseBigInt
};
