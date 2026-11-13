import { describe, expect, it } from "vitest";
import { decodeCbor, InvalidCborError, type CborValue } from "../src/index.js";

function hex(encoded: string): Uint8Array {
  return Uint8Array.from(encoded.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function range(from: number, to: number): number[] {
  return Array.from({ length: to - from + 1 }, (_, i) => from + i);
}

// RFC 8949 Appendix A, the examples inside the subset: definite lengths, no floats, no tags, integers up to 2^53 - 1.
const DECODED: readonly (readonly [string, CborValue])[] = [
  ["00", 0],
  ["01", 1],
  ["0a", 10],
  ["17", 23],
  ["1818", 24],
  ["1819", 25],
  ["1864", 100],
  ["1903e8", 1000],
  ["1a000f4240", 1000000],
  ["1b000000e8d4a51000", 1000000000000],
  ["20", -1],
  ["29", -10],
  ["3863", -100],
  ["3903e7", -1000],
  ["f4", false],
  ["f5", true],
  ["f6", null],
  ["40", new Uint8Array()],
  ["4401020304", new Uint8Array([1, 2, 3, 4])],
  ["60", ""],
  ["6161", "a"],
  ["6449455446", "IETF"],
  ["62225c", '"\\'],
  ["62c3bc", "ü"],
  ["63e6b0b4", "水"],
  ["64f0908591", "𐅑"],
  ["80", []],
  ["83010203", [1, 2, 3]],
  ["8301820203820405", [1, [2, 3], [4, 5]]],
  ["98190102030405060708090a0b0c0d0e0f101112131415161718181819", range(1, 25)],
  ["a0", new Map()],
  ["a201020304", new Map([[1, 2], [3, 4]])],
  ["a26161016162820203", new Map<string, CborValue>([["a", 1], ["b", [2, 3]]])],
  ["826161a161626163", ["a", new Map([["b", "c"]])]],
  ["a56161614161626142616361436164614461656145", new Map([["a", "A"], ["b", "B"], ["c", "C"], ["d", "D"], ["e", "E"]])],
];

// RFC 8949 Appendix A, the examples outside the subset, which the decoder must reject rather than misread.
const REJECTED: readonly string[] = [
  "1bffffffffffffffff",
  "c249010000000000000000",
  "3bffffffffffffffff",
  "c349010000000000000000",
  "f90000",
  "f93c00",
  "fb3ff199999999999a",
  "fa47c35000",
  "f97c00",
  "f97e00",
  "f7",
  "f0",
  "f8ff",
  "c074323031332d30332d32315432303a30343a30305a",
  "c11a514b67b0",
  "d74401020304",
  "d818456449455446",
  "5f42010243030405ff",
  "7f657374726561646d696e67ff",
  "9fff",
  "9f018202039f0405ffff",
  "83018202039f0405ff",
  "bf61610161629f0203ffff",
  "826161bf61626163ff",
];

describe("RFC 8949 Appendix A", () => {
  it.each(DECODED)("decodes 0x%s", (encoded, value) => {
    expect(decodeCbor(hex(encoded))).toEqual(value);
  });

  it.each(REJECTED)("rejects 0x%s, which is outside the subset", (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(InvalidCborError);
  });
});

describe("CBOR subset", () => {
  it.each<[string, readonly number[]]>([
    ["an indefinite-length map", [0xbf, 0xff]],
    ["a tag", [0xc0, 0x00]],
    ["a float", [0xf9, 0x00, 0x00]],
    ["undefined", [0xf7]],
    ["a duplicate map key", [0xa2, 0x01, 0x00, 0x01, 0x00]],
    ["a map key that is a byte string", [0xa1, 0x41, 0x00, 0x00]],
    ["a truncated byte string", [0x42, 0x00]],
    ["trailing bytes", [0x00, 0x00]],
    ["invalid UTF-8 text", [0x61, 0xff]],
    ["an integer above 2^53 - 1", [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]],
  ])("rejects %s", (_name, bytes) => {
    expect(() => decodeCbor(new Uint8Array(bytes))).toThrow(InvalidCborError);
  });

  it.each([0xe0, 0xf3])("rejects the simple value below 20 encoded as 0x%s", (initial) => {
    expect(() => decodeCbor(new Uint8Array([initial]))).toThrow(InvalidCborError);
  });

  it("bounds the nesting depth", () => {
    expect(() => decodeCbor(new Uint8Array([...new Array<number>(40).fill(0x81), 0x00]))).toThrow(/too deep/);
  });
});
