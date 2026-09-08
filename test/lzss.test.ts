import { describe, expect, it } from "vitest";
import { lzssDecompressor } from "../src/lzss.js";

type Token =
	| { type: "literal"; value: number }
	| { type: "match"; offset: number; length: number }
	| { type: "end" };

function appendBits(bits: number[], value: number, width: number) {
	for (let bit = width - 1; bit >= 0; bit--)
		bits.push((value >> bit) & 1);
}

function encode(tokens: Token[], paddingBit = 0) {
	const bits: number[] = [];

	for (const token of tokens) {
		switch (token.type) {
			case "literal":
				bits.push(1);
				appendBits(bits, token.value, 8);
			break;

			case "match":
				bits.push(0);
				appendBits(bits, token.offset, 12);
				appendBits(bits, token.length - 2, 4);
			break;

			case "end":
				bits.push(0);
				appendBits(bits, 0, 12);
			break;
		}
	}

	while (bits.length % 8 != 0)
		bits.push(paddingBit);

	const bytes = Buffer.alloc(bits.length / 8);
	for (let i = 0; i < bits.length; i++)
		bytes[i >> 3] |= bits[i] << (7 - (i & 7));
	return bytes;
}

describe("Swupik LZSS decompressor", () => {
	it("decompresses literals", () => {
		const decompress = lzssDecompressor();
		const result = decompress(encode([
			{ type: "literal", value: 0x41 },
			{ type: "literal", value: 0x42 },
			{ type: "end" },
		]));

		expect(result.data).toEqual(Buffer.from("AB"));
		expect(result.finished).toBe(true);
	});

	it("supports overlapping dictionary matches", () => {
		const decompress = lzssDecompressor();
		const result = decompress(encode([
			{ type: "literal", value: 0x41 },
			{ type: "literal", value: 0x42 },
			{ type: "match", offset: 1, length: 4 },
			{ type: "end" },
		]));

		expect(result.data).toEqual(Buffer.from("ABABAB"));
		expect(result.finished).toBe(true);
	});

	it("preserves bit state across input chunks", () => {
		const compressed = encode([
			{ type: "literal", value: 0x41 },
			{ type: "literal", value: 0x42 },
			{ type: "match", offset: 1, length: 6 },
			{ type: "end" },
		]);
		const decompress = lzssDecompressor();
		const output: Buffer[] = [];
		let finished = false;

		for (const byte of compressed) {
			const result = decompress(Buffer.from([byte]));
			output.push(Buffer.from(result.data));
			finished = result.finished;
		}

		expect(Buffer.concat(output)).toEqual(Buffer.from("ABABABAB"));
		expect(finished).toBe(true);
	});

	it("finishes immediately on a zero offset without reading a match length", () => {
		const decompress = lzssDecompressor();
		const result = decompress(encode([{ type: "end" }]));

		expect(result.data).toHaveLength(0);
		expect(result.finished).toBe(true);
	});

	it("rejects non-zero padding bits", () => {
		const decompress = lzssDecompressor();

		expect(() => decompress(encode([{ type: "end" }], 1)))
			.toThrow("Invalid LZSS padding.");
	});

	it("rejects whole bytes after the padding", () => {
		const decompress = lzssDecompressor();
		const compressed = Buffer.concat([
			encode([{ type: "end" }]),
			Buffer.from([0x00]),
		]);

		expect(() => decompress(compressed)).toThrow("Invalid LZSS padding.");
	});

	it("ignores the six zero padding bits used by legacy WinSwup images", () => {
		const decompress = lzssDecompressor();
		const compressed = encode([
			...Array.from(Buffer.from("ABCDE", "ascii"), (value) => ({
				type: "literal" as const,
				value,
			})),
			{ type: "end" },
		]);

		expect(compressed.at(-1)! & 0x3F).toBe(0);
		const result = decompress(compressed);
		expect(result.data).toEqual(Buffer.from("ABCDE"));
		expect(result.finished).toBe(true);
	});

	it("reports an incomplete stream as unfinished", () => {
		const decompress = lzssDecompressor();
		const result = decompress(Buffer.from([0x00]));

		expect(result.data).toHaveLength(0);
		expect(result.finished).toBe(false);
	});

	it("rejects data supplied after the end marker", () => {
		const decompress = lzssDecompressor();
		expect(decompress(encode([{ type: "end" }])).finished).toBe(true);

		expect(() => decompress(Buffer.from([0x00]))).toThrow("Data after LZSS end marker.");
		expect(decompress(Buffer.alloc(0)).finished).toBe(true);
	});
});
