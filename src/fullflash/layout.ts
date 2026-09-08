import { findPattern } from "../patterns.js";
import { decodeASCIIString } from "../utils.js";
import {
	addrSpaceKey,
	containsAddrRange,
	deriveAddrSpaceCandidates,
	directAddrToOffset,
	isFlashAddr,
} from "./addressSpace.js";
import type { FlashAddrSpace, FlashLayoutAnalysis, FlashPartBlock, FlashPlatform } from "./types.js";

type LayoutFormat = {
	platform: FlashPlatform;
	pattern: string;
	structSize: number;
	nameOffset: number;
	tableSizeOffset: number;
	tableAddressOffset: number;
};

const NSG_STRUCT = [
	"?? ?? ?? A?", "?? ?? 00 00", "?? ?? 00 00", "?? ?? ?? ??", "?? ?? ?? ??", "?? ?? ?? ??",
	"?? ?? ?? A?", "?? ?? 00 00", "?? ?? 00 00", "?? ?? ?? A?", "?? ?? ?? ??", "?? ?? ?? A?", "?? ?? ?? ??",
].join(" ");
const SG_STRUCT = [
	"?? ?? ?? A?", "?? ?? 00 00", "?? ?? 00 00", "?? ?? ?? A?", "?? ?? 00 00", "?? ?? 00 00",
	"?? ?? ?? A?", "?? ?? ?? ??", "?? ?? ?? A?", "?? ?? ?? A?", "?? ?? ?? ??",
].join(" ");
const FORMATS: LayoutFormat[] = [
	{
		platform: "NSG",
		pattern: [NSG_STRUCT, NSG_STRUCT, NSG_STRUCT].join(" "),
		structSize: 0x34,
		nameOffset: 0,
		tableSizeOffset: 0x20,
		tableAddressOffset: 0x24,
	},
	{
		platform: "SG",
		pattern: [SG_STRUCT, SG_STRUCT, SG_STRUCT].join(" "),
		structSize: 0x2C,
		nameOffset: 0,
		tableSizeOffset: 0x14,
		tableAddressOffset: 0x18,
	},
];

export function analyzeFlashLayout(buffer: Buffer): FlashLayoutAnalysis | undefined {
	const candidates = new Map<string, FlashLayoutAnalysis>();
	for (const format of FORMATS) {
		for (const offset of findPattern(buffer, format.pattern, { align: 4 })) {
			const loose = parseLooseLayout(buffer, offset, format);
			if (!loose)
				continue;
			for (const addressRanges of deriveAddrSpaceCandidates(buffer.length, loose)) {
				const flatBlocks = validateLayout(loose, addressRanges);
				if (!flatBlocks)
					continue;
				const candidate: FlashLayoutAnalysis = {
					platform: format.platform,
					addressRanges,
					flatBlocks,
					blocks: nestBlocks(flatBlocks),
				};
				const blocksKey = flatBlocks.map((block) => `${block.name}:${block.start}:${block.size}`).join("|");
				candidates.set(`${format.platform}:${addrSpaceKey(addressRanges)}:${blocksKey}`, candidate);
			}
		}
	}
	const sorted = [...candidates.values()].sort((a, b) => b.flatBlocks.length - a.flatBlocks.length);
	if (!sorted[0] || (sorted[1] && sorted[1].flatBlocks.length == sorted[0].flatBlocks.length))
		return undefined;
	return sorted[0];
}

function parseLooseLayout(buffer: Buffer, infoOffset: number, format: LayoutFormat): FlashPartBlock[] | undefined {
	const blocks: FlashPartBlock[] = [];
	for (let offset = infoOffset; offset + format.structSize <= buffer.length; offset += format.structSize) {
		const item = buffer.subarray(offset, offset + format.structSize);
		const nameOffset = directAddrToOffset(item.readUInt32LE(format.nameOffset), buffer.length);
		const tableSize = item.readUInt32LE(format.tableSizeOffset);
		const tableOffset = directAddrToOffset(item.readUInt32LE(format.tableAddressOffset), buffer.length);
		if (nameOffset == null || tableOffset == null || tableSize < 1 || tableSize > 4096 || tableOffset + tableSize * 8 > buffer.length)
			break;
		const name = decodeASCIIString(buffer.subarray(nameOffset));
		if (!name?.match(/^[A-Z0-9_]{1,24}$/))
			break;
		for (let index = 0; index < tableSize; index++) {
			const start = buffer.readUInt32LE(tableOffset + index * 8);
			const size = buffer.readUInt32LE(tableOffset + index * 8 + 4);
			if (!isFlashAddr(start) || size < 1 || start + size > 0x100000000)
				return undefined;
			blocks.push({ name, start, size, children: [] });
		}
	}
	return blocks.length >= 3 ? blocks : undefined;
}

function validateLayout(source: FlashPartBlock[], addrSpace: FlashAddrSpace): FlashPartBlock[] | undefined {
	const blocks = source.map((block) => ({ ...block, children: [] as FlashPartBlock[] }));
	if (blocks.some((block) => !containsAddrRange(addrSpace, block.start, block.size)))
		return undefined;
	for (const block of blocks.filter((item) => item.name == "BCORE")) {
		const range = addrSpace.find((item) => block.start >= item.start && block.start < item.start + item.size);
		if (range) {
			const end = block.start + block.size;
			block.start = range.start;
			block.size = end - range.start;
		}
	}
	return blocks;
}

function nestBlocks(blocks: FlashPartBlock[]): FlashPartBlock[] {
	const sorted = [...blocks].sort((a, b) => a.size - b.size || a.start - b.start);
	const roots: FlashPartBlock[] = [];
	for (const block of sorted)
		block.children = [];
	for (const block of sorted) {
		const parent = sorted
			.filter((item) => item !== block && item.start <= block.start && item.start + item.size >= block.start + block.size)
			.sort((a, b) => a.size - b.size)[0];
		if (parent) {
			parent.children.push(block);
		} else {
			roots.push(block);
		}
	}
	return roots.sort((a, b) => a.start - b.start);
}
