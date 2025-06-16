import createDebug from "debug";
import { decodeASCIIString, decodeCString } from "./utils.js";
import { findPattern } from "./patterns.js";
import { getVersionFromFFS } from "./xfs.js";
import { sprintf } from "sprintf-js";
import { DateTime } from "luxon";

const BASE = 0xA0000000;

// 000000FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF ??????A0 ??????A0 + 0x18

const PHONE_INFO_TABLE = 0xA008FD04;

const debug = createDebug('ff');
const ADDR_MASK = 0x0FFFFFFF;

type BasicSoftwareInfo = {
	reconfigureTime: DateTime;
	linkTime: DateTime;
	projectName: string;
	svn: number;
	langpack: string;
	model: string;
	vendor: string;
	baselineVersion: string;
};

type FlashLayoutFindConfig = {
	pattern: string;
	structSize: number;
	nameOffset: number;
	tableSizeOffset: number;
	tableAddrOffset: number;
};

export interface FlashPartBlock {
	name: string;
	start: number;
	size: number;
	children: FlashPartBlock[];
}

export interface FlashPartRegion {
	name: string;
	start: number;
	size: number;
}

export interface FirmwareInfo {
	databaseName: string;
	baselineVersion: string;
	baselineRelease: string;
	projectName: string;
	releaseType: string;
	reconfigureTime: string;
	linkTime: string;
	svn: number;
	vendor: string;
	model: string;
	langpack: number;
	tegic: number;
}

export interface FullFlashInfo {
	firmwareInfo: FirmwareInfo;
	bootcoreInfo?: FirmwareInfo;
	imei?: string;
	ffsVersion?: string;
	blocks: FlashPartBlock[];
	regions: FlashPartRegion[];
}

function parseInfoTables(buffer: Buffer): Record<"bootcore" | "firmware", FirmwareInfo> {
	const pattern = "000000FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF ??????A0 ??????A0 + 0x18";
	const found = findPattern(buffer, pattern, { base: 0xA0000000 });
	const fwInfo: Record<string, FirmwareInfo> = {};
	for (const addr of found) {
		const type = addr <= 0xA0020000 ? "bootcore" : "firmware";
		debug(sprintf("Found info pointers: %08X (%s)", addr, type));
		const infoTableAddr = buffer.readUInt32LE(OFFSET(addr + 4));
		debug(sprintf("Found info table: %08X (%s)", infoTableAddr, type));
		fwInfo[type] = parseFwInfoTable(buffer, infoTableAddr);
	}
	return fwInfo;
}

function parseSections(buffer: Buffer) {
	const addresses = [0xA008FD10, 0xA008FE80];
	const addr = addresses.filter((addr) => isPointer(buffer.readUInt32LE(OFFSET(addr))))[0];
	if (!addr)
		return undefined;

	console.log(sprintf("Found sections table: %08X", addr));
	for (let i = addr; i < addr + 0x100; i += 4) {
		const ptr = buffer.readUInt32LE(OFFSET(i));
		if (!isPointer(ptr))
			break;
		console.log(sprintf("  %08X", ptr));
	}

}

export function getFullFlashInfo(buffer: Buffer): FullFlashInfo | undefined {
	parseSections(buffer);
	return undefined;

	const fwInfo = parseInfoTables(buffer);
	const [blocks, regions] = parseFlashLayout(buffer);
	const imei = parseIMEI(buffer);
	console.log(parseBasicSoftwareInfo(buffer));
	return {
		firmwareInfo: fwInfo.firmware,
		bootcoreInfo: fwInfo.bootcore,
		imei,
		ffsVersion: getVersionFromFFS(buffer),
		blocks,
		regions
	};
}

export function parseIMEI(buffer: Buffer) {
	for (const offset of [0x65C, 0x660, 0x3E410]) {
		const imei = buffer.subarray(offset, offset + 14).toString();
		if (imei.match(/^[0-9]{14}$/))
			return imei;
	}
	return undefined;
}

function parseFwInfoTable(buffer: Buffer, addr: number): FirmwareInfo {
	const names: string[] = [
		"databaseName",
		"baselineVersion",
		"baselineRelease",
		"projectName",
		"releaseType",
		"reconfigureTime",
		"linkTime",
		"svn",
		"vendor",
		"model",
		"langpack",
		"tegic",
	];

	const infoTable: Record<string, string> = {};
	for (let i = 0; i < 13; i++) {
		const index = buffer.readUInt32LE(OFFSET(addr + i * 8));
		const ptr = buffer.readUInt32LE(OFFSET(addr + i * 8 + 4));
		infoTable[names[index]] = decodeCString(buffer.subarray(OFFSET(ptr)));
	}

	return {
		databaseName: infoTable.databaseName,
		baselineVersion: infoTable.baselineVersion,
		baselineRelease: infoTable.baselineRelease,
		projectName: infoTable.projectName,
		releaseType: infoTable.releaseType,
		reconfigureTime: infoTable.reconfigureTime,
		linkTime: infoTable.linkTime,
		svn: +infoTable.svn,
		vendor: infoTable.vendor,
		model: infoTable.model,
		langpack: +infoTable.langpack,
		tegic: +infoTable.tegic,
	};
}

function parseBasicSoftwareInfo(buffer: Buffer) {
	const info: Record<string, FirmwareInfo | undefined> = {};

	const parser = (addr: number): FirmwareInfo | undefined => {
		const reconfigureTime = decodeASCIIString(buffer, OFFSET(addr), 16);
		if (!reconfigureTime?.match(/^\d+\.\d+\.\d+:\d+:\d+$/))
			return undefined;

		const extendedInfoTable = buffer.readUInt32LE(OFFSET(addr + 0x104));
		if (!isPointer(extendedInfoTable))
			return undefined;

		const names: string[] = [
			"databaseName",
			"baselineVersion",
			"baselineRelease",
			"projectName",
			"releaseType",
			"reconfigureTime",
			"linkTime",
			"svn",
			"vendor",
			"model",
			"langpack",
			"tegic",
		];

		const infoTable: Record<string, string> = {};
		for (let i = 0; i < 32; i++) {
			const index = buffer.readUInt32LE(OFFSET(extendedInfoTable + i * 8));
			const addr = buffer.readUInt32LE(OFFSET(extendedInfoTable + i * 8 + 4));
			if (index == 0xFFFF)
				break;
			infoTable[names[index]] = decodeCString(buffer.subarray(OFFSET(addr)));
		}

		return {
			databaseName: infoTable.databaseName,
			baselineVersion: infoTable.baselineVersion,
			baselineRelease: infoTable.baselineRelease,
			projectName: infoTable.projectName,
			releaseType: infoTable.releaseType,
			reconfigureTime: infoTable.reconfigureTime,
			linkTime: infoTable.linkTime,
			svn: +infoTable.svn,
			vendor: infoTable.vendor,
			model: infoTable.model,
			langpack: +infoTable.langpack,
			tegic: +infoTable.tegic,
		}
	};

	const parseConfig: Record<string, number[]> = {
		bootcore: [0xA0000C00, 0xA0000800],
		firmware: [0xA008FC00],
	};
	for (const type in parseConfig) {
		for (const addr of parseConfig[type]) {
			info[type] = parser(addr);
			if (info[type])
				break;
		}
	}
	return info;
}

export function parseSectionsTable(buffer: Buffer) {
	const configs = [
		// NSG
		{
			type: "NSG",
			pattern: [
				"?? ?? ?? A0",
				"?? ?? ?? A0",
				"?? ?? ?? A0",
				"?? ?? ?? A0",
				"?? ?? ?? A0",
				"?? ?? ?? A0",
				"?? ?? ?? A?",
				"?? ?? ?? A?",
				"?? ?? ?? A?",
				"?? ?? ?? A?",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
			].join(" ")
		},
		// SG
		{
			type: "SG",
			pattern: [
				"?? ?? ?? A0",
				"?? ?? ?? A0",
				"?? ?? ?? A0",
				"?? ?? ?? A0",
				"?? ?? ?? A?",
				"?? ?? ?? A?",
				"?? ?? ?? A?",
				"?? ?? ?? A?",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
				"FF FF FF FF",
			].join(" "),
			items: [
				"BOOT",
				"FIRMWARE_INFO",
				"MOTSTAMP",
				"BUILD_TIMESTAMP",
				"SECTIONS",
				"CODE",
				"UNKNOWN",
				"LANGPACK",
				"TEGIC",
			]
		},
	];
	for (const config of configs) {
		const offsets = findPattern(buffer, config.pattern, { align: 4 });
		for (const offset of offsets) {
			const result = tryParseFlashLayout(buffer, offset, config);
			if (result)
				return result;
		}
	}
}

export function parseFlashLayout(buffer: Buffer) {
	const configs: FlashLayoutFindConfig[] = [
		// NSG
		{
			pattern: [
				"?? ?? ?? A?", // name ptr
				"?? ?? 00 00",
				"?? ?? 00 00",
				"?? ?? ?? ??",
				"?? ?? ?? ??",
				"?? ?? ?? ??",
				"?? ?? ?? A?",
				"?? ?? 00 00",
				"?? ?? 00 00", // table size
				"?? ?? ?? A?", // table
				"?? ?? ?? ??",
				"?? ?? ?? A?",
				"?? ?? ?? ??",
			].join(" ").repeat(3),
			structSize: 0x34,
			nameOffset: 0x00,
			tableSizeOffset: 0x20,
			tableAddrOffset: 0x24
		},
		// SG
		{
			pattern: [
				"?? ?? ?? A?", // name ptr
				"?? ?? 00 00",
				"?? ?? 00 00",
				"?? ?? ?? A?",
				"?? ?? 00 00",
				"?? ?? 00 00", // table size
				"?? ?? ?? A?", // table ptr
				"?? ?? ?? ??",
				"?? ?? ?? A?",
				"?? ?? ?? A?", // unk func
				"?? ?? ?? ??",
			].join(" ").repeat(3),
			structSize: 0x2C,
			nameOffset: 0x00,
			tableSizeOffset: 0x14,
			tableAddrOffset: 0x18
		}
	];

	for (const config of configs) {
		const offsets = findPattern(buffer, config.pattern, { align: 4 });
		for (const offset of offsets) {
			const result = tryParseFlashLayout(buffer, offset, config);
			if (result)
				return result;
		}
	}

	return [];
}

function tryParseFlashLayout(buffer: Buffer, infoOffset: number, config: FlashLayoutFindConfig): [FlashPartBlock[], FlashPartRegion[]] | undefined {
	let blocks: FlashPartBlock[] = [];
	for (let offset = infoOffset; offset < infoOffset + 64 * config.structSize; offset += config.structSize) {
		const struct = buffer.subarray(offset, offset + config.structSize);
		const nameAddr = struct.readUInt32LE(config.nameOffset);
		const tableSize = struct.readUInt32LE(config.tableSizeOffset);
		const tableAddr = struct.readUInt32LE(config.tableAddrOffset);

		if ((BigInt(nameAddr) & 0xF0000000n) != 0xA0000000n)
			break;
		if ((BigInt(tableAddr) & 0xF0000000n) != 0xA0000000n)
			break;
		const name = decodeASCIIString(buffer.subarray(OFFSET(nameAddr)));
		if (!name)
			break;

		const table = buffer.subarray(OFFSET(tableAddr));
		for (let i = 0; i < tableSize * 8; i += 8) {
			const start = table.readUInt32LE(i);
			const size = table.readUInt32LE(i + 4);

			console.log(sprintf("name: %s, start: %08X, size: %08X, table: %008X", name, start, size, tableAddr + i));

			if (name == "BCORE" && start == 0xA003E000) {
				blocks.push({ name, start: 0xA0000000, size: start + size - 0xA0000000, children: [] });
				blocks.push({ name: "BCORE2", start, size, children: [] });
			} else {
				blocks.push({ name, start, size, children: [] });
			}
		}
	}

	if (!blocks.length)
		return undefined;

	const rsc = findPattern(buffer, "52 45 FF FF FF FF FF FF");
	if (rsc.length) {
		blocks.push({
			name: "RESOURCE",
			start: rsc[0] + 0xA0000000,
			size: 64 * 1024,
			children: []
		});
	}

	const lgp = findPattern(buffer, "BB BB 00 00");
	if (lgp.length) {
		blocks.push({
			name: "LANGPACK",
			start: lgp[0] + 0xA0000000,
			size: 64 * 1024,
			children: []
		});
	}

	blocks = nestBlocks(blocks);

	let unknownBlocks: FlashPartBlock[] = [];
	let prevBlock: FlashPartBlock | undefined;
	for (const block of blocks) {
		if (!prevBlock) {
			if (block.start != 0xA0000000) {
				unknownBlocks.push({
					name: "UNKNOWN",
					start: 0xA0000000,
					size: block.start - 0xA0000000,
					children: []
				});
			}
		} else if (prevBlock.start + prevBlock.size != block.start) {
			const prevBlockEnd = prevBlock.start + prevBlock.size;
			unknownBlocks.push({
				name: "UNKNOWN",
				start: prevBlockEnd,
				size: block.start - prevBlockEnd,
				children: []
			});
		}
		prevBlock = block;
	}

//	unknownBlocks.sort((a, b) => b.size - a.size);
//	unknownBlocks[0].name = "CODE";

	if (unknownBlocks.length > 0) {
		blocks.push(...unknownBlocks);
		blocks.sort((a, b) => a.start - b.start);
	}

	blocks = mergeBlocks(blocks);

	if (hasOverlap(blocks))
		throw new Error("Parsed blocks has overlap, internal error.");

	const regions: FlashPartRegion[] = [];
	for (const block of blocks) {
		const prevBlock = regions.length > 0 ? regions[regions.length - 1] : undefined;
		if (prevBlock && prevBlock.name == block.name && prevBlock.start + prevBlock.size == block.start) {
			prevBlock.size += block.size;
			continue;
		}
		regions.push({
			name: block.name,
			start: block.start,
			size: block.size
		});
	}

	return [blocks, regions];
}

function mergeBlocks(blocks: FlashPartBlock[]): FlashPartBlock[] {
	const merged = [...blocks];
	const used = new Set<FlashPartBlock>();
	const allowedToMergeBlocks = ["RESOURCE", "LANGPACK"];
	for (let i = 1; i < merged.length; i++) {
		const block = merged[i - 1];
		const nextBlock = merged[i];
		if (allowedToMergeBlocks.includes(block.name) && nextBlock.name == "UNKNOWN") {
			block.size += nextBlock.size;
			used.add(nextBlock);
		}
	}
	return merged.filter(b => !used.has(b));
}

function nestBlocks(blocks: FlashPartBlock[]): FlashPartBlock[] {
	const sorted = [...blocks].sort((a, b) => b.size - a.size);
	const used = new Set<FlashPartBlock>();

	for (const parent of sorted) {
		parent.children = [];
		for (const child of sorted) {
			if (child === parent || used.has(child))
				continue;
			if (child.start >= parent.start && child.start + child.size <= parent.start + parent.size) {
				parent.children.push(child);
				used.add(child);
			}
		}
	}

	return sorted.filter(b => !used.has(b)).sort((a, b) => a.start - b.start);
}

function hasOverlap(blocks: FlashPartBlock[] | FlashPartRegion[]): boolean {
	for (let i = 1; i < blocks.length; i++) {
		const prev = blocks[i - 1];
		const curr = blocks[i];
		const prevEnd = prev.start + prev.size;
		const currEnd = curr.start + curr.size;
		if (curr.start < prevEnd && currEnd > prevEnd)
			return true;
	}
	return false;
}

function isPointer(addr: number) {
	return addr >= 0xA0000000 && addr < 0xB0000000;
}

function OFFSET(addr: number) {
	return addr & ADDR_MASK;
}

function parseSwInfoDate(raw: string): DateTime {
	const match = raw.match(/^(\d{2})\.(\d{2})\.(\d{2})(\d{2}):(\d{2}):(\d{2})$/);
	if (!match)
		throw new Error(`Invalid date format: ${raw}`);

	const [ , dd, MM, yy, HH, mm, ss ] = match;
	const str = `${dd}.${MM}.${yy} ${HH}:${mm}:${ss}`;

	const dt = DateTime.fromFormat(str, "dd.MM.yy HH:mm:ss", { zone: "UTC", setZone: true });
	if (!dt.isValid)
		throw new Error(`Invalid date format: ${raw}`);

	return dt;
}
