import createDebug from "debug";
import { decodeASCIIString, decodeCString } from "./utils.js";
import { findPattern } from "./patterns.js";
import { getVersionFromFFS } from "./xfs.js";

const debug = createDebug('ff');

const BLOCK_SIZE = 0x10000;

enum FFSType {
	UNKNOWN,
	SG,
	NSG,
}

export interface FlashPart {
	name: string;
	size: number;
	blocks: FlashPartBlock[];
	regions: FlashPartRegion[];
}

interface FlashPartParsedBlock {
	name: string;
	start: number;
	size: number;
}

export interface FlashPartBlock {
	index: number;
	start: number;
	size: number;
}

export interface FlashPartRegion {
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
	partitions: Record<string, FlashPart>;
}

export function getFullFlashInfo(buffer: Buffer): FullFlashInfo {
	const fwInfo = parseFwInfo(buffer);
	const partitions = parsePartitions(buffer);
	const imei = parseIMEI(buffer);
	return {
		firmwareInfo: fwInfo.firmware,
		bootcoreInfo: fwInfo.bootcore,
		imei,
		ffsVersion: getVersionFromFFS(buffer),
		partitions
	};
}

function parseIMEI(buffer: Buffer) {
	for (const offset of [0x65C, 0x660, 0x3E410]) {
		const imei = buffer.subarray(offset, offset + 14).toString();
		if (imei.match(/^[0-9]{14}$/))
			return imei;
	}
	return undefined;
}

function parseFwInfo(buffer: Buffer): Record<string, FirmwareInfo> {
	const fwInfoTable = findPattern(buffer, "??????A0 0C000000 ??????A0 FFFF0000 00000000", {
		align: 4,
		limit: 2,
	});

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

	const fwInfoList: Record<string, FirmwareInfo> = {};
	for (const offset of fwInfoTable) {
		const tableOffset = offset - 0x5C;
		const infoTable: Record<string, string> = {};
		for (let i = 0; i < 13; i++) {
			const index = buffer.readUInt32LE(tableOffset + i * 8);
			const addr = buffer.readUInt32LE(tableOffset + i * 8 + 4);
			infoTable[names[index]] = decodeCString(buffer.subarray(addr & 0x0FFFFFFF));
		}

		const type = offset < 128 * 1024 ? "bootcore" : "firmware";
		fwInfoList[type] = {
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
	}

	return fwInfoList;
}

function parsePartitions(buffer: Buffer): Record<string, FlashPart> {
	let ffsType: FFSType = FFSType.UNKNOWN;

	const parseNsgBlock = (offset: number): FlashPartParsedBlock | undefined => {
		const hdr = buffer.subarray(offset + BLOCK_SIZE - 32, offset + BLOCK_SIZE);
		const name = decodeASCIIString(hdr.subarray(0, 8));
		const zero = hdr.readUInt16LE(10);
		const magic = hdr.readUInt32LE(12);

		for (let i = 0; i < 4; i++) {
			const ff = hdr.readUInt32LE(16 + i * 4);
			if (ff != 0xFFFFFFFF)
				return undefined;
		}

		if (zero == 0 && magic == 0xFFFFFFF0 && name != null) {
			return {
				name,
				start: offset,
				size: BLOCK_SIZE * 4,
			};
		}
		return undefined;
	};

	const parseSgBlock = (offset: number): FlashPartParsedBlock | undefined => {
		const hdr = buffer.subarray(offset, offset + 16);
		const name = decodeASCIIString(hdr.subarray(0, 8));
		const zero = hdr.readUInt16LE(10);
		const magic = hdr.readUInt32LE(12);
		if (zero == 0 && magic == 0xFFFFFFF0 && name != null) {
			return {
				name,
				start: offset,
				size: BLOCK_SIZE * 2,
			};
		}
		return undefined;
	};

	const blocks: FlashPartParsedBlock[] = [
		{
			name: "BOOTCORE",
			start: 0,
			size: 128 * 1024
		}
	];
	for (let i = 0; i < buffer.length; i += BLOCK_SIZE) {
		if (ffsType == FFSType.UNKNOWN || ffsType == FFSType.NSG) {
			const block = parseNsgBlock(i);
			if (block) {
				blocks.push(block);
				ffsType = FFSType.NSG;
			}
		}

		if (ffsType == FFSType.UNKNOWN || ffsType == FFSType.SG) {
			const block = parseSgBlock(i);
			if (block) {
				blocks.push(block);
				ffsType = FFSType.SG;
			}
		}
	}

	const parts: Record<string, FlashPart> = {};
	for (const block of blocks) {
		if (!parts[block.name]) {
			parts[block.name] = {
				name: block.name,
				size: 0,
				blocks: [],
				regions: []
			};
		}
		parts[block.name].blocks.push({
			index: parts[block.name].blocks.length,
			start: block.start,
			size: block.size
		});
		parts[block.name].size += block.size;
	}

	for (const part of Object.values(parts)) {
		for (const block of part.blocks) {
			if (part.regions.length > 0 && part.regions[part.regions.length - 1].start + part.regions[part.regions.length - 1].size == block.start) {
				part.regions[part.regions.length - 1].size += block.size;
				continue;
			}
			part.regions.push({
				start: block.start,
				size: block.size
			});
		}
	}

	return parts;
}
