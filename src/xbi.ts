import { sprintf } from "sprintf-js";
import createDebug from 'debug';
import { inspect } from "node:util";
import { lzssDecompressor } from "./lzss.js";
const debug = createDebug('fw');

const SAG_JK_WH = Buffer.from('SAG_JK_WH');

const XBI_FORMATS = [
	{
		signatureID: Buffer.from("Siemens Mobile Phones:SIGNATURE:01.00"),
		softwareID: Buffer.from("Siemens Mobile Phones:SOFTWARE:01.00"),
		key: Buffer.from("Siemens Mobile Phones:SOFTWARE:01.00\0").reverse(),
		version: 32
	}, {
		signatureID: Buffer.from("Siemens Mobile Phones Signature File"),
		softwareID: Buffer.from("Siemens Mobile Phones Software"),
		key: Buffer.from("Siemens Mobile Phones Software\0").reverse(),
		version: 24
	},
];

type XbiFieldsParser = Record<number, [string,
	"str" | "str2" | "buffer" | "type" | "svn" | "uint32be" | "uint16be" | "uint16le" | "uint8" | "splitInfo" | "region" | "compressionInfo" | "ramSize" | "version"
]>;

export const XBI_CPU_NAMES: Record<number, string> = {
	0:		"HighGold Vxx ... V3.6",
	1:		"HighGold V4 C7-Technology",
	2:		"HighGold V4 C9-Technology",
	3:		"EGOLD V1 ... 1.2",
	4:		"EGOLD V2",
	5:		"EGOLD Plus V1.2", // U35
	6:		"EGOLD Plus V3", // from S45 till 55 generation
	7:		"SGold-Lite", // 65 generation
	8:		"SGold",
	0x80:	"TI Hercules-Chipset"
};

export const XBI_DATA_FORMAT = {
	0:		"bin",
	1:		"len-chk",
	2:		"raw",
	3:		"compressed"
};

const XBI_FILEDS: XbiFieldsParser = {
	0x11:	['minWinswupVersion', 'version'],

	0x12:	['reconfigureTime', 'str'],
	0x13:	['linkTime', 'str'],
	0x16:	['releaseType', 'str'],
	0x17:	['productCode', 'str'],

	0x1A:	['langpack', 'str'],
	0x1D:	['svn', 'svn'],

	0x23:	['flashSize', 'uint32be'],
	0x24:	['ertecSum', 'uint16be'],
	0x25:	['statisticAddr', 'uint32be'],
	0x28:	['model', 'str'],
	0x29:	['vendor', 'str'],
	0x2A:	['baseline', 'str'],
	0x30:	['eraseRegions[]', 'region'],
	0x31:	['asicType', 'uint8'],
	0x32:	['flashWriteType', 'uint8'],
	0x33:	['ramSize', 'ramSize'],
	0x37:	['splitInfo', 'splitInfo'],
	0x34:	['cpuType', 'uint8'],
	0x35:	['ignitionType', 'uint8'],
	0x38:	['align', 'uint16be'],
	0x39:	['compressionType', 'uint8'],
	0x3A:	['compressionInfo', 'compressionInfo'],
	0x40:	['updateType', 'type'],

	0x50:	['mapInfoSize', 'uint16be'],
	0x51:	['mapInfo[]', 'buffer'],

	0x56:	['hashAreaSize', 'uint16le'],

	0x60:	['t9', 'uint8'],
	0x61:	['databaseName', 'str'],
	0x62:	['baselineVersion', 'str'],
	0x63:	['baselineRelease', 'str'],

	0x64:	['operatorProductName', 'str2'],
	0x70:	['dll', 'str2'],
};

const XBI_FILEDS2: XbiFieldsParser = {
	0x5C:	['dataFlash[]', 'region'],
};

const XBI_TYPES: Record<number, string> = {
	0:	'MobSw',			// Mobile-SW
	1:	'Eesimu',			// Data for EEPROM-Simulation in Flash (old!)
	2:	'VoiceMemo',
	3:	'CodeOnly',
	4:	'LangOnly',
	5:	'CodeAndLang',
	6:	'DiffFile',			// Incremental Mobile-SW (only for development)
	7:	'ExtendedNewSplit',	// Extended Split-SW
};

type XbiCompressionInfo = {
	algorithm:	number;
	compressionRatio: number;
	additionalInfo: number[];
	fromFormat: number;
	toFormat: number;
};

export type XbiFrame = {
	size: number;
	cmd: number;
	value: Buffer;
	chk: number;
};

export type XbiDataChunk = {
	addr: number;
	size: number;
	offset: number;
};

export type XbiWriteBlock = {
	addr: number;
	size: number;
	data: Buffer;
};

export type XbiFormat = {
	signed: boolean;
	offset: number;
	signatureSize: number;
	key: Buffer;
	version: number;
};

export type XbiSplitInfo = {
	addr: number;
	id: number;
};

export type XbiInfoMemoryRegion = {
	from: number;
	to: number;
};

export type XbiInfo = {
	signed: boolean;
	valid: boolean;
	unknown: Record<number, Buffer>;
	dataChunks: XbiDataChunk[];
	size: number;
	compressionType: number;
	compressionInfo?: Buffer;
	reconfigureTime?: string;
	linkTime?: string;
	releaseType?: string;
	productCode?: string;
	langpack?: string;
	svn?: number;
	flashSize?: number;
	model?: string;
	vendor?: string;
	baseline?: string;
	splitInfo?: XbiSplitInfo;
	cpuType?: number;
	cpuTypeName?: string;
	updateType?: string;
	mapInfoSize?: number;
	mapInfo?: Buffer[];
	hashAreaSize?: number;
	hashArea?: Buffer;
	t9?: number;
	databaseName?: string;
	baselineVersion?: string;
	baselineRelease?: string;
	operatorProductName?: string;
	dll?: string;
	eraseRegions?: XbiInfoMemoryRegion[];
	dataFlash?: XbiInfoMemoryRegion[];
	hwid?: number;
	align?: number;
	ertecSum?: number;
	statisticAddr?: number;
	minWinswupVersion?: number;
	asicType?: number;
	flashWriteType?: number;
	ramSize?: number;
	ignitionType?: number;
};

export function isXbi(buffer: Buffer) {
	return detectXbiFormat(buffer) != null;
}

export function parseXbi(buffer: Buffer, onlyHeader: boolean = false): XbiInfo | undefined {
	const xbiFormat = detectXbiFormat(buffer);
	if (!xbiFormat)
		return undefined;

	debug("XBI version: " + xbiFormat.version);
	debug("XBI signed: " + xbiFormat.signed);

	if (xbiFormat.version == 24 && buffer.subarray(buffer.length - SAG_JK_WH.length).equals(SAG_JK_WH)) {
		const size = buffer.readUInt32BE(buffer.length - SAG_JK_WH.length - 4) + SAG_JK_WH.length + 4;
		if (size == buffer.length) {
			buffer = buffer.subarray(0, buffer.length - SAG_JK_WH.length - 4);
			debug("Removing trailing SAG_JK_WH header!");
		}
	}

	const dataChunks: XbiDataChunk[] = [];
	const info: XbiInfo = {
		signed: xbiFormat.signed,
		valid: true,
		unknown: {},
		dataChunks,
		size: buffer.length,
		compressionType: 0,
	};

	const postprocessor = (key: string, frame: XbiFrame) => {
		switch (key) {
			case "cpuType":
				if (info.cpuType != null && XBI_CPU_NAMES[info.cpuType]) {
					info.cpuTypeName = XBI_CPU_NAMES[info.cpuType];
					debug(sprintf("[info] %02X: cpuTypeName = %s", frame.cmd, info.cpuTypeName));
				}
			break;

			case "mapInfo[]":
				if (info.mapInfo != null) {
					info.hwid = info.mapInfo[0].readUInt16LE(2);
					debug(sprintf("[info] %02X: HWID = %d", frame.cmd, info.hwid));
				}
			break;
		}
	};

	const printValue = (value: any) => inspect(value, { breakLength: Infinity });

	let offset = xbiFormat.offset;
	while (offset < buffer.length) {
		const [size, frame] = decodeXbiFrame(0xFE, xbiFormat.version, buffer.subarray(offset));
		offset += size;

		if (frame.cmd == 0x04) // EOF
			break;

		if (!XBI_FILEDS[frame.cmd]) {
			info.unknown[frame.cmd] = frame.value;
			debug(sprintf("[info] %02X: unknown", frame.cmd), frame.value);
			continue;
		}

		const infoRef = info as Record<string, any>;
		const [key, type] = XBI_FILEDS[frame.cmd];
		if (key.endsWith('[]')) {
			const shortKey = key.substring(0, key.length - 2);
			infoRef[shortKey] = infoRef[shortKey] || [];
			const decodedValue = decodeXbiInfoField(type, xbiFormat.key, frame.value);
			infoRef[shortKey].push(decodedValue);
			debug(sprintf("[info] %02X: %s =", frame.cmd, key), printValue(decodedValue));
		} else {
			infoRef[key] = decodeXbiInfoField(type, xbiFormat.key, frame.value);
			debug(sprintf("[info] %02X: %s =", frame.cmd, key), printValue(infoRef[key]));
		}

		postprocessor(key, frame);
	}

	if (info.hashAreaSize) {
		info.hashArea = buffer.subarray(offset, offset + info.hashAreaSize);
		debug("HASH_AREA: +" + info.hashAreaSize);
		offset += info.hashAreaSize;
	}

	while (offset < buffer.length) {
		if (!isXbiFrame(0xFF, xbiFormat.version, buffer.subarray(offset)))
			break;

		const [size, frame] = decodeXbiFrame(0xFF, xbiFormat.version, buffer.subarray(offset));
		offset += size;

		if (!XBI_FILEDS2[frame.cmd]) {
			info.unknown[frame.cmd] = frame.value;
			debug(sprintf("[info] %02X: unknown", frame.cmd), frame.value);
			continue;
		}

		const infoRef = info as Record<string, any>;
		const [key, type] = XBI_FILEDS2[frame.cmd];
		if (key.endsWith('[]')) {
			const shortKey = key.substring(0, key.length - 2);
			infoRef[shortKey] = infoRef[shortKey] || [];
			const decodedValue = decodeXbiInfoField(type, xbiFormat.key, frame.value);
			infoRef[shortKey].push(decodedValue);
			debug(sprintf("[info] %02X: %s =", frame.cmd, key), printValue(decodedValue));
		} else {
			infoRef[key] = decodeXbiInfoField(type, xbiFormat.key, frame.value);
			debug(sprintf("[info] %02X: %s =", frame.cmd, key), printValue(infoRef[key]));
		}

		postprocessor(key, frame);
	}

	try {
		while (offset < buffer.length) {
			const [size, frame] = decodeXbiWriteFrame(xbiFormat.version, buffer.subarray(offset), offset);
			offset += size;
			info.dataChunks.push(frame);
		}
	} catch (e) {
		if (!onlyHeader)
			throw e;
		info.valid = false;
	}

	return info;
}

export function getXbiExtension(xbi: XbiInfo) {
	if (xbi.updateType == 'ExtendedNewSplit') {
		return 'xfs';
	} else if (xbi.updateType == 'CodeOnly') {
		return 'xci';
	} else if (xbi.databaseName == 'klf_bootcore') {
		return 'xbb';
	}
	return xbi.compressionType == 0 ? 'xbi' : 'xbz';
}

export function convertXbiToFlash(buffer: Buffer, parsedXbi: XbiInfo | undefined = undefined) {
	const xbi = parsedXbi ?? parseXbi(buffer);
	if (!xbi)
		throw new Error(`XBI is not parsed!`);

	if (!xbi.flashSize)
		throw new Error(`No flash size in XbiInfo!`);

	const flash = Buffer.alloc(xbi.flashSize);
	flash.fill(0xFF, 0);

	const writeFlash = (addr: number, buffer: Buffer) => {
		const localOffset = (addr & ~0xF0000000);
		debug(sprintf("[write] %08X %08X", addr, buffer.length));
		buffer.copy(flash, localOffset);
	};

	processXbiWriteBlocks(buffer, xbi, writeFlash);

	return flash;
}

export function getXbiWriteBlocks(buffer: Buffer, parsedXbi: XbiInfo | undefined = undefined): XbiWriteBlock[] {
	const xbi = parsedXbi ?? parseXbi(buffer);
	if (!xbi)
		throw new Error(`XBI is not parsed!`);

	const writes: XbiWriteBlock[] = [];
	processXbiWriteBlocks(buffer, xbi, (addr, data) => {
		const dataCopy = Buffer.from(data);
		writes.push({ addr, size: dataCopy.length, data: dataCopy });
	});
	return writes;
}

function processXbiWriteBlocks(buffer: Buffer, xbi: XbiInfo, onWrite: (addr: number, data: Buffer) => void) {
	if (xbi.compressionType == 3) {
		const decompressor = xbiDecompressor(onWrite);
		let finished = false;
		for (const chunk of xbi.dataChunks)
			finished = decompressor(buffer.subarray(chunk.offset, chunk.offset + chunk.size));
		if (!finished)
			throw new Error(`Unexpected EOF.`);
	} else if (xbi.compressionType == 0) {
		for (const chunk of xbi.dataChunks)
			onWrite(chunk.addr, buffer.subarray(chunk.offset, chunk.offset + chunk.size));
	} else {
		throw new Error(`Unknown compression type: ${xbi.compressionType}`);
	}
}

function decodeXbiWriteFrame(version: number, buffer: Buffer, offset: number): [number, XbiDataChunk] {
	if (version == 24) {
		const addr = (buffer.readUInt8(0) << 16) | (buffer.readUInt8(1) << 8) | (buffer.readUInt8(2));
		const size = buffer.readUInt8(3);
		const chk = buffer.readUInt8(4 + size);
		const actualChk = calcChecksum(buffer, 4 + size);

		if (chk != actualChk)
			throw new Error(`Invalid chk: ${sprintf("%08X %04X CHK:%02X != %02X", addr, size, chk, actualChk)} at ${buffer.byteOffset}`);

		return [ 4 + 1 + size, { addr, size, offset: offset + 4 } ];
	} else if (version == 32) {
		const addr = buffer.readUInt32BE(0);
		const size = buffer.readUInt16BE(4);
		const chk = buffer.readUInt8(6 + size);
		const actualChk = calcChecksum(buffer, 6 + size);

		if (chk != actualChk)
			throw new Error(`Invalid chk: ${sprintf("%08X %04X CHK:%02X != %02X", addr, size, chk, actualChk)} at ${buffer.byteOffset}`);

		return [ 6 + 1 + size, { addr, size, offset: offset + 6 } ];
	}
	throw new Error(`Unknown version: ${version}`);
}

function isXbiFrame(frameType: number, version: number, buffer: Buffer): boolean {
	if (version == 24) {
		const type = (buffer.readUInt8(0) << 16) | (buffer.readUInt8(1) << 8) | (buffer.readUInt8(2));
		return type == (0xFFFF00 | frameType);
	} else if (version == 32) {
		const type = buffer.readUInt32BE(0);
		return type == (0xFFFFFF00 | frameType) >>> 0;
	}
	throw new Error(`Unknown version: ${version}`);
}

function decodeXbiFrame(frameType: number, version: number, buffer: Buffer): [number, XbiFrame] {
	if (!isXbiFrame(frameType, version, buffer))
		throw new Error(`Invalid ${sprintf("%02X", frameType)} frame!`);

	if (version == 24) {
		const size = buffer.readUInt8(3);
		const cmd = buffer.readUInt8(4);
		const value = buffer.subarray(5, 5 + size - 1);
		const chk = buffer.readUInt8(5 + size - 1);

		if (chk != calcChecksum(buffer, 5 + size - 1))
			throw new Error(`Invalid chk: ${chk}`);

		return [ 5 + size, { size, cmd, value, chk } ];
	} else if (version == 32) {
		const size = buffer.readUInt16BE(4);
		const cmd = buffer.readUInt8(6);
		const value = buffer.subarray(7, 7 + size - 1);
		const chk = buffer.readUInt8(7 + size - 1);

		if (chk != calcChecksum(buffer, 7 + size - 1))
			throw new Error(`Invalid chk: ${chk}`);

		return [ 7 + size, { size, cmd, value, chk } ];
	}
	throw new Error(`Unknown version: ${version}`);
}

function calcChecksum(buffer: Buffer, size: number) {
	let chk = 0;
	if (size > buffer.length)
		throw new Error(`Truncated file! [${size} > ${buffer.length}]`);
	for (let i = 0; i < size; i++)
		chk ^= buffer[i];
	return chk;
}

function decodeXbiInfoField(type: string, key: Buffer, value: Buffer): any {
	switch (type) {
		case "str":
			return decryptString(key, value).toString();
		case "str2":
			return value.toString();
		case "uint8":
			return value.readUint8(0);
		case "uint16le":
			return value.readUint16LE(0);
		case "uint16be":
			return value.readUint16BE(0);
		case "uint32le":
			return value.readUint32LE(0);
		case "uint32be":
			return value.readUint32BE(0);
		case "svn":
			return parseInt(value.readUint16LE(0).toString(16).padStart(4, '0').toUpperCase()) / 100;
		case "type":
			return XBI_TYPES[value.readUint8(0)] || `unknown_${value.readUint8(0)}`;
		case "region":
			return { from: value.readUint32BE(0), to: value.readUint32BE(4) } as XbiInfoMemoryRegion;
		case "splitInfo":
			return { addr: value.readUint32BE(0), id: value.readUint32BE(4) } as XbiSplitInfo;
		case "buffer":
			return value;
		case "ramSize":
			return value.readUint16BE(0) * 1024;
		case "compressionInfo":
			return {
				algorithm:			value.readUint16BE(0),
				compressionRatio:	value.readUint16BE(2),
				fromFormat:			value.readUint8(4),
				toFormat:			value.readUint8(5),
				additionalInfo:		[
					value.readUint16BE(6),
					value.readUint16BE(8),
					value.readUint16BE(10),
				]
			} as XbiCompressionInfo;
		case "version":
			return value[1] + value[0] * 100;
	}

	throw new Error(`Unknown type: ${type}`);
}

function decryptString(key: Buffer, value: Buffer) {
	value = Buffer.from(value);
	for (let i = 0; i < value.length; i++)
		value[i] = value[i] ^ key[i % key.length];
	return value;
}

export function detectXbiFormat(buffer: Buffer): XbiFormat | undefined {
	for (const format of XBI_FORMATS) {
		// Signed
		if (format.signatureID.equals(buffer.subarray(0, format.signatureID.length))) {
			const softwareOffset = buffer.indexOf(format.softwareID);
			if (softwareOffset < 0)
				continue;
			return {
				signed: true,
				offset: softwareOffset + format.softwareID.length + 1,
				signatureSize: softwareOffset,
				key: format.key,
				version: format.version
			};
		}

		// Unsigned
		if (format.softwareID.equals(buffer.subarray(0, format.softwareID.length))) {
			return {
				signed: false,
				offset: format.softwareID.length + 1,
				signatureSize: 0,
				key: format.key,
				version: format.version
			};
		}
	}
	return undefined;
}

function xbiDecompressor(onWrite: (addr: number, block: Buffer) => void) {
	let state = 0;
	let checksum = 0;
	let blockSize = 0;
	let blockAddr = 0;
	let remainingBytes = 0;
	const tempBuffer = Buffer.alloc(4096);

	const decompressor = lzssDecompressor();

	return (buffer: Buffer) => {
		const { data: decompressedData, finished } = decompressor(buffer);

		for (let i = 0; i < decompressedData.length; i++) {
			const byte = decompressedData[i];

			checksum = checksum ^ byte;

			switch (state) {
				case 0:
					checksum = byte;

					if ((byte & 0x80) == 0) { // data frame
						state = 7;
						blockSize = 0;
						remainingBytes = byte & 0x7F;

						if (remainingBytes == 0)
							throw new Error(`Invalid chunk size (${remainingBytes})!`);
					} else { // address frame
						state = 1;
					}
				break;

				// Parse address frame
				case 1:
					if (byte != 0xFF)
						throw new Error(`Invalid address frame.`);
					state = 2;
				break;

				case 2:
					blockAddr = byte;
					state = 3;
				break;

				case 3:
				case 4:
				case 5:
					blockAddr = ((blockAddr << 8) >>> 0) + byte;
					state++;
				break;

				case 6:
					if (checksum != 0)
						throw new Error(`Invalid address frame checksum.`);
					state = 0;
				break;

				// Parse data frame
				case 7:
					tempBuffer[blockSize++] = byte;

					if (blockSize >= 1024)
						throw new Error(`Chunk is bigger than 1023 bytes.`);

					remainingBytes--;

					if (remainingBytes == 0)
						state = 8;
				break;

				case 8:
					if (checksum != 0)
						throw new Error(`Invalid data frame checksum.`);

					onWrite(blockAddr, tempBuffer.subarray(0, blockSize));

					blockAddr += blockSize;
					state = 0;
				break;

				default:
					throw new Error(`Invalid state.`);
			}
		}

		return finished && state == 0;
	};
}
