import { sprintf } from "sprintf-js";
import createDebug from 'debug';
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

const XBI_FILEDS = {
	0x12:	['reconfigureTime', 'str'],
	0x13:	['linkTime', 'str'],
	0x16:	['releaseType', 'str'],
	0x17:	['productCode', 'str'],

	0x1A:	['langpack', 'str'],
	0x1D:	['svn', 'svn'],

	0x23:	['flashSize', 'uint32be'],
	0x28:	['model', 'str'],
	0x29:	['vendor', 'str'],
	0x2A:	['baseline', 'str'],
	0x30:	['eraseRegions[]', 'region'],
	0x37:	['swCode', 'swCode'],
	0x34:	['projectType', 'uint8'],
	0x39:	['compressionType', 'uint8'],
	0x3A:	['compressionInfo', 'buffer'],
	0x40:	['updateType', 'type'],

	0x50:	['mapInfoSize', 'uint16be'],
	0x51:	['mapInfo[]', 'buffer'],

	0x56:	['hashAreaSize', 'uint16le'],

	0x60:	['t9', 'uint8'],
	0x61:	['databaseName', 'str'],
	0x62:	['baselineVersion', 'str'],
	0x63:	['baselineRelease', 'str'],

	0x64:	['mobileName', 'str2'],
	0x70:	['dll', 'str2'],
};

const XBI_FILEDS2 = {
	0x5C:	['dataFlash[]', 'region'],
};

const XBI_TYPES = {
	0:	'MobSw',
	1:	'Eesimu',
	2:	'VoiceMemo',
	3:	'CodeOnly',
	4:	'LangOnly',
	5:	'CodeAndLang',
	6:	'DiffFile',
	7:	'ExtendedNewSplit',
};

export function isXbi(buffer) {
	return detectXbiFormat(buffer) != null;
}

export function parseXbi(buffer, onlyHeader = false) {
	let xbiFormat = detectXbiFormat(buffer);
	if (!xbiFormat)
		return null;

	debug("XBI version: " + xbiFormat.version);
	debug("XBI signed: " + xbiFormat.signed);

	if (xbiFormat.version == 24 && buffer.subarray(buffer.length - SAG_JK_WH.length).equals(SAG_JK_WH)) {
		let size = buffer.readUInt32BE(buffer.length - SAG_JK_WH.length - 4) + SAG_JK_WH.length + 4;
		if (size == buffer.length) {
			buffer = buffer.subarray(0, buffer.length - SAG_JK_WH.length - 4);
			debug("Removing trailing SAG_JK_WH header!");
		}
	}

	let info = {
		signed: xbiFormat.signed,
		valid: true,
		writes: [],
		size: buffer.length
	};

	let offset = xbiFormat.offset;
	while (offset < buffer.length) {
		let [size, frame] = decodeXbiFrame(0xFE, xbiFormat.version, buffer.slice(offset));
		offset += size;

		if (frame.cmd == 0x04) // EOF
			break;

		if (!XBI_FILEDS[frame.cmd]) {
			debug(sprintf("[info] %02X: unknown", frame.cmd), frame.value);
			continue;
		}

		let [key, type] = XBI_FILEDS[frame.cmd];
		if (key.endsWith('[]')) {
			let shortKey = key.substr(0, key.length - 2);
			info[shortKey] = info[shortKey] || [];
			let decodedValue = decodeXbiInfoField(type, xbiFormat.key, frame.value);
			info[shortKey].push(decodedValue);
			debug(sprintf("[info] %02X: %s =", frame.cmd, key), decodedValue);
		} else {
			info[key] = decodeXbiInfoField(type, xbiFormat.key, frame.value);
			debug(sprintf("[info] %02X: %s =", frame.cmd, key), info[key]);
		}
	}

	if (info.hashAreaSize) {
		debug("skip HASH_AREA: +" + info.hashAreaSize);
		offset += info.hashAreaSize;
	}

	while (offset < buffer.length) {
		if (!isXbiFrame(0xFF, xbiFormat.version, buffer.slice(offset)))
			break;

		let [size, frame] = decodeXbiFrame(0xFF, xbiFormat.version, buffer.slice(offset));
		offset += size;

		if (!XBI_FILEDS2[frame.cmd]) {
			debug(sprintf("[info] %02X: unknown", frame.cmd), frame.value);
			continue;
		}

		let [key, type] = XBI_FILEDS2[frame.cmd];
		if (key.endsWith('[]')) {
			let shortKey = key.substr(0, key.length - 2);
			info[shortKey] = info[shortKey] || [];
			let decodedValue = decodeXbiInfoField(type, xbiFormat.key, frame.value);
			info[shortKey].push(decodedValue);
			debug(sprintf("[info] %02X: %s =", frame.cmd, key), decodedValue);
		} else {
			info[key] = decodeXbiInfoField(type, xbiFormat.key, frame.value);
			debug(sprintf("[info] %02X: %s =", frame.cmd, key), info[key]);
		}
	}

	try {
		while (offset < buffer.length) {
			let [size, frame] = decodeXbiWriteFrame(xbiFormat.version, buffer.slice(offset), offset);
			offset += size;
			info.writes.push(frame);
		}
	} catch (e) {
		if (!onlyHeader)
			throw e;
		info.valid = false;
	}

	return info;
}

export function getXbiExtension(xbi) {
	if (xbi.updateType == 'ExtendedNewSplit') {
		return 'xfs';
	} else if (xbi.databaseName == 'klf_bootcore') {
		return 'xbb';
	}
	return xbi.compressionType == 0 ? 'xbi' : 'xbz';
}

export function convertXbiToFlash(buffer, xbi = null) {
	xbi = xbi || parseXbi(buffer);

	let flash = Buffer.alloc(xbi.flashSize);
	flash.fill(0xFF, 0);

	let writeFlash = (addr, buffer) => {
		let localOffset = (addr & ~0xF0000000);
		debug(sprintf("[write] %08X %08X", addr, buffer.length));
		buffer.copy(flash, localOffset);
	};

	if (xbi.compressionType == 3) {
		let decompressor = xbiDecompressor(writeFlash);
		let finished = false;
		for (let w of xbi.writes)
			finished = decompressor(buffer.subarray(w.offset, w.offset + w.size));
		if (!finished)
			throw new Error(`Unexpected EOF.`);
	} else if (xbi.compressionType == 0) {
		for (let w of xbi.writes)
			writeFlash(w.addr, buffer.subarray(w.offset, w.offset + w.size));
	} else {
		throw new Error(`Unknown compression type: ${xbi.compressionType}`);
	}

	return flash;
}

function decodeXbiWriteFrame(version, buffer, offset) {
	if (version == 24) {
		let addr = (buffer.readUInt8(0) << 16) | (buffer.readUInt8(1) << 8) | (buffer.readUInt8(2));
		let size = buffer.readUInt8(3);
		let chk = buffer.readUInt8(4 + size);
		let actualChk = calcChecksum(buffer, 4 + size);

		if (chk != actualChk)
			throw new Error(`Invalid chk: ${sprintf("%08X %04X CHK:%02X != %02X", addr, size, chk, actualChk)} at ${buffer.byteOffset}`);

		return [ 4 + 1 + size, { addr, size, offset: offset + 4 } ];
	} else if (version == 32) {
		let addr = buffer.readUInt32BE(0);
		let size = buffer.readUInt16BE(4);
		let chk = buffer.readUInt8(6 + size);
		let actualChk = calcChecksum(buffer, 6 + size);

		if (chk != actualChk)
			throw new Error(`Invalid chk: ${sprintf("%08X %04X CHK:%02X != %02X", addr, size, chk, actualChk)} at ${buffer.byteOffset}`);

		return [ 6 + 1 + size, { addr, size, offset: offset + 6 } ];
	}
	throw new Error(`Unknown version: ${version}`);
}

function isXbiFrame(frameType, version, buffer) {
	if (version == 24) {
		let type = (buffer.readUInt8(0) << 16) | (buffer.readUInt8(1) << 8) | (buffer.readUInt8(2));
		return type == (0xFFFF00 | frameType);
	} else if (version == 32) {
		let type = buffer.readUInt32BE(0);
		return type == (0xFFFFFF00 | frameType) >>> 0;
	}
	throw new Error(`Unknown version: ${version}`);
}

function decodeXbiFrame(frameType, version, buffer) {
	if (!isXbiFrame(frameType, version, buffer))
		throw new Error(`Invalid ${sprintf("%02X", frameType)} frame!`);

	if (version == 24) {
		let size = buffer.readUInt8(3);
		let cmd = buffer.readUInt8(4);
		let value = buffer.subarray(5, 5 + size - 1);
		let chk = buffer.readUInt8(5 + size - 1);

		if (chk != calcChecksum(buffer, 5 + size - 1))
			throw new Error(`Invalid chk: ${chk}`);

		return [ 5 + size, { size, cmd, value, chk } ];
	} else if (version == 32) {
		let size = buffer.readUInt16BE(4);
		let cmd = buffer.readUInt8(6);
		let value = buffer.subarray(7, 7 + size - 1);
		let chk = buffer.readUInt8(7 + size - 1);

		if (chk != calcChecksum(buffer, 7 + size - 1))
			throw new Error(`Invalid chk: ${chk}`);

		return [ 7 + size, { size, cmd, value, chk } ];
	}
	throw new Error(`Unknown version: ${version}`);
}

function calcChecksum(buffer, size) {
	let chk = 0;
	if (size > buffer.length)
		throw new Error(`Truncated file! [${size} > ${buffer.length}]`);
	for (let i = 0; i < size; i++)
		chk ^= buffer[i];
	return chk;
}

function decodeXbiInfoField(type, key, value) {
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
			return { from: value.readUint32BE(0), to: value.readUint32BE(4) };
		case "swCode":
			return { addr: value.readUint32BE(0), value: value.readUint32BE(4) };
		case "buffer":
			return value;
	}
	throw new Error(`Unknown type: ${type}`);
}

function decryptString(key, value) {
	value = Buffer.from(value);
	for (let i = 0; i < value.length; i++)
		value[i] = value[i] ^ key[i % key.length];
	return value;
}

export function detectXbiFormat(buffer) {
	for (let format of XBI_FORMATS) {
		// Signed
		if (format.signatureID.equals(buffer.subarray(0, format.signatureID.length))) {
			let softwareOffset = buffer.indexOf(format.softwareID);
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
				key: format.key,
				version: format.version
			};
		}
	}
	return null;
}

function xbiDecompressor(onWrite) {
	let state = 0;
	let checksum = 0;
	let blockSize = 0;
	let blockAddr = 0;
	let remainingBytes = 0;
	let tempBuffer = Buffer.alloc(4096);

	let decompressor = lzssDecompressor();

	return (buffer) => {
		let decompressedData = decompressor(buffer);

		for (let i = 0; i < decompressedData.length; i++) {
			let byte = decompressedData[i];

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

		return state == 0;
	};
}

function lzssDecompressor() {
	let decompressedBuffer = Buffer.alloc(4096);
	let circularBuffer = Buffer.alloc(4096);
	let circularBufferPos = 1;
	let copyFrom = 0;
	let state = 0;
	let tempByte = 0;
	let tempByteBitsCnt = 0;

	return (buffer) => {
		let decompressedSize = 0;

		for (let i = 0; i < buffer.length; i++) {
			let byte = buffer[i];
			for (let bitN = 0; bitN < 8; bitN++) {
				let bit = (byte & (1 << (8 - bitN - 1))) != 0 ? 1 : 0;

				switch (state) {
					case 0:
						tempByteBitsCnt = 0;
						tempByte = 0;
						state = bit ? 1 : 2;
					break;

					case 1:
						tempByte = (tempByte << 1) | bit;
						tempByteBitsCnt++;

						if (tempByteBitsCnt == 8) {
							decompressedBuffer[decompressedSize++] = tempByte;
							circularBuffer[circularBufferPos] = tempByte;
							circularBufferPos = (circularBufferPos + 1) & 0xFFF;
							state = 0;
						}
					break;

					case 2:
						tempByte = (tempByte << 1) | bit;
						tempByteBitsCnt++;

						if (tempByteBitsCnt == 12) {
							copyFrom = tempByte;
							tempByte = 0;
							tempByteBitsCnt = 0;
							state = 3;
						}
					break;

					case 3:
						tempByte = (tempByte << 1) | bit;
						tempByteBitsCnt++;

						if (tempByteBitsCnt == 4) {
							for (let j = 0; j <= tempByte + 1; j++) {
								let value = circularBuffer[(copyFrom + j) & 0xFFF];
								decompressedBuffer[decompressedSize++] = value;
								circularBuffer[circularBufferPos] = value;
								circularBufferPos = (circularBufferPos + 1) & 0xFFF;
							}
							state = 0;
						}
					break;

					default:
						throw new Error(`Invalid state.`);
				}
			}
		}
		return decompressedBuffer.subarray(0, decompressedSize);
	};
}
