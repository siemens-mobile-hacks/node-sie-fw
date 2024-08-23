import { sprintf } from 'sprintf-js';
import crypto from 'crypto';
import createDebug from 'debug';
const debug = createDebug('fw');

const SAG_UDT = Buffer.from('SAG_UDT');
const SAG_JK_WH = Buffer.from('SAG_JK_WH');

const SERVICE_EXE_VERSIONS = [
	{ name: Buffer.from("Siemens Mobile Phones Software"), version: 1 }, // E-GOLD
	{ name: Buffer.from("Siemens Mobile Phones Signature File"), version: 1 }, // E-GOLD
	{ name: Buffer.from("Siemens Mobile Phones:SOFTWARE:01.00"), version: 2 }, // S-GOLD
	{ name: Buffer.from("Siemens Mobile Phones:SIGNATURE:01.00"), version: 2 }, // S-GOLD
];

export function detectExeType(buffer) {
	if (buffer.slice(buffer.length - SAG_UDT.length).equals(SAG_UDT))
		return "update";
	if (buffer.slice(buffer.length - SAG_JK_WH.length).equals(SAG_JK_WH))
		return "service";
	return null;
}

export function extractFromExe(buffer) {
	switch (detectExeType(buffer)) {
		case "update":
			debug('Detected type: xbi update (SAG_UDT)');
			return extractFromUpdateExe(buffer);

		case "service":
			debug('Detected type: xbi service (SAG_JK_WH)');
			let exeFormatVersion = detectServiceExeVersion(buffer);
			debug(`exeFormatVersion=${exeFormatVersion}`);
			return extractFromServiceExe(buffer, exeFormatVersion);
	}
	debug('Unknown type of EXE!');
	return false;
}

export function extractUpdaterFromExe(buffer) {
	switch (detectExeType(buffer)) {
		case "update":
			debug('Detected type: xbi update (SAG_UDT)');
			return extractFromUpdateExe(buffer, true);

		case "service":
			debug('Detected type: xbi service (SAG_JK_WH)');
			let exeFormatVersion = detectServiceExeVersion(buffer);
			debug(`exeFormatVersion=${exeFormatVersion}`);
			return extractFromServiceExe(buffer, exeFormatVersion, true);
	}
	debug('Unknown type of EXE!');
	return false;
}

function detectServiceExeVersion(buffer) {
	for (let ptr of SERVICE_EXE_VERSIONS) {
		let offset = buffer.length - SAG_JK_WH.length - 5;
		let name = buffer.slice(offset - ptr.name.length, offset);
		if (name.equals(ptr.name))
			return ptr.version;
	}

	// Legacy E-GOLD format
	let size = buffer.readUInt32BE(buffer.length - SAG_JK_WH.length - 4);
	if (size < buffer.length)
		return 0;

	return -1;
}

// From WinSwup
function extractFromServiceExe(buffer, version, extractExe = false) {
	let blocks = [];
	let offset;
	let size;
	let cipherKeyLength;
	let cipherKey;

	if (version == 0) {
		offset = buffer.length - SAG_JK_WH.length - 4;
		size = buffer.readUInt32BE(offset) + SAG_JK_WH.length + 4;
		blocks[0] = { offset: buffer.length - size, size };
	} else {
		let verions = {
			1: { metaOffset: 108 },
			2: { metaOffset: 114 },
		};

		if (!(version in verions)) {
			debug(`Unknown xbi version: ${version}`);
			return false;
		}

		// Block 0
		offset = buffer.length - verions[version].metaOffset;
		size = readBits(buffer.slice(offset));
		blocks[0] = { size, offset: offset - size };

		if (version == 2) {
			// Block 1
			offset = blocks[0].offset - 32;
			size = readBits(buffer.slice(offset));
			blocks[2] = { size, offset: offset - size };

			// Block 2
			offset = blocks[2].offset - 32;
			size = readBits(buffer.slice(offset));
			blocks[1] = { size, offset: offset - size };

			// Block 3
			offset = blocks[1].offset - 32;
			size = readBits(buffer.slice(offset));
			blocks[3] = { size, offset: offset - size };
		}

		cipherKeyLength = Math.min(...blocks.filter((b) => b.size > 0).map((b) => b.offset));
		cipherKey = buffer.subarray(0, cipherKeyLength);
		debug(`cipherKeyLength=${cipherKeyLength}`);
	}

	if (extractExe) {
		let minOffset = Math.min(...blocks.filter((b) => b.size > 0).map((b) => b.offset));
		debug(`Updater exe size: ${minOffset}`);
		return Buffer.from(buffer.subarray(0, minOffset));
	}

	// Extract blocks
	let payloads = [];
	for (let i = 0; i < blocks.length; i++) {
		if (blocks[i].offset < 0 || blocks[i].offset >= buffer.length || blocks[i].offset + blocks[i].size > buffer.length) {
			debug(sprintf("BLOCK %08X %08X is out of range!", blocks[i].offset, blocks[i].size));
			return false;
		}

		if (blocks[i].size) {
			debug(sprintf("BLOCK %08X %08X", blocks[i].offset, blocks[i].size));
			let payload = Buffer.from(buffer.subarray(blocks[i].offset, blocks[i].offset + blocks[i].size));
			if (cipherKey != null)
				applyXor(payload, cipherKey);
			payloads[i] = payload;
		}
	}

	return payloads;
}

function readBits(ptr) {
    let result = 0n;
	for (let i = 0n; i < 32n; i++)
		result += ((ptr[i] & 0x80) ? 1n : 0n) << i;
    return Number(result);
}

function extractFromUpdateExe(buffer, extractExe = false) {
	let aes = findAesKeys(buffer) || findAesKeysV2(buffer);
	if (!aes) {
		debug("Can't find AES KEY & IV in exe!");
		return false;
	}

	let payloadOffset = Number(
		BigInt(buffer.readUInt8(buffer.length - 29)) |
		(BigInt(buffer.readUInt8(buffer.length - 26)) << 24n) |
		(BigInt(buffer.readUInt8(buffer.length - 22)) << 8n) |
		(BigInt(buffer.readUInt8(buffer.length - 17)) << 16n)
	);

	let payloadSize = buffer.length - payloadOffset - 34;
	debug(sprintf("payloadOffset=%08X, size=%d kB", payloadOffset, payloadSize / 1024));

	if (payloadSize < 0) {
		debug("Invalid payload offset.");
		return false;
	}

	let type = buffer.readUInt16BE(payloadOffset);
	debug(sprintf("type=%04X", type));
	payloadOffset += 2;
	payloadSize -= 2;

	if (type != 1) {
		debug(`Invalid type: 0x${type.toString(16)}`);
		return false;
	}

	if (extractExe) {
		debug(`Updater exe size: ${payloadOffset}`);
		return Buffer.from(buffer.subarray(0, payloadOffset));
	}

	let payload = buffer.slice(payloadOffset, payloadOffset + payloadSize);
	let signTime = payload.readUInt32BE(0);
	let signSize = payload.readUInt32BE(4);
	let encryptedSign = payload.slice(8, 8 + signSize);
	let encryptedBody = payload.slice(8 + signSize);

	debug(`signTime=${(new Date(signTime * 1000)).toUTCString()}`);
	debug(`signSize=${signSize}`);
	debug(`encryptedSign=${encryptedSign.toString('hex')}`);
	debug(`encryptedBodySize=${encryptedBody.length}`);

	if (signSize != 128) {
		debug(`Invalid signature size: ${keySize}`);
		return false;
	}

	aes.iv.writeUInt32BE(signTime, 0);

	debug(`AES-128 KEY: ${aes.key.toString('hex')}`);
	debug(`AES-128 IV: ${aes.iv.toString('hex')}`);

	try {
		let decipher = crypto.createDecipheriv('aes-128-cbc', aes.key, aes.iv);
		let decrypted = Buffer.concat([decipher.update(encryptedBody), decipher.final()]);
		debug(`decryptedSize=${decrypted.length}`);
		return [decrypted];
	} catch (e) {
		debug(`AES-128 decryption failed: ${e.message}`);
	}
	return false;
}

function applyXor(buffer, key) {
	let newBuffer = buffer;
	for (let i = 0; i < newBuffer.length; i++)
		newBuffer[i] = newBuffer[i] ^ key[i % key.length];
}

// from Smelter.exe
function findAesKeys(exe) {
	// 68 ?? ?? ?? ?? 68 80 00 00 00 68 ?? ?? ?? ??
	const KEY_PTR = Buffer.from('688000000068', 'hex');

	let lastIndex = 0;
	while (true) {
		let keyIndex = exe.indexOf(KEY_PTR, lastIndex);
		if (keyIndex < 0)
			return false;

		lastIndex = keyIndex + 1;

		let instrOffset1 = keyIndex - 5;
		let instr1 = exe.slice(instrOffset1, instrOffset1 + 5);
		if (instr1[0] != 0x68)
			continue;

		let instrOffset2 = keyIndex + 5;
		let instr2 = exe.slice(instrOffset2, instrOffset2 + 5);
		if (instr2[0] != 0x68)
			continue;

		let iv = instr1.readUInt32LE(1) - 0x400000;
		if (iv + 16 >= exe.length)
			return false;

		let key = instr2.readUInt32LE(1) - 0x400000;
		if (key + 16 >= exe.length)
			return false;

		debug(sprintf(`Found AES-128 IV offset 0x%08X`, iv));
		debug(sprintf(`Found AES-128 KEY offset 0x%08X`, key));

		return {
			key: Buffer.from(exe.slice(key, key + 16)),
			iv: Buffer.from(exe.slice(iv, iv + 16)),
		};
	}
}

function findAesKeysV2(exe) {
	// 68 ?? ?? ?? ?? 2B FA 52 68 ?? ?? ?? ??
	const KEY_PTR = Buffer.from('2BFA5268', 'hex');

	let lastIndex = 0;
	while (true) {
		let keyIndex = exe.indexOf(KEY_PTR, lastIndex);
		if (keyIndex < 0)
			return false;

		lastIndex = keyIndex + 1;

		let instrOffset1 = keyIndex - 5;
		let instr1 = exe.slice(instrOffset1, instrOffset1 + 5);
		if (instr1[0] != 0x68)
			continue;

		let instrOffset2 = keyIndex + 3;
		let instr2 = exe.slice(instrOffset2, instrOffset2 + 5);
		if (instr2[0] != 0x68)
			continue;

		let iv = instr1.readUInt32LE(1) - 0x400000;
		if (iv + 16 >= exe.length)
			return false;

		let key = instr2.readUInt32LE(1) - 0x400000;
		if (key + 16 >= exe.length)
			return false;

		debug(sprintf(`Found AES-128 IV offset 0x%08X`, iv));
		debug(sprintf(`Found AES-128 KEY offset 0x%08X`, key));

		return {
			key: Buffer.from(exe.slice(key, key + 16)),
			iv: Buffer.from(exe.slice(iv, iv + 16)),
		};
	}
}
