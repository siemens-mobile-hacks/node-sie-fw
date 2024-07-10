import { sprintf } from "sprintf-js";
import createDebug from 'debug';
const debug = createDebug('fw');

export function extractSwupFromFullflash(buffer, addr) {
	let offset = addr & ~0xF0000000;

	let swupAddr = buffer.readUInt32LE(offset);
	let blocksCnt = buffer.readUInt32LE(offset + 8);

	debug(sprintf("SWUP %08X (%d blocks)", swupAddr, blocksCnt));

	let swupOffset = swupAddr & ~0xF0000000;
	let blocks = [];
	for (let i = 0; i < blocksCnt; i++) {
		let [blockSize, block] = decodeBlock(buffer, swupOffset);
		swupOffset += blockSize;
		blocks.push(block);
	}

	let prevBlock;
	let newBlocks = [];
	for (let block of blocks) {
		if (!prevBlock) {
			prevBlock = block;
		} else if (prevBlock.addr + prevBlock.size == block.addr) {
			prevBlock.data = Buffer.concat([prevBlock.data, block.data]);
			prevBlock.size += block.size;
		} else {
			newBlocks.push(prevBlock);
			prevBlock = block;
		}
	}
	newBlocks.push(prevBlock);

	for (let block of newBlocks) {
		debug(sprintf("  BLK %08X %08X", block.addr, block.size));
	}

	return newBlocks;
}

function decodeBlock(buffer, offset) {
	let addr = buffer.readUInt32BE(offset);
	let size = buffer.readUInt16BE(offset + 4);
	let data = buffer.subarray(offset + 6, offset + 6 + size);
	return [size + 7, { addr, size, data }];
}
