import { sprintf } from "sprintf-js";
import createDebug from 'debug';
const debug = createDebug('fw');

type SwupikBlock = {
	addr: number;
	size: number;
	data: Buffer;
};

export function extractSwupFromFullflash(buffer: Buffer, addr: number) {
	const offset = addr & ~0xF0000000;

	const swupAddr = buffer.readUInt32LE(offset);
	const blocksCnt = buffer.readUInt32LE(offset + 8);

	debug(sprintf("SWUP %08X (%d blocks)", swupAddr, blocksCnt));

	const blocks = [];
	let swupOffset = swupAddr & ~0xF0000000;
	for (let i = 0; i < blocksCnt; i++) {
		const [blockSize, block] = decodeBlock(buffer, swupOffset);
		swupOffset += blockSize;
		blocks.push(block);
	}

	let prevBlock: SwupikBlock | undefined;
	const newBlocks: SwupikBlock[] = [];
	for (const block of blocks) {
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
	if (prevBlock)
		newBlocks.push(prevBlock);

	for (const block of newBlocks) {
		debug(sprintf("  BLK %08X %08X", block.addr, block.size));
	}

	return newBlocks;
}

function decodeBlock(buffer: Buffer, offset: number): [number, SwupikBlock] {
	const addr = buffer.readUInt32BE(offset);
	const size = buffer.readUInt16BE(offset + 4);
	const data = buffer.subarray(offset + 6, offset + 6 + size);
	return [size + 7, { addr, size, data }];
}
