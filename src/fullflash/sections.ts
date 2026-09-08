import { isFlashPointer, offsetToAddr } from "./addressSpace.js";
import type { FlashAddrSpace, FlashSectionsTable, InfoTableAnchor } from "./types.js";

const BLOCK_SIZE = 64 * 1024;

export function findSectionsTable(buffer: Buffer, addrSpace: FlashAddrSpace, anchors: InfoTableAnchor[]): FlashSectionsTable | undefined {
	const candidates = new Map<number, FlashSectionsTable>();
	for (const anchor of anchors) {
		const blockStart = anchor.fileOffset - anchor.fileOffset % BLOCK_SIZE;
		const blockEnd = Math.min(blockStart + BLOCK_SIZE, buffer.length);
		const blockAddress = offsetToAddr(addrSpace, blockStart);
		if (blockAddress == null)
			continue;

		for (let offset = blockStart; offset + 4 <= blockEnd;) {
			if (!isFlashPointer(addrSpace, buffer.readUInt32LE(offset))) {
				offset += 4;
				continue;
			}
			const start = offset;
			const pointers: number[] = [];
			while (offset + 4 <= blockEnd && isFlashPointer(addrSpace, buffer.readUInt32LE(offset))) {
				pointers.push(buffer.readUInt32LE(offset));
				offset += 4;
			}
			const metadataPointers = pointers.filter((pointer) => pointer >= blockAddress && pointer < blockAddress + BLOCK_SIZE);
			const sectionBoundaries = pointers.filter((pointer) => pointer >= blockAddress + BLOCK_SIZE && pointer % BLOCK_SIZE == 0);
			if (pointers.length < 5 || metadataPointers.length < 3 || sectionBoundaries.length < 1)
				continue;
			const address = offsetToAddr(addrSpace, start);
			if (address != null) {
				const taggedResource = buffer.readUInt32LE(anchor.fileOffset + 8);
				let resourceAddress: number | undefined;
				if (taggedResource % BLOCK_SIZE == 8 && isFlashPointer(addrSpace, taggedResource - 8))
					resourceAddress = taggedResource - 8;
				candidates.set(start, { address, pointers, resourceAddress });
			}
		}
	}
	return candidates.size == 1 ? [...candidates.values()][0] : undefined;
}
