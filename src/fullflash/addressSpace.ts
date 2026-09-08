import type { FlashAddrSpace, FlashPartBlock } from "./types.js";

export const FLASH_SEGMENT_START = 0xA0000000;
export const FLASH_SEGMENT_END = 0xB0000000;

export function isFlashAddr(address: number): boolean {
	return address >= FLASH_SEGMENT_START && address < FLASH_SEGMENT_END;
}

export function linearAddrSpace(size: number): FlashAddrSpace {
	return [{ start: FLASH_SEGMENT_START, size, fileOffset: 0 }];
}

export function addrToOffset(addrSpace: FlashAddrSpace, address: number): number | undefined {
	for (const range of addrSpace) {
		if (address >= range.start && address < range.start + range.size)
			return range.fileOffset + address - range.start;
	}
	return undefined;
}

export function offsetToAddr(addrSpace: FlashAddrSpace, offset: number): number | undefined {
	for (const range of addrSpace) {
		if (offset >= range.fileOffset && offset < range.fileOffset + range.size)
			return range.start + offset - range.fileOffset;
	}
	const last = addrSpace.at(-1);
	return last && offset == last.fileOffset + last.size ? last.start + last.size : undefined;
}

export function containsAddrRange(addrSpace: FlashAddrSpace, start: number, size = 1): boolean {
	if (size < 1)
		return false;
	const first = addrToOffset(addrSpace, start);
	const last = addrToOffset(addrSpace, start + size - 1);
	return first != null && last == first + size - 1;
}

export function isFlashPointer(addrSpace: FlashAddrSpace, address: number): boolean {
	return isFlashAddr(address) && addrToOffset(addrSpace, address) != null;
}

export function directAddrToOffset(address: number, size: number): number | undefined {
	if (!isFlashAddr(address))
		return undefined;
	const offset = address - FLASH_SEGMENT_START;
	return offset < size ? offset : undefined;
}

export function addrSpaceKey(addrSpace: FlashAddrSpace): string {
	return addrSpace.map((range) => `${range.start}:${range.size}:${range.fileOffset}`).join("|");
}

export function deriveAddrSpaceCandidates(size: number, blocks: FlashPartBlock[]): FlashAddrSpace[] {
	const result: FlashAddrSpace[] = [linearAddrSpace(size)];
	const maxEnd = blocks.reduce((end, block) => Math.max(end, block.start + block.size), FLASH_SEGMENT_START);
	const missingSize = maxEnd - FLASH_SEGMENT_START - size;
	if (missingSize <= 0)
		return result;

	const intervals = blocks
		.filter((block) => block.size > 0 && isFlashAddr(block.start))
		.map((block) => ({ start: block.start, end: block.start + block.size }))
		.sort((a, b) => a.start - b.start);
	const merged: { start: number; end: number }[] = [];
	for (const interval of intervals) {
		const previous = merged.at(-1);
		if (previous && interval.start <= previous.end) {
			previous.end = Math.max(previous.end, interval.end);
		} else {
			merged.push({ ...interval });
		}
	}

	for (let index = 1; index < merged.length; index++) {
		const holeStart = merged[index - 1].end;
		const holeEnd = merged[index].start;
		if (holeEnd - holeStart != missingSize)
			continue;
		const lowerSize = holeStart - FLASH_SEGMENT_START;
		const upperSize = maxEnd - holeEnd;
		if (lowerSize <= 0 || upperSize <= 0 || lowerSize + upperSize != size)
			continue;
		result.push([
			{ start: FLASH_SEGMENT_START, size: lowerSize, fileOffset: 0 },
			{ start: holeEnd, size: upperSize, fileOffset: lowerSize },
		]);
	}

	const seen = new Set<string>();
	return result.filter((addrSpace) => {
		const key = addrSpaceKey(addrSpace);
		if (seen.has(key))
			return false;
		seen.add(key);
		return true;
	});
}
