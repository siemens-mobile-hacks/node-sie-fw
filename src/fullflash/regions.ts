import { addrToOffset, offsetToAddr } from "./addressSpace.js";
import type { FlashAddrSpace, FlashPartBlock, FlashPartRegion, FlashPlatform, FlashSectionsTable } from "./types.js";

const BLOCK_SIZE = 64 * 1024;
type Cell = { start: number; size: number; erased: boolean; name: string };
type Marker = { fileOffset: number; address: number };

export function buildFlashRegions(buffer: Buffer, blocks: FlashPartBlock[], addrSpace: FlashAddrSpace, sections?: FlashSectionsTable, platform?: FlashPlatform): FlashPartRegion[] {
	const cells = createCells(buffer, addrSpace);
	const pointers = [...new Set(sections?.pointers ?? [])].sort((a, b) => a - b);
	let langpack = findLangpackMarker(buffer, addrSpace, pointers);
	let resource = findResourceMarker(buffer, addrSpace, langpack?.fileOffset);
	if (!resource && sections?.resourceAddress != null)
		resource = markerAt(sections.resourceAddress, addrSpace);
	let inferredLangEnd: number | undefined;
	if (!langpack && resource && sections) {
		const metadataEnd = alignUp(sections.address + sections.pointers.length * 4, BLOCK_SIZE);
		const boundaries = pointers.filter((pointer) => pointer >= metadataEnd && pointer < resource.address && pointer % BLOCK_SIZE == 0);
		if (platform == "NSG" && boundaries.length) {
			langpack = markerAt(boundaries[0], addrSpace);
			inferredLangEnd = resource.address;
		} else if (boundaries.length >= 2) {
			langpack = markerAt(boundaries.at(-2)!, addrSpace);
			inferredLangEnd = boundaries.at(-1);
		}
	}
	const codeStart = sections ? alignUp(sections.address + sections.pointers.length * 4, BLOCK_SIZE) : undefined;

	if (langpack && codeStart != null) {
		const codeEnd = pointers.filter((pointer) => pointer > codeStart && pointer < langpack.address && pointer % BLOCK_SIZE == 0).at(-1);
		if (codeEnd != null && codeEnd > codeStart)
			setRange(cells, codeStart, codeEnd, "CODE");
	}

	const langEndOffset = langpack && inferredLangEnd == null ? findLangpackEnd(buffer, langpack.fileOffset, resource?.fileOffset) : undefined;
	let langEnd = inferredLangEnd;
	if (langEnd == null && langEndOffset != null)
		langEnd = offsetToAddr(addrSpace, langEndOffset);
	if (langpack && langEnd != null && langEnd > langpack.address)
		setRange(cells, langpack.address, langEnd, "LANGPACK");
	if (langEnd != null && resource && langEnd < resource.address)
		setRange(cells, langEnd, resource.address, "CODE");

	if (resource) {
		const blockEnd = blocks
			.filter((block) => block.name != "__FM__" && block.start > resource.address)
			.map((block) => block.start)
			.sort((a, b) => a - b)[0];
		const pointerEnd = pointers
			.filter((address) => address > resource.address)
			.sort((a, b) => a - b)[0];
		const end = blockEnd ?? pointerEnd;
		if (end != null)
			setRange(cells, resource.address, end, "RESOURCE");
	}
	markLeadingCodeSections(cells, sections, langpack?.address ?? resource?.address);
	markAdditionalCodeSections(buffer, addrSpace, cells, pointers, blocks);

	for (const block of [...blocks].sort((a, b) => b.size - a.size)) {
		if (block.name != "__FM__")
			setRange(cells, block.start, block.start + block.size, block.name);
	}
	return mergeCells(cells);
}

function createCells(buffer: Buffer, addrSpace: FlashAddrSpace): Cell[] {
	return addrSpace.flatMap((range) => Array.from({ length: Math.ceil(range.size / BLOCK_SIZE) }, (_, index) => {
		const delta = index * BLOCK_SIZE;
		const size = Math.min(BLOCK_SIZE, range.size - delta);
		const data = buffer.subarray(range.fileOffset + delta, range.fileOffset + delta + size);
		const erased = !data.some((value) => value != 0xFF);
		return {
			start: range.start + delta,
			size,
			erased,
			name: erased ? "EMPTY" : "UNKNOWN",
		};
	}));
}

function findLangpackMarker(buffer: Buffer, addrSpace: FlashAddrSpace, pointers: number[]): Marker | undefined {
	const pattern = Buffer.from([0xBB, 0xBB, 0, 0]);
	const candidates: Marker[] = [];
	for (let offset = buffer.indexOf(pattern); offset >= 0; offset = buffer.indexOf(pattern, offset + 1)) {
		if (offset % BLOCK_SIZE != 0 || offset + 64 > buffer.length)
			continue;
		const address = offsetToAddr(addrSpace, offset);
		const header = buffer.subarray(offset, offset + 64).toString("latin1");
		if (address != null && /lg[0-9]/i.test(header))
			candidates.push({ fileOffset: offset, address });
	}
	const referenced = candidates.filter((candidate) => pointers.includes(candidate.address));
	return single(referenced.length ? referenced : candidates);
}

function findResourceMarker(buffer: Buffer, addrSpace: FlashAddrSpace, after?: number): Marker | undefined {
	const pattern = Buffer.from([0x52, 0x45, 0xFF, 0xFF]);
	const candidates: Marker[] = [];
	for (let offset = buffer.indexOf(pattern, after == null ? 0 : after + BLOCK_SIZE); offset >= 0; offset = buffer.indexOf(pattern, offset + 1)) {
		if (offset % BLOCK_SIZE != 0 || offset + 128 > buffer.length || !buffer.subarray(offset, offset + 64).includes(Buffer.from("RESOURCE")))
			continue;
		const address = offsetToAddr(addrSpace, offset);
		if (address == null)
			continue;
		candidates.push({ fileOffset: offset, address });
	}
	return single(candidates);
}

function single<T>(items: T[]): T | undefined {
	return items.length == 1 ? items[0] : undefined;
}

function findLangpackEnd(buffer: Buffer, start: number, resource?: number): number | undefined {
	if (start + 0x3C > buffer.length)
		return undefined;
	if (buffer.readUInt32LE(start + 8) == 0x58 && buffer.readUInt32LE(start + 0xC) == 0x25C) {
		const payloadSize = buffer.readUInt32LE(start + 0x38);
		const end = alignUp(start + BLOCK_SIZE + payloadSize, BLOCK_SIZE);
		if (payloadSize > 0 && end <= buffer.length && (resource == null || end <= resource))
			return end;
	}
	return resource;
}

function alignUp(value: number, alignment: number): number {
	return Math.ceil(value / alignment) * alignment;
}

function alignDown(value: number, alignment: number): number {
	return Math.floor(value / alignment) * alignment;
}

function markerAt(address: number, addrSpace: FlashAddrSpace): Marker | undefined {
	const fileOffset = addrToOffset(addrSpace, address);
	return fileOffset == null ? undefined : { address, fileOffset };
}

function markLeadingCodeSections(cells: Cell[], sections?: FlashSectionsTable, end = Number.POSITIVE_INFINITY) {
	if (!sections)
		return;
	const metadataStart = alignDown(sections.address, BLOCK_SIZE);
	const metadataEnd = alignUp(sections.address + sections.pointers.length * 4, BLOCK_SIZE);
	setRange(cells, metadataStart, metadataEnd, "CODE");
	const leadingStart = sections.pointers
		.filter((pointer) => pointer < metadataStart && pointer % BLOCK_SIZE == 0)
		.sort((a, b) => b - a)[0];
	if (leadingStart != null)
		markNonErasedCode(cells, leadingStart, metadataStart);
	markNonErasedCode(cells, metadataEnd, end);
}

function markNonErasedCode(cells: Cell[], start: number, end: number) {
	for (const cell of cells) {
		if (cell.start < start)
			continue;
		if (cell.start >= end || cell.erased || cell.name != "UNKNOWN")
			break;
		cell.name = "CODE";
	}
}

function markAdditionalCodeSections(buffer: Buffer, addrSpace: FlashAddrSpace, cells: Cell[], pointers: number[], blocks: FlashPartBlock[]) {
	const layoutBlocks = blocks.filter((block) => block.name != "__FM__");
	for (const pointer of pointers) {
		const start = alignDown(pointer, BLOCK_SIZE);
		const cell = cells.find((item) => item.start == start);
		if (!cell || cell.erased || cell.name != "UNKNOWN")
			continue;
		const nextCell = cells.find((item) => item.start == start + BLOCK_SIZE);
		const offset = addrToOffset(addrSpace, start);
		if (pointer > start && (!nextCell || nextCell.erased) && offset != null && buffer.subarray(offset, offset + 8).equals(Buffer.from("MOTSTAMP"))) {
			cell.name = "MOTSTAMP";
			continue;
		}
		if (!layoutBlocks.some((block) => block.start + block.size == start))
			continue;
		const end = layoutBlocks.map((block) => block.start).filter((address) => address > start).sort((a, b) => a - b)[0];
		if (end == null)
			continue;
		const range = cells.filter((item) => item.start >= start && item.start < end);
		if (range.some((item) => item.name != "UNKNOWN" && item.name != "EMPTY"))
			continue;
		if (!nextCell || nextCell.erased)
			continue;
		setRange(cells, start, end, "CODE");
	}
}

function setRange(cells: Cell[], start: number, end: number, name: string) {
	for (const cell of cells) {
		if (cell.start < end && cell.start + cell.size > start)
			cell.name = name;
	}
}

function mergeCells(cells: Cell[]): FlashPartRegion[] {
	const result: FlashPartRegion[] = [];
	for (const cell of cells.sort((a, b) => a.start - b.start)) {
		const previous = result.at(-1);
		if (previous && cell.start < previous.start + previous.size)
			throw new Error("Flash regions overlap.");
		if (previous && previous.name == cell.name && previous.start + previous.size == cell.start) {
			previous.size += cell.size;
		} else {
			result.push({ name: cell.name, start: cell.start, size: cell.size });
		}
	}
	return result;
}
