import { getVersionFromFFS } from "../xfs.js";
import { addrToOffset, linearAddrSpace } from "./addressSpace.js";
import { parseInfoTables } from "./info.js";
import { analyzeFlashLayout } from "./layout.js";
import { buildFlashRegions } from "./regions.js";
import { findSectionsTable } from "./sections.js";
import type { FlashAddrSpace, FlashPartBlock, FlashPartRegion, FlashPlatform, FlashSectionsTable, FullFlashInfo } from "./types.js";

export function getFullFlashInfo(buffer: Buffer): FullFlashInfo | undefined {
	const layout = analyzeFlashLayout(buffer);
	if (!layout)
		return undefined;
	const info = parseInfoTables(buffer, layout.addressRanges);
	if (!info.firmware)
		return undefined;
	const sections = findSectionsTable(buffer, layout.addressRanges, info.anchors);
	return {
		platform: layout.platform,
		flashSize: buffer.length,
		addressRanges: layout.addressRanges,
		firmwareInfo: info.firmware,
		bootcoreInfo: info.bootcore,
		imei: parseIMEI(buffer),
		ffsVersion: getVersionFromFFS(buffer),
		blocks: layout.blocks,
		regions: buildFlashRegions(buffer, layout.flatBlocks, layout.addressRanges, sections, layout.platform),
		sections,
	};
}

export function parseFlashLayout(buffer: Buffer): [FlashPartBlock[], FlashPartRegion[], FlashPlatform, FlashAddrSpace] | undefined {
	const info = getFullFlashInfo(buffer);
	return info ? [info.blocks, info.regions, info.platform, info.addressRanges] : undefined;
}

export function parseSectionsTable(buffer: Buffer, platform?: FlashPlatform, addrSpace?: FlashAddrSpace): FlashSectionsTable | undefined {
	const layout = addrSpace ? undefined : analyzeFlashLayout(buffer);
	const addressRanges = addrSpace ?? layout?.addressRanges ?? linearAddrSpace(buffer.length);
	const info = parseInfoTables(buffer, addressRanges);
	void platform;
	return findSectionsTable(buffer, addressRanges, info.anchors);
}

export function readFlashBytes(buffer: Buffer, addrSpace: FlashAddrSpace, address: number, size: number): Buffer | undefined {
	const first = addrToOffset(addrSpace, address);
	const last = size < 1 ? undefined : addrToOffset(addrSpace, address + size - 1);
	return first != null && last == first + size - 1 ? buffer.subarray(first, first + size) : undefined;
}

export function parseIMEI(buffer: Buffer): string | undefined {
	const candidates = new Set<string>();
	for (let offset = 0; offset + 15 <= buffer.length; offset++) {
		if (buffer[offset] < 0x30 || buffer[offset] > 0x39)
			continue;
		let end = offset;
		while (end < buffer.length && buffer[end] >= 0x30 && buffer[end] <= 0x39)
			end++;
		if (end - offset == 15) {
			const value = buffer.toString("ascii", offset, end);
			if (validLuhn(value))
				candidates.add(value);
		}
		offset = end;
	}
	return candidates.size == 1 ? [...candidates][0] : undefined;
}

function validLuhn(value: string): boolean {
	let sum = 0;
	for (let index = 0; index < value.length; index++) {
		let digit = Number(value[index]);
		if (index % 2 == 1) {
			digit *= 2;
			if (digit > 9)
				digit -= 9;
		}
		sum += digit;
	}
	return sum % 10 == 0;
}
