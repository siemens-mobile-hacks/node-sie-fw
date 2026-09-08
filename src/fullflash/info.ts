import { findPattern } from "../patterns.js";
import { decodeCString } from "../utils.js";
import { addrToOffset, offsetToAddr } from "./addressSpace.js";
import type { FirmwareInfo, FlashAddrSpace, InfoTableAnchor } from "./types.js";

const INFO_POINTER_PATTERN = "000000FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF ??????A0 ??????A0 + 0x18";
const FIELDS = [
	"databaseName", "baselineVersion", "baselineRelease", "projectName", "releaseType", "reconfigureTime",
	"linkTime", "svn", "vendor", "model", "langpack", "tegic",
];

export type ParsedInfoTables = {
	firmware?: FirmwareInfo;
	bootcore?: FirmwareInfo;
	anchors: InfoTableAnchor[];
};

export function parseInfoTables(buffer: Buffer, addrSpace: FlashAddrSpace): ParsedInfoTables {
	const result: ParsedInfoTables = { anchors: [] };
	const candidates: { info: FirmwareInfo; anchor: InfoTableAnchor }[] = [];
	for (const fileOffset of findPattern(buffer, INFO_POINTER_PATTERN)) {
		const address = offsetToAddr(addrSpace, fileOffset);
		if (address == null || fileOffset + 8 > buffer.length)
			continue;
		try {
			const info = parseFirmwareInfoTable(buffer, buffer.readUInt32LE(fileOffset + 4), addrSpace);
			const anchor = { address, fileOffset };
			result.anchors.push(anchor);
			candidates.push({ info, anchor });
		} catch {
			// A byte-pattern match is not sufficient evidence.
		}
	}
	const resourceModels = findResourceModels(buffer);
	const matching = candidates.filter((candidate) => resourceModels.has(candidate.info.model));
	const notNamedBootcore = candidates.filter((candidate) => !/bootcore/i.test(candidate.info.databaseName));
	const firmware = matching.length ? single(matching) : single(notNamedBootcore);
	if (firmware) {
		result.firmware = firmware.info;
		const bootcore = candidates.filter((candidate) => candidate !== firmware);
		if (bootcore.length == 1)
			result.bootcore = bootcore[0].info;
	}
	return result;
}

function findResourceModels(buffer: Buffer): Set<string> {
	const models = new Set<string>();
	const marker = Buffer.from([0x52, 0x45, 0xFF, 0xFF]);
	for (let offset = buffer.indexOf(marker); offset >= 0; offset = buffer.indexOf(marker, offset + 1)) {
		if (offset % (64 * 1024) != 0 || offset + 64 > buffer.length)
			continue;
		if (!buffer.subarray(offset, offset + 64).includes(Buffer.from("RESOURCE")))
			continue;
		const model = buffer.subarray(offset + 8, offset + 24).toString("ascii").split("\0", 1)[0];
		if (model.match(/^[A-Z][A-Z0-9]{1,15}$/))
			models.add(model);
	}
	return models;
}

function single<T>(items: T[]): T | undefined {
	return items.length == 1 ? items[0] : undefined;
}

export function parseFirmwareInfoTable(buffer: Buffer, tableAddress: number, addrSpace: FlashAddrSpace): FirmwareInfo {
	const values: Partial<Record<string, string>> = {};
	for (let index = 0; index < 32; index++) {
		const offset = addrToOffset(addrSpace, tableAddress + index * 8);
		if (offset == null || offset + 8 > buffer.length)
			throw new Error("Firmware info table leaves flash.");
		const field = buffer.readUInt32LE(offset);
		if (field == 0xFFFF)
			break;
		const valueOffset = addrToOffset(addrSpace, buffer.readUInt32LE(offset + 4));
		if (field > 0xFF || valueOffset == null)
			throw new Error("Invalid firmware info table entry.");
		if (field < FIELDS.length)
			values[FIELDS[field]] = decodeCString(buffer.subarray(valueOffset));
	}
	if (!values.model || values.svn == null || !Number.isFinite(+values.svn))
		throw new Error("Incomplete firmware info table.");
	return {
		databaseName: values.databaseName ?? "",
		baselineVersion: values.baselineVersion ?? "",
		baselineRelease: values.baselineRelease ?? "",
		projectName: values.projectName ?? "",
		releaseType: values.releaseType ?? "",
		reconfigureTime: values.reconfigureTime ?? "",
		linkTime: values.linkTime ?? "",
		svn: +values.svn,
		vendor: values.vendor ?? "",
		model: values.model,
		langpack: +(values.langpack ?? 0),
		tegic: +(values.tegic ?? 0),
	};
}
