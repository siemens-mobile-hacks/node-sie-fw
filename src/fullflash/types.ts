export type FlashPlatform = "SG" | "NSG";

export type FlashAddrSpace = Array<{
	start: number;
	size: number;
	fileOffset: number;
}>;

export interface FlashPartBlock {
	name: string;
	start: number;
	size: number;
	children: FlashPartBlock[];
}

export interface FlashPartRegion {
	name: string;
	start: number;
	size: number;
}

export interface FirmwareInfo {
	databaseName: string;
	baselineVersion: string;
	baselineRelease: string;
	projectName: string;
	releaseType: string;
	reconfigureTime: string;
	linkTime: string;
	svn: number;
	vendor: string;
	model: string;
	langpack: number;
	tegic: number;
}

export interface InfoTableAnchor {
	address: number;
	fileOffset: number;
}

export interface FlashSectionsTable {
	address: number;
	pointers: number[];
	resourceAddress?: number;
}

export interface FlashLayoutAnalysis {
	platform: FlashPlatform;
	addressRanges: FlashAddrSpace;
	blocks: FlashPartBlock[];
	flatBlocks: FlashPartBlock[];
}

export interface FullFlashInfo {
	platform: FlashPlatform;
	flashSize: number;
	addressRanges: FlashAddrSpace;
	firmwareInfo: FirmwareInfo;
	bootcoreInfo?: FirmwareInfo;
	imei?: string;
	ffsVersion?: string;
	blocks: FlashPartBlock[];
	regions: FlashPartRegion[];
	sections?: FlashSectionsTable;
}
