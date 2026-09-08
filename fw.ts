import fs from 'node:fs';
import { findPattern, getFullFlashInfo } from "./src/index.js";
import { table as asciiTable } from 'table';
import { sprintf } from "sprintf-js";
import { formatSize } from "./src/utils.js";

const buffer = fs.readFileSync("/home/azq2/Documents/ff/C81v51.bin");
const info = getFullFlashInfo(buffer);
console.log(info);

/*
// for (const file of fs.globSync("/home/azq2/Downloads/max_ff/*.bin")) {
for (const file of fs.globSync("/tmp/C1F0_db51.1.bin")) {
	const buffer = fs.readFileSync(file);
	console.log(file);
	const info = getFullFlashInfo(buffer);
	if (!info)
		continue;

	const table: string[][] = [
		['Name', 'Start', 'End', 'Size']
	];
	for (const region of info.regions) {
		table.push([
			region.name,
			sprintf("%08X", region.start),
			sprintf("%08X", region.start + region.size - 1),
			formatSize(region.size),
		]);
	}
	console.log(asciiTable(table));
}
*/
