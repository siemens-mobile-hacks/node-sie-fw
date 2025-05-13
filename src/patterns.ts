import moo, { Token } from "moo";
import { sprintf } from "sprintf-js";
import createDebug from "debug";

const debug = createDebug("ptr");

type Pattern = Array<{
	mask: number;
	value: number;
	index: number;
}>;

type PatternOptions = {
	align?: number;
	limit?: number;
	base?: number;
};

export function findPattern(buffer: Buffer, patternStr: string, options?: PatternOptions) {
	const validOptions = {
		align: 1,
		limit: 0,
		base: 0,
		...options
	};

	let pattern = parsePattern(patternStr);
	const foundDataLength = pattern.length;
	debug.enabled && debug(`Searching for pattern: ${stringifyPattern(pattern)}`);

	pattern = pattern.filter((p) => p.mask != 0x00);
	if (!pattern.length)
		throw new Error("Pattern doesn't contain any non-wildcard bytes");

	const align = validOptions.align;
	const length = buffer.length - foundDataLength;
	const patternLength = pattern.length;

	const firstPattern = pattern[0];
	const foundOffsets: number[] = [];
	for (let i = 0; i < length; i += align) {
		if ((buffer[i + firstPattern.index] & firstPattern.mask) != firstPattern.value)
			continue;

		let found = true;
		for (let j = 1; j < patternLength; j++) {
			const ptr = pattern[j];
			if (ptr.mask) {
				if ((buffer[i + ptr.index] & ptr.mask) != ptr.value) {
					found = false;
					break;
				}
			}
		}

		if (found) {
			debug.enabled && debug(sprintf("Found pattern at offset %08X", i + validOptions.base));
			foundOffsets.push(i + validOptions.base);
			if (validOptions.limit && foundOffsets.length >= validOptions.limit)
				break;
		}
	}

	return foundOffsets;
}

export function prettifyPattern(patternStr: string) {
	const pattern = parsePattern(patternStr);
	return stringifyPattern(pattern);
}

function stringifyPattern(pattern: Pattern) {
	return pattern.map((ptr) => {
		if (ptr.mask == 0x00)
			return "??";
		if (ptr.mask == 0xF0)
			return sprintf("%X?", ptr.value >> 4);
		if (ptr.mask == 0x0F)
			return sprintf("?%X", ptr.value);
		if (ptr.mask == 0xFF)
			return sprintf("%02X", ptr.value);

		const bits: string[] = [];
		for (let i = 0; i < 8; i++) {
			const bit = 1 << (7 - i);
			if ((ptr.mask & bit)) {
				bits.push((ptr.value & bit) ? '1' : '0');
			} else {
				bits.push('.');
			}
		}

		return `[${bits.join('')}]`;
	}).join(' ');
}

function parsePattern(patternStr: string): Pattern {
	const lexer = moo.compile({
		ANY:	/\?\?/,
		HIGH:	/[0-9A-Fa-f]\?/,
		LOW:	/\?[0-9A-Fa-f]/,
		MASK:	/\[[01.]{8}]/,
		BYTE:	/[0-9A-Fa-f]{2}/,
		SPACE:	{ match: /\s+/, lineBreaks: true }
	});
	lexer.reset(patternStr);

	const pattern: Pattern = [];

	let token: Token | undefined;
	while (token = lexer.next()) {
		if (token.type === 'SPACE')
			continue;

		if (token.type === 'BYTE') {
			const value = parseInt(token.value, 16);
			pattern.push({ index: pattern.length, mask: 0xFF, value });
		} else if (token.type === 'HIGH') {
			const value = parseInt(token.value, 16) << 4;
			pattern.push({ index: pattern.length, mask: 0xF0, value });
		} else if (token.type === 'LOW') {
			const value = parseInt(token.value, 16);
			pattern.push({ index: pattern.length, mask: 0x0F, value });
		} else if (token.type === 'MASK') {
			const bits = token.value.substring(1, token.value.length - 1);
			let mask = 0;
			let value = 0;
			for (let i = 0; i < 8; i++) {
				if (bits[i] == '.')
					continue;
				mask |= 1 << (7 - i);
				if (bits[i] == '1')
					value |= 1 << (7 - i);
			}
			pattern.push({ index: pattern.length, mask, value });
		} else if (token.type === 'ANY') {
			pattern.push({ index: pattern.length, mask: 0x00, value: 0x00 });
		} else {
			throw new Error(`Invalid token in pattern: ${token.type}`);
		}
	}

	return pattern;
}
