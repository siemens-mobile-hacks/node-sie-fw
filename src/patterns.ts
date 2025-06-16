import moo, { Token } from "moo";
import { sprintf } from "sprintf-js";
import createDebug from "debug";

const debug = createDebug("ptr");

type Pattern = {
	matches: PatternMatch[];
	offset: number;
};

type PatternMatch = {
	mask: number;
	value: number;
	index: number;
};

type PatternOptions = {
	align?: number;
	limit?: number;
	base?: number;
};

export function findPattern(buffer: Buffer, patternStr: string, options?: PatternOptions) {
	const validOptions = {
		align: 4,
		limit: 0,
		base: 0,
		...options
	};

	const pattern = parsePattern(patternStr);
	let matches = [...pattern.matches];

	const foundDataLength = matches.length;
	debug.enabled && debug(`Searching for pattern: ${stringifyPattern(pattern)}`);

	matches = matches.filter((p) => p.mask != 0x00);
	if (!matches.length)
		throw new Error("Pattern doesn't contain any non-wildcard bytes");

	const align = validOptions.align;
	const length = buffer.length - foundDataLength;
	const patternLength = matches.length;

	const firstPattern = matches[0];
	const foundOffsets: number[] = [];
	for (let i = 0; i < length; i += align) {
		if ((buffer[i + firstPattern.index] & firstPattern.mask) != firstPattern.value)
			continue;

		let found = true;
		for (let j = 1; j < patternLength; j++) {
			const ptr = matches[j];
			if (ptr.mask) {
				if ((buffer[i + ptr.index] & ptr.mask) != ptr.value) {
					found = false;
					break;
				}
			}
		}

		if (found) {
			debug.enabled && debug(sprintf("Found pattern at offset %08X", i + validOptions.base));
			foundOffsets.push(i + validOptions.base + pattern.offset);
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
	const strings = pattern.matches.map((ptr) => {
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
	});

	if (pattern.offset != 0)
		strings.unshift(sprintf("+%X", pattern.offset));

	return strings.join(' ');
}

function parsePattern(patternStr: string): Pattern {
	const lexer = moo.compile({
		ANY:	/\?\?/,
		HIGH:	/[0-9A-Fa-f]\?/,
		LOW:	/\?[0-9A-Fa-f]/,
		MASK:	/\[[01.]{8}]/,
		BYTE:	/[0-9A-Fa-f]{2}/,
		OFFSET:	/[+-]\s*0x[0-9A-Fa-f]+/,
		SPACE:	{ match: /\s+/, lineBreaks: true }
	});
	lexer.reset(patternStr);

	const pattern: Pattern = {
		matches: [],
		offset: 0,
	};

	let token: Token | undefined;
	let patternDone = false;
	while (token = lexer.next()) {
		if (token.type === 'SPACE')
			continue;

		if (patternDone)
			throw new Error(`Unexpected token after pattern: ${token.type}`);

		if (token.type === 'BYTE') {
			const value = parseInt(token.value, 16);
			pattern.matches.push({ index: pattern.matches.length, mask: 0xFF, value });
		} else if (token.type === 'HIGH') {
			const value = parseInt(token.value, 16) << 4;
			pattern.matches.push({ index: pattern.matches.length, mask: 0xF0, value });
		} else if (token.type === 'LOW') {
			const value = parseInt(token.value, 16);
			pattern.matches.push({ index: pattern.matches.length, mask: 0x0F, value });
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
			pattern.matches.push({ index: pattern.matches.length, mask, value });
		} else if (token.type === 'ANY') {
			pattern.matches.push({ index: pattern.matches.length, mask: 0x00, value: 0x00 });
		} else if (token.type === 'OFFSET') {
			const parsedOffset = token.value.match(/^([+-])\s*(.*?)$/);
			if (!parsedOffset)
				throw new Error(`Invalid offset: ${token.value}`);
			pattern.offset = parsedOffset[1] == '+' ? parseInt(parsedOffset[2], 16) : -parseInt(parsedOffset[2], 16);
			patternDone = true;
		} else {
			throw new Error(`Invalid token in pattern: ${token.type}`);
		}
	}

	return pattern;
}
