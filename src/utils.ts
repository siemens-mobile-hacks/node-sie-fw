export function decodeASCIIString(buf: Buffer): string | undefined {
	let end = 0;
	for (; end < buf.length; end++) {
		const byte = buf[end];
		if (byte === 0x00)
			break;
		if (byte < 0x20 || byte > 0x7E)
			return undefined; // Not valid ASCII
	}

	// Ensure the remaining bytes are all zero
	for (let i = end; i < buf.length; i++) {
		if (buf[i] !== 0x00)
			return undefined;
	}

	return buf.toString('utf-8', 0, end);
}

export function decodeCString(buf: Buffer): string {
	let end = 0;
	for (; end < buf.length; end++) {
		const byte = buf[end];
		if (byte === 0x00)
			break;
	}
	return buf.toString('utf-8', 0, end);
}
