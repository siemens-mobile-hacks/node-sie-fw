export function decodeASCIIString(source: Buffer, offset?: number, size?: number): string | undefined {
	let buf: Buffer = source;
	if (offset != null && size != null) {
		buf = source.subarray(offset, offset + size);
	} else if (offset != null) {
		buf = source.subarray(offset);
	}

	let end = 0;
	for (; end < buf.length; end++) {
		const byte = buf[end];
		if (byte === 0x00)
			break;
		if (byte < 0x20 || byte > 0x7E)
			return undefined; // Not valid ASCII
	}

	return buf.toString('utf-8', 0, end);
}

export function decodeCString(source: Buffer, offset?: number, size?: number): string {
	let buf: Buffer = source;
	if (offset != null && size != null) {
		buf = source.subarray(offset, offset + size);
	} else if (offset != null) {
		buf = source.subarray(offset);
	}

	let end = 0;
	for (; end < buf.length; end++) {
		const byte = buf[end];
		if (byte === 0x00)
			break;
	}
	return buf.toString('utf-8', 0, end);
}

export function formatSize(bytes: number): string {
	const units = ["B", "KiB", "MiB", "GiB"];
	let i = 0;
	while (bytes >= 1024 && i < units.length - 1) {
		bytes /= 1024;
		i++;
	}
	return `${Math.round(bytes * 100) / 100} ${units[i]}`;
}
