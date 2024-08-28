import iconv from 'iconv-lite';

export function getVersionFromFFS(buffer) {
	return _getVersionFromFFS_SG(buffer) || _getVersionFromFFS_NSG(buffer);
}

function _getVersionFromFFS_NSG(buffer) {
	let fileNamePtr = iconv.encode("info.txt", "utf16-be");
	let lastIndex = 0;
	while (true) {
		let index = buffer.indexOf(fileNamePtr, lastIndex);
		if (index < 0)
			break;

		index += fileNamePtr.length;

		let possibleString = buffer.subarray(index, index + 256).filter((byte) => byte != 0xFF).toString();
		let matches = possibleString.match(/([\w\d]+_\d+_[\w\d-]+_\d+_\d+)\n/i);

		if (matches && matches[1])
			return matches[1];

		lastIndex = index + 1;
	}

	return null;
}

function _getVersionFromFFS_SG(buffer) {
	let patterns = [
		iconv.encode("ccq_vinfo.txt", "utf16-be"),
		Buffer.concat([ Buffer.from("ccq_vinfo.txt", "utf-8"), Buffer.from([0]) ])
	];

	for (let fileNamePtr of patterns) {
		let lastIndex = 0;
		while (true) {
			let index = buffer.indexOf(fileNamePtr, lastIndex);
			if (index < 0)
				break;

			index += fileNamePtr.length;

			let chars = [];
			while (index < buffer.length && buffer[index] != 0x0A) {
				if (buffer[index] > 0x7F || buffer[index] < 0x20) {
					if (buffer[index] != 0x0A)
						chars = [];
					break;
				}
				chars.push(buffer[index]);
				index++;
			}

			let possibleString = Buffer.from(chars).toString();
			if (possibleString.match(/^[\w\d]+_\d+_[\w\d-]+_\d+_\d+$/i))
				return possibleString;

			lastIndex = index + 1;
		}
	}

	return null;
}
