export type LzssDecompressResult = {
	data: Buffer;
	finished: boolean;
};

export function lzssDecompressor() {
	const decompressedBuffer = Buffer.alloc(4096);
	const circularBuffer = Buffer.alloc(4096);
	let circularBufferPos = 1;
	let copyFrom = 0;
	let state = 0;
	let tempByte = 0;
	let tempByteBitsCnt = 0;
	let finished = false;

	return (buffer: Buffer): LzssDecompressResult => {
		if (finished) {
			if (buffer.length != 0)
				throw new Error(`Data after LZSS end marker.`);
			return { data: Buffer.alloc(0), finished };
		}

		let decompressedSize = 0;

		inputLoop: for (let i = 0; i < buffer.length; i++) {
			const byte = buffer[i];
			for (let bitN = 0; bitN < 8; bitN++) {
				const bit = (byte & (1 << (8 - bitN - 1))) != 0 ? 1 : 0;

				switch (state) {
					case 0:
						tempByteBitsCnt = 0;
						tempByte = 0;
						state = bit ? 1 : 2;
					break;

					case 1:
						tempByte = (tempByte << 1) | bit;
						tempByteBitsCnt++;

						if (tempByteBitsCnt == 8) {
							decompressedBuffer[decompressedSize++] = tempByte;
							circularBuffer[circularBufferPos] = tempByte;
							circularBufferPos = (circularBufferPos + 1) & 0xFFF;
							state = 0;
						}
					break;

					case 2:
						tempByte = (tempByte << 1) | bit;
						tempByteBitsCnt++;

						if (tempByteBitsCnt == 12) {
							copyFrom = tempByte;

							if (copyFrom == 0) {
								const paddingBits = 7 - bitN;
								const paddingMask = (1 << paddingBits) - 1;
								if ((byte & paddingMask) != 0 || i != buffer.length - 1)
									throw new Error(`Invalid LZSS padding.`);

								finished = true;
								state = 0;
								break inputLoop;
							}

							tempByte = 0;
							tempByteBitsCnt = 0;
							state = 3;
						}
					break;

					case 3:
						tempByte = (tempByte << 1) | bit;
						tempByteBitsCnt++;

						if (tempByteBitsCnt == 4) {
							for (let j = 0; j <= tempByte + 1; j++) {
								const value = circularBuffer[(copyFrom + j) & 0xFFF];
								decompressedBuffer[decompressedSize++] = value;
								circularBuffer[circularBufferPos] = value;
								circularBufferPos = (circularBufferPos + 1) & 0xFFF;
							}
							state = 0;
						}
					break;

					default:
						throw new Error(`Invalid state.`);
				}
			}
		}
		return { data: decompressedBuffer.subarray(0, decompressedSize), finished };
	};
}
