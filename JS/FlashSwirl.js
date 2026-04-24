// FlashSwirl 闪旋 算法库  https://github.com/fzxx/FlashSwirl

const BLOCK_SIZE = 32;      // 算法块大小，单位为字节
const KEY_SIZE = 32;        // 密钥长度，单位为字节
const NONCE_SIZE = 24;      // 随机数长度，单位为字节
const TAG_SIZE = 16;        // AEAD 认证标签长度，单位为字节
const BUFFER_SIZE = 4 << 20; // 4MB缓冲区

// 初始状态
const FIXED_INITIAL_STATE = new Uint8Array([
	0x46, 0x6c, 0x61, 0x73, 0x68, 0x53, 0x77, 0x69,
	0x72, 0x6c, 0xe9, 0x97, 0xaa, 0xe6, 0x97, 0x8b,
	0x20, 0x46, 0x65, 0x6e, 0x67, 0x5a, 0x68, 0x69,
	0x58, 0x69, 0x61, 0x58, 0x69, 0x61, 0x6e, 0x67,
]);

function writeStateLE(state, output, offset) {
	for (let i = 0; i < 8; i++) {
		const val = state[i];
		output[offset + i * 4] = val & 0xff;
		output[offset + i * 4 + 1] = (val >> 8) & 0xff;
		output[offset + i * 4 + 2] = (val >> 16) & 0xff;
		output[offset + i * 4 + 3] = (val >> 24) & 0xff;
	}
}

function xofOutput(state, outputLen) {
	const output = new Uint8Array(outputLen);
	let outOff = 0;
	const fullBlocks = outputLen >> 5;
	for (let b = 0; b < fullBlocks; b++) {
		writeStateLE(state, output, outOff);
		outOff += BLOCK_SIZE;
		if (outOff < outputLen) {
			for (let r = 0; r < 10; r++) swirlRound(state);
		}
	}
	const remaining = outputLen & 31;
	for (let i = 0; i < remaining; i++) {
		output[outOff + i] = (state[i >> 2] >> ((i & 3) * 8)) & 0xff;
	}
	return output;
}

function flashSwirlXOF(input, outputLen) {
	const state = keyToState(input);
	if (input.length > BLOCK_SIZE) {
		const remaining = input.subarray(BLOCK_SIZE);
		for (let i = 0; i < remaining.length; i++) {
			const byteIdx = i & 31;
			state[byteIdx >> 2] ^= (remaining[i] << ((byteIdx & 3) * 8));
		}
	}
	for (let r = 0; r < 20; r++) swirlRound(state);
	return xofOutput(state, outputLen);
}


let cachedFixedState = null;

// 初始化缓存的固定初始状态
function initCachedFixedState() {
	cachedFixedState = keyToState(FIXED_INITIAL_STATE);
}

initCachedFixedState();
const bufferPool = {
	buffers: [],
	get() {
		const len = this.buffers.length;
		return len > 0 ? this.buffers.pop() : new Uint8Array(BUFFER_SIZE);
	},
	put(buffer) {
		if (this.buffers.length < 10) {
			this.buffers.push(buffer);
		}
	}
};

const statePool = {
	pool: [],
	get() {
		const len = this.pool.length;
		if (len > 0) {
			const arr = this.pool.pop();
			arr.fill(0);
			return arr;
		}
		return new Uint32Array(8);
	},
	put(arr) {
		if (this.pool.length < 20) {
			this.pool.push(arr);
		}
	}
};

function validateKey(key) {
	if (key.length !== KEY_SIZE) {
		throw new Error(`密钥长度必须为 ${KEY_SIZE} 字节`);
	}
}

function validateNonce(nonce) {
	if (nonce.length !== NONCE_SIZE) {
		throw new Error(`随机Nonce长度必须为 ${NONCE_SIZE} 字节`);
	}
}

function validateKeyAndNonce(key, nonce) {
	validateKey(key);
	validateNonce(nonce);
}

function clearBuffer(buf) {
	buf.fill(0);
}

function prepareHmacPads(key, ipad, opad) {
	for (let i = 0; i < BLOCK_SIZE; i++) {
		const keyByte = i < key.length ? key[i] : 0;
		ipad[i] = keyByte ^ 0x36;
		opad[i] = keyByte ^ 0x5C;
	}
}

function constantTimeCompare(a, b) {
	if (a.length !== b.length) return false;
	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a[i] ^ b[i];
	}
	return result === 0;
}

function xorBytes(dst, src, n) {
	let i = 0;
	for (; i + 8 <= n; i += 8) {
		const low1 = dst[i] | (dst[i + 1] << 8) | (dst[i + 2] << 16) | (dst[i + 3] << 24);
		const high1 = dst[i + 4] | (dst[i + 5] << 8) | (dst[i + 6] << 16) | (dst[i + 7] << 24);
		const low2 = src[i] | (src[i + 1] << 8) | (src[i + 2] << 16) | (src[i + 3] << 24);
		const high2 = src[i + 4] | (src[i + 5] << 8) | (src[i + 6] << 16) | (src[i + 7] << 24);
		const xorLow = (low1 ^ low2) >>> 0;
		const xorHigh = (high1 ^ high2) >>> 0;
		dst[i] = xorLow & 0xff;
		dst[i + 1] = (xorLow >> 8) & 0xff;
		dst[i + 2] = (xorLow >> 16) & 0xff;
		dst[i + 3] = (xorLow >> 24) & 0xff;
		dst[i + 4] = xorHigh & 0xff;
		dst[i + 5] = (xorHigh >> 8) & 0xff;
		dst[i + 6] = (xorHigh >> 16) & 0xff;
		dst[i + 7] = (xorHigh >> 24) & 0xff;
	}
	for (; i < n; i++) {
		dst[i] ^= src[i];
	}
}

function writeUint64LE(buf, offset, value) {
	const high = Number((value >> 32n) & 0xffffffffn);
	const low = Number(value & 0xffffffffn);
	buf[offset] = low & 0xff;
	buf[offset + 1] = (low >> 8) & 0xff;
	buf[offset + 2] = (low >> 16) & 0xff;
	buf[offset + 3] = (low >> 24) & 0xff;
	buf[offset + 4] = high & 0xff;
	buf[offset + 5] = (high >> 8) & 0xff;
	buf[offset + 6] = (high >> 16) & 0xff;
	buf[offset + 7] = (high >> 24) & 0xff;
}

function swirlRound(state) {
	let a = state[0], b = state[1], c = state[2], d = state[3];
	a = (a + b) >>> 0; d = ((d ^ a) << 16 | (d ^ a) >>> 16) >>> 0;
	c = (c + d) >>> 0; b = ((b ^ c) << 12 | (b ^ c) >>> 20) >>> 0;
	a = (a + b) >>> 0; d = ((d ^ a) << 8 | (d ^ a) >>> 24) >>> 0;
	c = (c + d) >>> 0; b = ((b ^ c) << 7 | (b ^ c) >>> 25) >>> 0;
	state[0] = a; state[1] = b; state[2] = c; state[3] = d;

	let e = state[4], f = state[5], g = state[6], h = state[7];
	e = (e + f) >>> 0; h = ((h ^ e) << 16 | (h ^ e) >>> 16) >>> 0;
	g = (g + h) >>> 0; f = ((f ^ g) << 12 | (f ^ g) >>> 20) >>> 0;
	e = (e + f) >>> 0; h = ((h ^ e) << 8 | (h ^ e) >>> 24) >>> 0;
	g = (g + h) >>> 0; f = ((f ^ g) << 7 | (f ^ g) >>> 25) >>> 0;
	state[4] = e; state[5] = f; state[6] = g; state[7] = h;

	a = state[0], f = state[5], c = state[2], h = state[7];
	a = (a + f) >>> 0; h = ((h ^ a) << 16 | (h ^ a) >>> 16) >>> 0;
	c = (c + h) >>> 0; f = ((f ^ c) << 12 | (f ^ c) >>> 20) >>> 0;
	a = (a + f) >>> 0; h = ((h ^ a) << 8 | (h ^ a) >>> 24) >>> 0;
	c = (c + h) >>> 0; f = ((f ^ c) << 7 | (f ^ c) >>> 25) >>> 0;
	state[0] = a; state[5] = f; state[2] = c; state[7] = h;

	b = state[1], e = state[4], d = state[3], g = state[6];
	b = (b + e) >>> 0; g = ((g ^ b) << 16 | (g ^ b) >>> 16) >>> 0;
	d = (d + g) >>> 0; e = ((e ^ d) << 12 | (e ^ d) >>> 20) >>> 0;
	b = (b + e) >>> 0; g = ((g ^ b) << 8 | (g ^ b) >>> 24) >>> 0;
	d = (d + g) >>> 0; e = ((e ^ d) << 7 | (e ^ d) >>> 25) >>> 0;
	state[1] = b; state[4] = e; state[3] = d; state[6] = g;
}

function normalizeRounds(rounds) {
	return (rounds === 8 || rounds === 20) ? rounds / 2 : 10;
}

function applySwirlRounds(state, rounds) {
	for (let i = 0; i < rounds; i++) {
		swirlRound(state);
	}
}

function readUint32LE(buf, offset) {
	return (buf[offset]) | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24) >>> 0;
}

function writeUint32LE(buf, offset, value) {
	buf[offset] = value & 0xff;
	buf[offset + 1] = (value >> 8) & 0xff;
	buf[offset + 2] = (value >> 16) & 0xff;
	buf[offset + 3] = (value >> 24) & 0xff;
}

function keyToState(key) {
	const state = new Uint32Array(8);
	for (let i = 0; i < 8; i++) {
		const offset = i * 4;
		if (offset + 4 <= key.length) {
			state[i] = readUint32LE(key, offset);
		} else {
			let tmp = 0;
			for (let j = 0; j < 4; j++) {
				if (offset + j < key.length) {
					tmp |= key[offset + j] << (j * 8);
				}
			}
			state[i] = tmp >>> 0;
		}
	}
	return state;
}

function stateToBytes(state, buffer) {
	const out = buffer || new Uint8Array(BLOCK_SIZE);
	for (let i = 0; i < 8; i++) {
		writeUint32LE(out, i * 4, state[i]);
	}
	return out;
}

function bytesToState(bytes, offset = 0) {
	const state = new Uint32Array(8);
	for (let i = 0; i < 8; i++) {
		state[i] = readUint32LE(bytes, offset + i * 4);
	}
	return state;
}

function copyState(src) {
	return new Uint32Array(src);
}

function makeBaseNonce(key, nonce) {
	try {
		validateKeyAndNonce(key, nonce);
		const baseNonce = new Uint8Array(BLOCK_SIZE);
		for (let i = 0; i < BLOCK_SIZE; i++) {
			const nonceByte = i < NONCE_SIZE ? nonce[i] : 0;
			baseNonce[i] = FIXED_INITIAL_STATE[i] ^ key[i] ^ nonceByte;
		}
		return [baseNonce, null];
	} catch (error) {
		return [null, error];
	}
}

function keystreamBlockCore(baseNonce, counter, rounds) {
	const state = bytesToState(baseNonce);
	state[6] ^= Number((counter >> 32n) & 0xffffffffn);
	state[7] ^= Number(counter & 0xffffffffn);
	const original = copyState(state);
	applySwirlRounds(state, rounds);
	for (let i = 0; i < 8; i++) {
		state[i] += original[i];
	}
	return state;
}

function generateKeystreamBlock(baseNonce, counter, normalizedRounds) {
	return stateToBytes(keystreamBlockCore(baseNonce, counter, normalizedRounds));
}

function processKeystreamBlocks(baseNonce, counter, normalizedRounds, dst) {
	const numBlocks = Math.floor(dst.length / BLOCK_SIZE);
	for (let i = 0; i < numBlocks; i++) {
		const state = keystreamBlockCore(baseNonce, counter + BigInt(i), normalizedRounds);
		const offset = i * BLOCK_SIZE;
		for (let j = 0; j < 8; j++) {
			const val = state[j];
			dst[offset + j * 4] ^= val & 0xff;
			dst[offset + j * 4 + 1] ^= (val >> 8) & 0xff;
			dst[offset + j * 4 + 2] ^= (val >> 16) & 0xff;
			dst[offset + j * 4 + 3] ^= (val >> 24) & 0xff;
		}
	}
	return counter + BigInt(numBlocks);
}

function processStreamCore(baseNonce, normalizedRounds, input, output, onChunk) {
	const buf = bufferPool.get();
	let counter = 0n;
	let n;
	try {
		do {
			n = input.read(buf);
			if (n > 0) {
				const fullBlocks = Math.floor(n / BLOCK_SIZE);
				const fullBlockSize = fullBlocks * BLOCK_SIZE;
				if (fullBlocks > 0) {
					counter = processKeystreamBlocks(baseNonce, counter, normalizedRounds, buf.subarray(0, fullBlockSize));
				}
				const remaining = n % BLOCK_SIZE;
				if (remaining > 0) {
					const keystream = generateKeystreamBlock(baseNonce, counter, normalizedRounds);
					xorBytes(buf.subarray(fullBlockSize, fullBlockSize + remaining), keystream, remaining);
					counter++;
				}
				const chunk = buf.subarray(0, n);
				if (onChunk) onChunk(chunk, fullBlockSize, remaining);
				output.write(chunk);
			}
		} while (n > 0);
	} finally {
		bufferPool.put(buf);
	}
}

function streamProcess(key, rounds, input, output, randomNonce) {
	const normalizedRounds = normalizeRounds(rounds);
	const [baseNonce, err] = makeBaseNonce(key, randomNonce);
	if (err) throw err;
	try {
		processStreamCore(baseNonce, normalizedRounds, input, output);
	} finally {
		clearBuffer(baseNonce);
	}
}

class MemoryReader {
	constructor(data) {
		this.data = data;
		this.dataLen = data.length;
		this.position = 0;
	}

	read(buffer) {
		const remaining = this.dataLen - this.position;
		if (remaining <= 0) return 0;
		const bufLen = buffer.length;
		const toRead = remaining < bufLen ? remaining : bufLen;
		buffer.set(this.data.subarray(this.position, this.position + toRead));
		this.position += toRead;
		return toRead;
	}
}

class MemoryWriter {
	constructor(initialCapacity = 4096) {
		this.buffer = new Uint8Array(initialCapacity);
		this.length = 0;
	}

	write(data) {
		const dataLen = data.length;
		const needed = this.length + dataLen;
		if (needed > this.buffer.length) {
			const newLen = Math.max(needed, this.buffer.length * 2);
			const newBuf = new Uint8Array(newLen);
			newBuf.set(this.buffer.subarray(0, this.length));
			this.buffer = newBuf;
		}
		this.buffer.set(data, this.length);
		this.length += dataLen;
	}

	getResult() {
		return this.buffer.subarray(0, this.length);
	}
}

function deriveKeys(masterKey, rounds) {
	try {
		validateKey(masterKey);
		const normalizedRounds = normalizeRounds(rounds);
		const [encryptionKey, err1] = hkdfInternal(masterKey, null, new TextEncoder().encode("aead-key"), BLOCK_SIZE, normalizedRounds);
		if (err1) return [null, null, err1];
		const [authKey, err2] = hkdfInternal(masterKey, null, new TextEncoder().encode("tag-key"), BLOCK_SIZE, normalizedRounds);
		if (err2) {
			clearBuffer(encryptionKey);
			return [null, null, err2];
		}
		return [encryptionKey, authKey, null];
	} catch (error) {
		return [null, null, error];
	}
}

function prepareAeadHmac(authKey, rounds) {
	let processedAuthKey = authKey;
	if (authKey.length > BLOCK_SIZE) {
		const hashWriter = new MemoryWriter();
		const [, hashErr] = hashInternal(new MemoryReader(authKey), rounds, hashWriter);
		if (hashErr) throw hashErr;
		processedAuthKey = hashWriter.getResult();
	}
	const ipad = new Uint8Array(BLOCK_SIZE);
	const opad = new Uint8Array(BLOCK_SIZE);
	prepareHmacPads(processedAuthKey, ipad, opad);
	return { ipad, opad };
}

class HashState {
	constructor(key, rounds, direct = false) {
		const keyState = keyToState(key);
		this.state = new Uint32Array(8);
		for (let i = 0; i < 8; i++) {
			this.state[i] = cachedFixedState[i] ^ keyState[i];
		}
		this.pending = new Uint8Array(2 * BLOCK_SIZE);
		this.pendingLen = 0;
		this.total = 0n;
		this.rounds = rounds;
		this.direct = direct;
	}

	static withRounds(key, normalizedRounds) {
		return new HashState(key, normalizedRounds, true);
	}

	write(data) {
		this.total += BigInt(data.length);
		if (this.pendingLen > 0) {
			const need = BLOCK_SIZE - this.pendingLen;
			if (data.length >= need) {
				this.pending.set(data.subarray(0, need), this.pendingLen);
				compress(this.state, this.pending, this.rounds, !this.direct);
				this.pendingLen = 0;
				data = data.subarray(need);
			} else {
				this.pending.set(data, this.pendingLen);
				this.pendingLen += data.length;
				return;
			}
		}
		for (let i = 0; i < data.length; i += BLOCK_SIZE) {
			const end = Math.min(i + BLOCK_SIZE, data.length);
			if (end - i === BLOCK_SIZE) {
				compress(this.state, data.subarray(i, end), this.rounds, !this.direct);
			} else {
				this.pending.set(data.subarray(i, end));
				this.pendingLen = end - i;
			}
		}
	}

	sum() {
		const state = copyState(this.state);
		const pending = new Uint8Array(this.pending);
		let pendingLen = this.pendingLen;

		pending[pendingLen++] = 0x80;
		const pad = (BLOCK_SIZE - (pendingLen + 8) % BLOCK_SIZE) % BLOCK_SIZE;
		for (let i = 0; i < pad; i++) {
			pending[pendingLen++] = 0;
		}
		writeUint64LE(pending, pendingLen, this.total * 8n);
		pendingLen += 8;

		for (let i = 0; i < pendingLen; i += BLOCK_SIZE) {
			const end = Math.min(i + BLOCK_SIZE, pendingLen);
			compress(state, pending.subarray(i, end), this.rounds, !this.direct);
		}

		return stateToBytes(state);
	}

	reset(key, rounds, direct = false) {
		const keyState = keyToState(key);
		for (let i = 0; i < 8; i++) {
			this.state[i] = cachedFixedState[i] ^ keyState[i];
		}
		this.pending.fill(0);
		this.pendingLen = 0;
		this.total = 0n;
		this.rounds = rounds;
		this.direct = direct;
	}
}

function aeadEncryptInternal(key, randomNonce, input, output, additionalData, rounds) {
	validateKeyAndNonce(key, randomNonce);

	const [encryptionKey, authKey, err] = deriveKeys(key, rounds);
	if (err) throw err;
	try {
		const { ipad, opad } = prepareAeadHmac(authKey, rounds);
		const normalizedRounds = normalizeRounds(rounds);
		const hashRounds = Math.max(1, Math.floor(normalizedRounds / 2));

		const inner = HashState.withRounds(ipad, hashRounds);
		inner.write(additionalData);

		const [baseNonce, baseErr] = makeBaseNonce(encryptionKey, randomNonce);
		if (baseErr) throw baseErr;

		try {
			processStreamCore(baseNonce, normalizedRounds, input, output, (chunk, fullBlockSize, remaining) => {
				if (fullBlockSize > 0) inner.write(chunk.subarray(0, fullBlockSize));
				if (remaining > 0) inner.write(chunk.subarray(fullBlockSize, fullBlockSize + remaining));
			});

			const outer = HashState.withRounds(opad, hashRounds);
			outer.write(inner.sum());
			output.write(outer.sum().subarray(0, TAG_SIZE));
		} finally {
			clearBuffer(baseNonce);
		}
	} finally {
		clearBuffer(encryptionKey);
		clearBuffer(authKey);
	}
}

function aeadDecryptInternal(key, randomNonce, input, output, additionalData, rounds) {
	validateKeyAndNonce(key, randomNonce);

	const [encryptionKey, authKey, err] = deriveKeys(key, rounds);
	if (err) throw err;
	try {
		const allData = new MemoryWriter();
		const buf = bufferPool.get();
		try {
			let n;
			do {
				n = input.read(buf);
				if (n > 0) allData.write(buf.subarray(0, n));
			} while (n > 0);
		} finally {
			bufferPool.put(buf);
		}

		const data = allData.getResult();
		if (data.length < TAG_SIZE) throw new Error("输入数据的大小错误");
		const ciphertext = data.subarray(0, data.length - TAG_SIZE);
		const expectedTag = data.subarray(data.length - TAG_SIZE);

		const { ipad, opad } = prepareAeadHmac(authKey, rounds);
		const normalizedRounds = normalizeRounds(rounds);
		const hashRounds = Math.max(1, Math.floor(normalizedRounds / 2));

		const inner = HashState.withRounds(ipad, hashRounds);
		inner.write(additionalData);
		inner.write(ciphertext);
		const outer = HashState.withRounds(opad, hashRounds);
		outer.write(inner.sum());
		if (!constantTimeCompare(outer.sum().subarray(0, TAG_SIZE), expectedTag)) throw new Error("认证失败");

		const [baseNonce, baseErr] = makeBaseNonce(encryptionKey, randomNonce);
		if (baseErr) throw baseErr;

		try {
			processStreamCore(baseNonce, normalizedRounds, new MemoryReader(ciphertext), output);
		} finally {
			clearBuffer(baseNonce);
		}
	} finally {
		clearBuffer(encryptionKey);
		clearBuffer(authKey);
	}
}

const compressTemp = new Uint32Array(8);

function compress(state, block, rounds, normalize = true) {
	const m = bytesToState(block);
	const old = copyState(state);
	const temp = compressTemp;
	temp.fill(0);
	for (let i = 0; i < 8; i++) {
		temp[i] = old[i] ^ m[i];
	}
	const actualRounds = normalize ? normalizeRounds(rounds) : rounds;
	for (let r = 0; r < actualRounds; r++) {
		swirlRound(temp);
	}
	for (let i = 0; i < 8; i++) {
		state[i] = old[i] ^ temp[i];
	}
}

function hashWithState(initialState, input, rounds, out) {
	try {
		const state = copyState(initialState);

		const buf = new Uint8Array(BLOCK_SIZE);
		const pending = new Uint8Array(2 * BLOCK_SIZE);
		let pendingLen = 0;
		let totalBytes = 0n;

		let n;
		do {
			n = input.read(buf);
			if (n > 0) {
				totalBytes += BigInt(n);
				let src = buf.subarray(0, n);
				while (src.length > 0) {
					const space = BLOCK_SIZE - pendingLen;
					const copyLen = Math.min(src.length, space);
					pending.set(src.subarray(0, copyLen), pendingLen);
					pendingLen += copyLen;
					src = src.subarray(copyLen);
					if (pendingLen === BLOCK_SIZE) {
						compress(state, pending.subarray(0, BLOCK_SIZE), rounds);
						pendingLen = 0;
					}
				}
			}
		} while (n > 0);

		const totalBits = totalBytes * 8n;
		pending[pendingLen++] = 0x80;
		const pad = (BLOCK_SIZE - (pendingLen + 8) % BLOCK_SIZE) % BLOCK_SIZE;
		for (let i = 0; i < pad; i++) {
			pending[pendingLen++] = 0;
		}
		writeUint64LE(pending, pendingLen, totalBits);
		pendingLen += 8;

		for (let i = 0; i < pendingLen; i += BLOCK_SIZE) {
			const end = Math.min(i + BLOCK_SIZE, pendingLen);
			compress(state, pending.subarray(i, end), rounds);
		}

		stateToBytes(state, out);
		return null;
	} catch (error) {
		return error;
	}
}

function hashInternal(input, rounds, output) {
	const out = new Uint8Array(BLOCK_SIZE);
	const err = hashWithState(cachedFixedState, input, rounds, out);
	if (err) return [null, err];
	if (output) output.write(out);
	return [out, null];
}

function xorStateWithFixed(key) {
	const state = new Uint32Array(8);
	const keyState = keyToState(key);
	for (let i = 0; i < 8; i++) {
		state[i] = cachedFixedState[i] ^ keyState[i];
	}
	return state;
}

function hmacTo(key, data, rounds, out) {
	try {
		if (out.length < BLOCK_SIZE) throw new Error("输出缓冲区太小");

		let processedKey = key;
		if (key.length > BLOCK_SIZE) {
			const hashWriter = new MemoryWriter();
			const [, err] = hashInternal(new MemoryReader(key), rounds, hashWriter);
			if (err) return err;
			processedKey = hashWriter.getResult();
		}
		const keyIpad = new Uint8Array(BLOCK_SIZE);
		const keyOpad = new Uint8Array(BLOCK_SIZE);
		prepareHmacPads(processedKey, keyIpad, keyOpad);

		const innerInitialState = xorStateWithFixed(keyIpad);
		const outerInitialState = xorStateWithFixed(keyOpad);

		const innerHash = new Uint8Array(BLOCK_SIZE);
		const err1 = hashWithState(innerInitialState, data, rounds, innerHash);
		if (err1) return err1;

		return hashWithState(outerInitialState, new MemoryReader(innerHash), rounds, out);
	} catch (error) {
		return error;
	}
}

function hmacInternal(key, data, rounds) {
	const out = new Uint8Array(BLOCK_SIZE);
	const err = hmacTo(key, data, rounds, out);
	return err ? [null, err] : [out, null];
}

function hkdfInternal(masterKey, salt, info, length, rounds) {
	try {
		if (length <= 0 || length > 255 * BLOCK_SIZE) {
			throw new Error(`输出长度必须在 1 到 ${255 * BLOCK_SIZE} 字节之间`);
		}

		let processedSalt = salt || new Uint8Array(BLOCK_SIZE);
		if (processedSalt.length !== BLOCK_SIZE) {
			const hashWriter = new MemoryWriter();
			const [, err] = hashInternal(new MemoryReader(processedSalt), rounds, hashWriter);
			if (err) return [null, err];
			processedSalt = hashWriter.getResult();
		}

		const prk = new Uint8Array(BLOCK_SIZE);
		const err1 = hmacTo(processedSalt, new MemoryReader(masterKey), rounds, prk);
		if (err1) return [null, err1];
		try {
			const numBlocks = Math.ceil(length / BLOCK_SIZE);
			const output = new Uint8Array(length);
			let pos = 0;
			const prevBlock = new Uint8Array(BLOCK_SIZE);
			const currentBlock = new Uint8Array(BLOCK_SIZE);

			for (let i = 1; i <= numBlocks; i++) {
				const blockInput = i === 1
					? new Uint8Array([...info, i])
					: new Uint8Array([...prevBlock, ...info, i]);

				const err2 = hmacTo(prk, new MemoryReader(blockInput), rounds, currentBlock);
				if (err2) return [null, err2];

				const copyLen = Math.min(BLOCK_SIZE, length - pos);
				output.set(currentBlock.subarray(0, copyLen), pos);
				pos += copyLen;
				prevBlock.set(currentBlock);
			}
			return [output, null];
		} finally {
			clearBuffer(prk);
		}
	} catch (error) {
		return [null, error];
	}
}

function pbkdf2Internal(password, salt, iterations, keyLength, rounds) {
	try {
		if (iterations <= 0) throw new Error("迭代次数必须大于0");
		if (keyLength <= 0) throw new Error("密钥长度必须大于0");

		const numBlocks = Math.ceil(keyLength / BLOCK_SIZE);
		const output = new Uint8Array(keyLength);
		let pos = 0;
		const u = new Uint8Array(BLOCK_SIZE);
		const f = new Uint8Array(BLOCK_SIZE);

		try {
			for (let i = 1; i <= numBlocks; i++) {
				const blockInput = new Uint8Array(salt.length + 4);
				blockInput.set(salt, 0);
				writeUint32LE(blockInput, salt.length, i);

				const err1 = hmacTo(password, new MemoryReader(blockInput), rounds, u);
				if (err1) return [null, err1];

				f.set(u);
				for (let j = 1; j < iterations; j++) {
					const err2 = hmacTo(password, new MemoryReader(u), rounds, u);
					if (err2) return [null, err2];
					for (let k = 0; k < BLOCK_SIZE; k++) {
						f[k] ^= u[k];
					}
				}

				const copyLen = Math.min(BLOCK_SIZE, keyLength - pos);
				output.set(f.subarray(0, copyLen), pos);
				pos += copyLen;
			}
			return [output, null];
		} finally {
			clearBuffer(u);
			clearBuffer(f);
		}
	} catch (error) {
		return [null, error];
	}
}

const FlashSwirl = {
	encrypt(mode, key, nonce, data, additionalData = new Uint8Array(0), rounds = 20) {
		const reader = new MemoryReader(data);
		const writer = new MemoryWriter();
		if (mode === 'stream') {
			streamProcess(key, rounds, reader, writer, nonce);
		} else if (mode === 'aead') {
			aeadEncryptInternal(key, nonce, reader, writer, additionalData, rounds);
		} else {
			throw new Error('不支持的加密模式：' + mode);
		}
		return writer.getResult();
	},

	decrypt(mode, key, nonce, data, additionalData = new Uint8Array(0), rounds = 20) {
		const reader = new MemoryReader(data);
		const writer = new MemoryWriter();
		if (mode === 'stream') {
			streamProcess(key, rounds, reader, writer, nonce);
		} else if (mode === 'aead') {
			aeadDecryptInternal(key, nonce, reader, writer, additionalData, rounds);
		} else {
			throw new Error('不支持的解密模式：' + mode);
		}
		return writer.getResult();
	},

	hash(data, rounds = 20) {
		const reader = new MemoryReader(data);
		const [result, err] = hashInternal(reader, rounds);
		if (err) throw err;
		return result;
	},

	hmac(key, data, rounds = 20) {
		const reader = new MemoryReader(data);
		const [result, err] = hmacInternal(key, reader, rounds);
		if (err) throw err;
		return result;
	},

	hkdf(masterKey, salt, info, length, rounds = 20) {
		const [result, err] = hkdfInternal(masterKey, salt, info, length, rounds);
		if (err) throw err;
		return result;
	},

	pbkdf2(password, salt, iterations, keyLength, rounds = 20) {
		const [result, err] = pbkdf2Internal(password, salt, iterations, keyLength, rounds);
		if (err) throw err;
		return result;
	}
};

if (typeof module !== 'undefined' && module.exports) {
	module.exports = FlashSwirl;
} else if (typeof window !== 'undefined') {
	window.FlashSwirl = FlashSwirl;
}
