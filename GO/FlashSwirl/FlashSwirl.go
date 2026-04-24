package FlashSwirl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

const (
	BLOCK_SIZE         = 32       // 算法块大小，单位为字节
	KEY_SIZE           = 32       // 密钥长度，单位为字节
	NONCE_SIZE         = 24       // 随机数长度，单位为字节
	TAG_SIZE           = 16       // AEAD 认证标签长度，单位为字节
	BUFFER_SIZE        = 4 << 20  // 4MB缓冲区
	PARALLEL_THRESHOLD = 64 << 10 // 64KB以上启用并行处理
	CACHE_LINE_SIZE    = 64       // 缓存行大小
	MEMORY_THRESHOLD   = 64 << 20 // 64MB以下使用内存缓冲
)

// 初始状态
var FIXED_INITIAL_STATE = [KEY_SIZE]byte{
	0x46, 0x6c, 0x61, 0x73, 0x68, 0x53, 0x77, 0x69,
	0x72, 0x6c, 0xe9, 0x97, 0xaa, 0xe6, 0x97, 0x8b,
	0x20, 0x46, 0x65, 0x6e, 0x67, 0x5a, 0x68, 0x69,
	0x58, 0x69, 0x61, 0x58, 0x69, 0x61, 0x6e, 0x67,
}

// 缓存的固定初始状态
var cachedFixedState [8]uint32

func init() {
	cachedFixedState = keyToState(FIXED_INITIAL_STATE[:])
}

func expandOutput(input []byte, outputLen int) []byte {
	output := make([]byte, outputLen)
	expandOutputToBuffer(input, output)
	return output
}

func expandOutputToBuffer(input []byte, output []byte) {
	outputLen := len(output)
	state := keyToState(input)
	for r := 0; r < 20; r++ {
		swirlRound(&state)
	}
	outOff := 0
	for outOff < outputLen {
		blockLen := BLOCK_SIZE
		if outputLen-outOff < blockLen {
			blockLen = outputLen - outOff
		}
		for i := 0; i < blockLen; i++ {
			output[outOff+i] = byte((state[i>>2] >> ((i & 3) * 8)) & 0xff)
		}
		outOff += blockLen
		if outOff < outputLen {
			for r := 0; r < 10; r++ {
				swirlRound(&state)
			}
		}
	}
}

func flashSwirlXOF(input []byte, outputLen int) []byte {
	output := make([]byte, outputLen)
	flashSwirlXOFToBuffer(input, output)
	return output
}

func flashSwirlXOFToBuffer(input []byte, output []byte) {
	outputLen := len(output)
	if len(input) <= BLOCK_SIZE {
		expandOutputToBuffer(input, output)
		return
	}

	state := keyToState(input)
	remaining := input[BLOCK_SIZE:]

	for i, b := range remaining {
		byteIdx := i % BLOCK_SIZE
		state[byteIdx>>2] ^= uint32(b) << ((byteIdx & 3) * 8)
	}

	for r := 0; r < 20; r++ {
		swirlRound(&state)
	}

	outOff := 0
	for outOff < outputLen {
		blockLen := BLOCK_SIZE
		if outputLen-outOff < blockLen {
			blockLen = outputLen - outOff
		}
		for i := 0; i < blockLen; i++ {
			output[outOff+i] = byte((state[i>>2] >> ((i & 3) * 8)) & 0xff)
		}
		outOff += blockLen
		if outOff < outputLen {
			for r := 0; r < 10; r++ {
				swirlRound(&state)
			}
		}
	}
}

// 缓冲区池
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, BUFFER_SIZE)
	},
}

// 32字节块缓冲区池
var block32Pool = sync.Pool{
	New: func() interface{} {
		var buf [BLOCK_SIZE]byte
		return &buf
	},
}

// 小缓冲区池
var smallBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 64)
	},
}

// 解密缓冲区池
var decryptBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, BUFFER_SIZE)
	},
}

var pendingPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, BLOCK_SIZE+TAG_SIZE)
	},
}

// ---------------------------- unsafe优化的辅助函数 ----------------------------

func readUint32LE(ptr *byte) uint32 {
	b := (*[4]byte)(unsafe.Pointer(ptr))
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func writeUint32LE(ptr *byte, v uint32) {
	b := (*[4]byte)(unsafe.Pointer(ptr))
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func xorBytes(dst, src []byte, n int) {
	if n == 0 {
		return
	}
	_ = src[n-1]
	_ = dst[n-1]

	dstPtr := unsafe.Pointer(&dst[0])
	srcPtr := unsafe.Pointer(&src[0])

	i := 0
	for ; i+64 <= n; i += 64 {
		pDst := (*[8]uint64)(unsafe.Pointer(uintptr(dstPtr) + uintptr(i)))
		pSrc := (*[8]uint64)(unsafe.Pointer(uintptr(srcPtr) + uintptr(i)))
		pDst[0] ^= pSrc[0]
		pDst[1] ^= pSrc[1]
		pDst[2] ^= pSrc[2]
		pDst[3] ^= pSrc[3]
		pDst[4] ^= pSrc[4]
		pDst[5] ^= pSrc[5]
		pDst[6] ^= pSrc[6]
		pDst[7] ^= pSrc[7]
	}
	for ; i+8 <= n; i += 8 {
		pDst := (*uint64)(unsafe.Pointer(uintptr(dstPtr) + uintptr(i)))
		pSrc := (*uint64)(unsafe.Pointer(uintptr(srcPtr) + uintptr(i)))
		*pDst ^= *pSrc
	}
	for ; i < n; i++ {
		dst[i] ^= src[i]
	}
}

func xorBlock32(dst []byte, offset int, s0, s1, s2, s3, s4, s5, s6, s7 uint32) {
	_ = dst[offset+31]
	ptr := unsafe.Pointer(&dst[offset])

	p := (*[32]byte)(ptr)
	p[0] ^= byte(s0)
	p[1] ^= byte(s0 >> 8)
	p[2] ^= byte(s0 >> 16)
	p[3] ^= byte(s0 >> 24)
	p[4] ^= byte(s1)
	p[5] ^= byte(s1 >> 8)
	p[6] ^= byte(s1 >> 16)
	p[7] ^= byte(s1 >> 24)
	p[8] ^= byte(s2)
	p[9] ^= byte(s2 >> 8)
	p[10] ^= byte(s2 >> 16)
	p[11] ^= byte(s2 >> 24)
	p[12] ^= byte(s3)
	p[13] ^= byte(s3 >> 8)
	p[14] ^= byte(s3 >> 16)
	p[15] ^= byte(s3 >> 24)
	p[16] ^= byte(s4)
	p[17] ^= byte(s4 >> 8)
	p[18] ^= byte(s4 >> 16)
	p[19] ^= byte(s4 >> 24)
	p[20] ^= byte(s5)
	p[21] ^= byte(s5 >> 8)
	p[22] ^= byte(s5 >> 16)
	p[23] ^= byte(s5 >> 24)
	p[24] ^= byte(s6)
	p[25] ^= byte(s6 >> 8)
	p[26] ^= byte(s6 >> 16)
	p[27] ^= byte(s6 >> 24)
	p[28] ^= byte(s7)
	p[29] ^= byte(s7 >> 8)
	p[30] ^= byte(s7 >> 16)
	p[31] ^= byte(s7 >> 24)
}

func validateKey(key []byte) error {
	if len(key) != KEY_SIZE {
		return fmt.Errorf("密钥长度必须为 %d 字节", KEY_SIZE)
	}
	return nil
}

func validateNonce(nonce []byte) error {
	if len(nonce) != NONCE_SIZE {
		return fmt.Errorf("随机Nonce长度必须为 %d 字节", NONCE_SIZE)
	}
	return nil
}

func validateKeyAndNonce(key, nonce []byte) error {
	if err := validateKey(key); err != nil {
		return err
	}
	return validateNonce(nonce)
}

func clearBuffer(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}

func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}
	return result == 0
}

func boolToUint64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// ---------------------------- 核心运算函数 ----------------------------

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

func swirlRound(state *[8]uint32) {
	s0, s1, s2, s3 := quarterRound(state[0], state[1], state[2], state[3])
	s4, s5, s6, s7 := quarterRound(state[4], state[5], state[6], state[7])
	s0, s5, s2, s7 = quarterRound(s0, s5, s2, s7)
	s1, s4, s3, s6 = quarterRound(s1, s4, s3, s6)
	state[0], state[1], state[2], state[3] = s0, s1, s2, s3
	state[4], state[5], state[6], state[7] = s4, s5, s6, s7
}

func swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7 uint32) (uint32, uint32, uint32, uint32, uint32, uint32, uint32, uint32) {
	s0, s1, s2, s3 = quarterRound(s0, s1, s2, s3)
	s4, s5, s6, s7 = quarterRound(s4, s5, s6, s7)
	s0, s5, s2, s7 = quarterRound(s0, s5, s2, s7)
	s1, s4, s3, s6 = quarterRound(s1, s4, s3, s6)
	return s0, s1, s2, s3, s4, s5, s6, s7
}

func normalizeRounds(rounds int) int {
	if rounds == 8 || rounds == 20 {
		return rounds / 2
	}
	return 10
}

func applySwirlRounds(state *[8]uint32, rounds int) {
	rounds = normalizeRounds(rounds)
	s0, s1, s2, s3 := state[0], state[1], state[2], state[3]
	s4, s5, s6, s7 := state[4], state[5], state[6], state[7]

	for rounds >= 4 {
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		rounds -= 4
	}
	for rounds > 0 {
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		rounds--
	}

	state[0], state[1], state[2], state[3] = s0, s1, s2, s3
	state[4], state[5], state[6], state[7] = s4, s5, s6, s7
}

func keyToState(key []byte) [8]uint32 {
	var state [8]uint32
	if len(key) >= 32 {
		ptr := unsafe.Pointer(&key[0])
		state[0] = readUint32LE((*byte)(ptr))
		state[1] = readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr) + 4)))
		state[2] = readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr) + 8)))
		state[3] = readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr) + 12)))
		state[4] = readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr) + 16)))
		state[5] = readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr) + 20)))
		state[6] = readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr) + 24)))
		state[7] = readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr) + 28)))
	} else {
		for i := 0; i < 8; i++ {
			offset := i * 4
			if offset+4 <= len(key) {
				state[i] = readUint32LE(&key[offset])
			} else {
				var tmp uint32
				for j := 0; j < 4; j++ {
					if offset+j < len(key) {
						tmp |= uint32(key[offset+j]) << (j * 8)
					}
				}
				state[i] = tmp
			}
		}
	}
	return state
}

func stateToBytesWithBuffer(state [8]uint32, buffer []byte) []byte {
	ptr := unsafe.Pointer(&buffer[0])
	writeUint32LE((*byte)(ptr), state[0])
	writeUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+4)), state[1])
	writeUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+8)), state[2])
	writeUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+12)), state[3])
	writeUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+16)), state[4])
	writeUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+20)), state[5])
	writeUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+24)), state[6])
	writeUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+28)), state[7])
	return buffer
}

// ---------------------------- 基础状态生成 ----------------------------
func makeBaseNonce(key []byte, nonce []byte) ([8]uint32, error) {
	if err := validateKeyAndNonce(key, nonce); err != nil {
		return [8]uint32{}, err
	}
	var baseNonceBytes [BLOCK_SIZE]byte
	for i := 0; i < BLOCK_SIZE; i++ {
		var nonceByte byte
		if i < NONCE_SIZE {
			nonceByte = nonce[i]
		}
		baseNonceBytes[i] = FIXED_INITIAL_STATE[i] ^ key[i] ^ nonceByte
	}
	baseNonce := keyToState(baseNonceBytes[:])
	return baseNonce, nil
}

// ---------------------------- 密钥流生成 ----------------------------
func generateKeystreamBlock(baseNonce [8]uint32, counter uint64, rounds int) [BLOCK_SIZE]byte {
	state := baseNonce
	state[6] ^= uint32(counter >> 32)
	state[7] ^= uint32(counter)
	original := state
	applySwirlRounds(&state, rounds)
	for i := 0; i < 8; i++ {
		state[i] += original[i]
	}
	var keystream [BLOCK_SIZE]byte
	stateToBytesWithBuffer(state, keystream[:])
	return keystream
}

// ---------------------------- 流加密/解密核心 ----------------------------
func processKeystreamBlocksBatch(baseNonce [8]uint32, counter uint64, normalizedRounds int, dst []byte) uint64 {
	numBlocks := len(dst) / BLOCK_SIZE
	if numBlocks == 0 {
		return counter
	}
	_ = dst[BLOCK_SIZE*numBlocks-1]
	_ = dst[0]

	i := 0
	for ; i+3 < numBlocks; i += 4 {
		s0_0, s1_0, s2_0, s3_0 := baseNonce[0], baseNonce[1], baseNonce[2], baseNonce[3]
		s4_0, s5_0, s6_0, s7_0 := baseNonce[4], baseNonce[5], baseNonce[6], baseNonce[7]
		s6_0 ^= uint32((counter + uint64(i)) >> 32)
		s7_0 ^= uint32(counter + uint64(i))
		o0_0, o1_0, o2_0, o3_0, o4_0, o5_0, o6_0, o7_0 := s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0

		s0_1, s1_1, s2_1, s3_1 := baseNonce[0], baseNonce[1], baseNonce[2], baseNonce[3]
		s4_1, s5_1, s6_1, s7_1 := baseNonce[4], baseNonce[5], baseNonce[6], baseNonce[7]
		s6_1 ^= uint32((counter + uint64(i+1)) >> 32)
		s7_1 ^= uint32(counter + uint64(i+1))
		o0_1, o1_1, o2_1, o3_1, o4_1, o5_1, o6_1, o7_1 := s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1

		s0_2, s1_2, s2_2, s3_2 := baseNonce[0], baseNonce[1], baseNonce[2], baseNonce[3]
		s4_2, s5_2, s6_2, s7_2 := baseNonce[4], baseNonce[5], baseNonce[6], baseNonce[7]
		s6_2 ^= uint32((counter + uint64(i+2)) >> 32)
		s7_2 ^= uint32(counter + uint64(i+2))
		o0_2, o1_2, o2_2, o3_2, o4_2, o5_2, o6_2, o7_2 := s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2

		s0_3, s1_3, s2_3, s3_3 := baseNonce[0], baseNonce[1], baseNonce[2], baseNonce[3]
		s4_3, s5_3, s6_3, s7_3 := baseNonce[4], baseNonce[5], baseNonce[6], baseNonce[7]
		s6_3 ^= uint32((counter + uint64(i+3)) >> 32)
		s7_3 ^= uint32(counter + uint64(i+3))
		o0_3, o1_3, o2_3, o3_3, o4_3, o5_3, o6_3, o7_3 := s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3

		r := normalizedRounds
		for r >= 4 {
			s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0 = swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0)
			s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1 = swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1)
			s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2 = swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2)
			s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3 = swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3)
			s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0 = swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0)
			s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1 = swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1)
			s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2 = swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2)
			s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3 = swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3)
			s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0 = swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0)
			s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1 = swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1)
			s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2 = swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2)
			s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3 = swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3)
			s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0 = swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0)
			s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1 = swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1)
			s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2 = swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2)
			s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3 = swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3)
			r -= 4
		}
		for r > 0 {
			s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0 = swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0)
			s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1 = swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1)
			s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2 = swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2)
			s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3 = swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3)
			r--
		}

		xorBlock32(dst, (i+0)*BLOCK_SIZE, s0_0+o0_0, s1_0+o1_0, s2_0+o2_0, s3_0+o3_0, s4_0+o4_0, s5_0+o5_0, s6_0+o6_0, s7_0+o7_0)
		xorBlock32(dst, (i+1)*BLOCK_SIZE, s0_1+o0_1, s1_1+o1_1, s2_1+o2_1, s3_1+o3_1, s4_1+o4_1, s5_1+o5_1, s6_1+o6_1, s7_1+o7_1)
		xorBlock32(dst, (i+2)*BLOCK_SIZE, s0_2+o0_2, s1_2+o1_2, s2_2+o2_2, s3_2+o3_2, s4_2+o4_2, s5_2+o5_2, s6_2+o6_2, s7_2+o7_2)
		xorBlock32(dst, (i+3)*BLOCK_SIZE, s0_3+o0_3, s1_3+o1_3, s2_3+o2_3, s3_3+o3_3, s4_3+o4_3, s5_3+o5_3, s6_3+o6_3, s7_3+o7_3)
	}

	for ; i < numBlocks; i++ {
		s0 := baseNonce[0]
		s1 := baseNonce[1]
		s2 := baseNonce[2]
		s3 := baseNonce[3]
		s4 := baseNonce[4]
		s5 := baseNonce[5]
		s6 := baseNonce[6] ^ uint32((counter+uint64(i))>>32)
		s7 := baseNonce[7] ^ uint32(counter+uint64(i))
		o0, o1, o2, o3, o4, o5, o6, o7 := s0, s1, s2, s3, s4, s5, s6, s7

		r := normalizedRounds
		for r >= 4 {
			s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
			s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
			s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
			s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
			r -= 4
		}
		for r > 0 {
			s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
			r--
		}

		xorBlock32(dst, i*BLOCK_SIZE, s0+o0, s1+o1, s2+o2, s3+o3, s4+o4, s5+o5, s6+o6, s7+o7)
	}

	return counter + uint64(numBlocks)
}

func getOptimalWorkerCount(dataSize int) int {
	cpuCount := runtime.NumCPU()
	if cpuCount <= 1 {
		return 1
	}
	blocks := dataSize / BLOCK_SIZE
	if blocks < cpuCount*4 {
		return 1
	}
	if blocks < cpuCount*16 {
		return cpuCount / 2
	}
	if cpuCount > 8 {
		return 8
	}
	return cpuCount
}

func processKeystreamBlocksParallel(baseNonce [8]uint32, counter uint64, rounds int, dst []byte) uint64 {
	numBlocks := len(dst) / BLOCK_SIZE
	if numBlocks == 0 {
		return counter
	}

	workers := getOptimalWorkerCount(len(dst))
	if workers <= 1 {
		return processKeystreamBlocksBatch(baseNonce, counter, normalizeRounds(rounds), dst)
	}

	blocksPerWorker := (numBlocks + workers - 1) / workers
	normalizedRounds := normalizeRounds(rounds)
	_ = dst[BLOCK_SIZE*numBlocks-1]
	_ = dst[0]
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		startBlock := w * blocksPerWorker
		endBlock := startBlock + blocksPerWorker
		if endBlock > numBlocks {
			endBlock = numBlocks
		}
		if startBlock >= numBlocks {
			wg.Done()
			continue
		}

		go func(startIdx, endIdx int, startCounter uint64) {
			defer wg.Done()
			chunkSize := (endIdx - startIdx) * BLOCK_SIZE
			processKeystreamBlocksBatch(baseNonce, startCounter, normalizedRounds, dst[startIdx*BLOCK_SIZE:startIdx*BLOCK_SIZE+chunkSize])
		}(startBlock, endBlock, counter+uint64(startBlock))
	}

	wg.Wait()
	return counter + uint64(numBlocks)
}

func streamProcess(key []byte, rounds int, input io.Reader, output io.Writer, randomNonce []byte) error {
	baseNonce, err := makeBaseNonce(key, randomNonce)
	if err != nil {
		return err
	}
	defer func() {
		for i := range baseNonce {
			baseNonce[i] = 0
		}
	}()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	buffer := buf[:BUFFER_SIZE]

	counter := uint64(0)

	for {
		n, err := input.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		fullBlocks := n / BLOCK_SIZE
		if fullBlocks > 0 {
			if n >= PARALLEL_THRESHOLD {
				counter = processKeystreamBlocksParallel(baseNonce, counter, rounds, buffer[:fullBlocks*BLOCK_SIZE])
			} else {
				counter = processKeystreamBlocksBatch(baseNonce, counter, normalizeRounds(rounds), buffer[:fullBlocks*BLOCK_SIZE])
			}
		}

		remaining := n % BLOCK_SIZE
		if remaining > 0 {
			keystream := generateKeystreamBlock(baseNonce, counter, rounds)
			xorBytes(buffer[fullBlocks*BLOCK_SIZE:], keystream[:], remaining)
			counter++
		}

		if _, err := output.Write(buffer[:n]); err != nil {
			return err
		}
	}
	return nil
}

// Encrypt 流加密
func Encrypt(key []byte, randomNonce []byte, input io.Reader, output io.Writer, rounds int) error {
	return streamProcess(key, rounds, input, output, randomNonce)
}

// Decrypt 流解密
func Decrypt(key []byte, randomNonce []byte, input io.Reader, output io.Writer, rounds int) error {
	return streamProcess(key, rounds, input, output, randomNonce)
}

// ---------------------------- AEAD 相关 ----------------------------
func deriveKeys(masterKey []byte, rounds int) (encryptionKey, authKey []byte, err error) {
	if err := validateKey(masterKey); err != nil {
		return nil, nil, err
	}
	normalizedRounds := normalizeRounds(rounds)
	encryptionKey, err = HKDF(masterKey, nil, []byte("aead-key"), BLOCK_SIZE, normalizedRounds)
	if err != nil {
		return nil, nil, err
	}
	authKey, err = HKDF(masterKey, nil, []byte("tag-key"), BLOCK_SIZE, normalizedRounds)
	if err != nil {
		clearBuffer(encryptionKey)
		return nil, nil, err
	}
	return encryptionKey, authKey, nil
}

func prepareHmacPads(authKey []byte, rounds int) ([BLOCK_SIZE]byte, [BLOCK_SIZE]byte, error) {
	var ipad, opad [BLOCK_SIZE]byte
	key := authKey
	if len(key) > BLOCK_SIZE {
		hashedKey, err := Hash(bytes.NewReader(key), rounds)
		if err != nil {
			return ipad, opad, err
		}
		key = hashedKey
	}
	for i := 0; i < BLOCK_SIZE; i++ {
		if i < len(key) {
			ipad[i] = key[i] ^ 0x36
			opad[i] = key[i] ^ 0x5C
		} else {
			ipad[i] = 0x36
			opad[i] = 0x5C
		}
	}
	return ipad, opad, nil
}

type hashState struct {
	state      [8]uint32
	pending    [2 * BLOCK_SIZE]byte
	pendingLen int
	total      uint64
	rounds     int
	direct     bool
}

func (h *hashState) Clear() {
	for i := range h.state {
		h.state[i] = 0
	}
	for i := range h.pending {
		h.pending[i] = 0
	}
	h.pendingLen = 0
	h.total = 0
	runtime.KeepAlive(h)
}

func newHashStateWithRounds(key []byte, normalizedRounds int, direct bool) *hashState {
	keyState := keyToState(key)
	var state [8]uint32
	for i := 0; i < 8; i++ {
		state[i] = cachedFixedState[i] ^ keyState[i]
	}
	return &hashState{
		state:  state,
		rounds: normalizedRounds,
		direct: direct,
	}
}

func (h *hashState) write(data []byte) {
	h.total += uint64(len(data))
	if h.pendingLen > 0 {
		need := BLOCK_SIZE - h.pendingLen
		if len(data) >= need {
			copy(h.pending[h.pendingLen:], data[:need])
			compress(&h.state, h.pending[:BLOCK_SIZE], h.rounds, !h.direct)
			h.pendingLen = 0
			data = data[need:]
		} else {
			copy(h.pending[h.pendingLen:], data)
			h.pendingLen += len(data)
			return
		}
	}
	for len(data) >= BLOCK_SIZE {
		compress(&h.state, data[:BLOCK_SIZE], h.rounds, !h.direct)
		data = data[BLOCK_SIZE:]
	}
	if len(data) > 0 {
		copy(h.pending[:], data)
		h.pendingLen = len(data)
	}
}

func (h *hashState) sum() []byte {
	state := h.state
	pending := h.pending
	pendingLen := h.pendingLen
	total := h.total

	pending[pendingLen] = 0x80
	pendingLen++
	pad := (BLOCK_SIZE - (pendingLen+8)%BLOCK_SIZE) % BLOCK_SIZE
	for i := 0; i < pad; i++ {
		pending[pendingLen] = 0
		pendingLen++
	}
	binary.LittleEndian.PutUint64(pending[pendingLen:], total*8)
	pendingLen += 8

	for i := 0; i < pendingLen; i += BLOCK_SIZE {
		compress(&state, pending[i:i+BLOCK_SIZE], h.rounds, !h.direct)
	}

	var out [BLOCK_SIZE]byte
	stateToBytesWithBuffer(state, out[:])
	return out[:]
}

// AEAD加密
func EncryptAEAD(key []byte, randomNonce []byte, input io.Reader, output io.Writer, additionalData []byte, rounds int) error {
	if err := validateKeyAndNonce(key, randomNonce); err != nil {
		return err
	}

	encryptionKey, authKey, err := deriveKeys(key, rounds)
	if err != nil {
		return err
	}
	defer clearBuffer(encryptionKey)
	defer clearBuffer(authKey)

	ipad, opad, err := prepareHmacPads(authKey, rounds)
	if err != nil {
		return err
	}

	baseNonce, err := makeBaseNonce(encryptionKey, randomNonce)
	if err != nil {
		return err
	}
	defer func() {
		for i := range baseNonce {
			baseNonce[i] = 0
		}
	}()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	buffer := buf[:BUFFER_SIZE]

	counter := uint64(0)
	normalizedRounds := normalizeRounds(rounds)
	hashRounds := normalizedRounds / 2
	if hashRounds < 1 {
		hashRounds = 1
	}

	innerState := newHashStateWithRounds(ipad[:], hashRounds, true)
	innerState.write(additionalData)

	for {
		n, err := input.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		fullBlocks := n / BLOCK_SIZE
		if fullBlocks > 0 {
			if n >= PARALLEL_THRESHOLD {
				counter = processKeystreamBlocksParallel(baseNonce, counter, rounds, buffer[:fullBlocks*BLOCK_SIZE])
			} else {
				counter = processKeystreamBlocksBatch(baseNonce, counter, normalizedRounds, buffer[:fullBlocks*BLOCK_SIZE])
			}
			innerState.write(buffer[:fullBlocks*BLOCK_SIZE])
		}

		remaining := n % BLOCK_SIZE
		if remaining > 0 {
			keystream := generateKeystreamBlock(baseNonce, counter, rounds)
			dst := buffer[fullBlocks*BLOCK_SIZE : fullBlocks*BLOCK_SIZE+remaining]
			xorBytes(dst, keystream[:], remaining)
			innerState.write(dst)
			counter++
		}

		if _, err := output.Write(buffer[:n]); err != nil {
			return err
		}
	}

	innerHash := innerState.sum()
	outer := newHashStateWithRounds(opad[:], hashRounds, true)
	outer.write(innerHash)
	tag := outer.sum()[:TAG_SIZE]

	if _, err := output.Write(tag); err != nil {
		return err
	}
	return nil
}

// AEAD解密
func DecryptAEAD(key []byte, randomNonce []byte, input io.Reader, output io.Writer, additionalData []byte, rounds int) (bool, error) {
	if err := validateKeyAndNonce(key, randomNonce); err != nil {
		return false, err
	}

	encryptionKey, authKey, err := deriveKeys(key, rounds)
	if err != nil {
		return false, err
	}
	defer clearBuffer(encryptionKey)
	defer clearBuffer(authKey)

	ipad, opad, err := prepareHmacPads(authKey, rounds)
	if err != nil {
		return false, err
	}

	normalizedRounds := normalizeRounds(rounds)
	hashRounds := normalizedRounds / 2
	if hashRounds < 1 {
		hashRounds = 1
	}

	inner := newHashStateWithRounds(ipad[:], hashRounds, true)
	inner.write(additionalData)

	baseNonce, err := makeBaseNonce(encryptionKey, randomNonce)
	if err != nil {
		return false, err
	}
	defer func() {
		for i := range baseNonce {
			baseNonce[i] = 0
		}
	}()

	memoryBuffer := make([]byte, 0, MEMORY_THRESHOLD)
	var tmpFile *os.File
	var tmpFileName string
	useTempFile := false

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	readBuffer := buf[:BUFFER_SIZE]
	decryptBuffer := decryptBufPool.Get().([]byte)[:BUFFER_SIZE]
	defer decryptBufPool.Put(decryptBuffer)

	pendingTail := pendingPool.Get().([]byte)[:0]
	defer pendingPool.Put(pendingTail)
	combinedBuf := bufferPool.Get().([]byte)
	defer bufferPool.Put(combinedBuf)
	totalPlaintextLen := int64(0)
	counter := uint64(0)

	for {
		n, readErr := input.Read(readBuffer)
		if readErr != nil && readErr != io.EOF {
			return false, readErr
		}
		if n == 0 {
			break
		}

		var processData []byte
		if len(pendingTail) > 0 {
			combinedLen := len(pendingTail) + n
			if cap(combinedBuf) < combinedLen {
				combinedBuf = make([]byte, combinedLen)
			}
			combined := combinedBuf[:combinedLen]
			copy(combined, pendingTail)
			copy(combined[len(pendingTail):], readBuffer[:n])
			processData = combined
			pendingTail = pendingTail[:0]
		} else {
			processData = readBuffer[:n]
		}

		if len(processData) <= TAG_SIZE {
			pendingTail = append(pendingTail, processData...)
			continue
		}

		ciphertextLen := len(processData) - TAG_SIZE
		remainingBytes := ciphertextLen % BLOCK_SIZE
		processableLen := ciphertextLen - remainingBytes
		plaintextLen := processableLen
		inner.write(processData[:processableLen])
		copy(decryptBuffer, processData[:processableLen])

		fullBlocks := processableLen / BLOCK_SIZE
		if fullBlocks > 0 {
			if processableLen >= PARALLEL_THRESHOLD {
				counter = processKeystreamBlocksParallel(baseNonce, counter, rounds, decryptBuffer[:fullBlocks*BLOCK_SIZE])
			} else {
				counter = processKeystreamBlocksBatch(baseNonce, counter, normalizedRounds, decryptBuffer[:fullBlocks*BLOCK_SIZE])
			}
		}

		if !useTempFile && totalPlaintextLen+int64(plaintextLen) <= int64(MEMORY_THRESHOLD) {
			memoryBuffer = append(memoryBuffer, decryptBuffer[:plaintextLen]...)
		} else {
			if !useTempFile {
				useTempFile = true
				tmpFile, err = os.CreateTemp("", "flashswirl_*.tmp")
				if err != nil {
					return false, err
				}
				tmpFileName = tmpFile.Name()
				defer os.Remove(tmpFileName)
				defer tmpFile.Close()

				if len(memoryBuffer) > 0 {
					if _, writeErr := tmpFile.Write(memoryBuffer); writeErr != nil {
						return false, writeErr
					}
				}
				memoryBuffer = nil
			}
			if _, writeErr := tmpFile.Write(decryptBuffer[:plaintextLen]); writeErr != nil {
				return false, writeErr
			}
		}

		totalPlaintextLen += int64(plaintextLen)
		pendingTail = append(pendingTail, processData[processableLen:]...)
	}

	if len(pendingTail) < TAG_SIZE {
		return false, fmt.Errorf("输入数据的大小错误")
	}

	finalRemaining := len(pendingTail) - TAG_SIZE
	if finalRemaining > 0 {
		inner.write(pendingTail[:finalRemaining])
	}
	expectedTag := pendingTail[finalRemaining:]

	innerHash := inner.sum()
	outer := newHashStateWithRounds(opad[:], hashRounds, true)
	outer.write(innerHash)
	computedTag := outer.sum()[:TAG_SIZE]

	if !constantTimeCompare(computedTag, expectedTag) {
		return false, nil
	}

	if finalRemaining > 0 {
		keystream := generateKeystreamBlock(baseNonce, counter, rounds)
		xorBytes(pendingTail[:finalRemaining], keystream[:], finalRemaining)
		counter++

		if !useTempFile && totalPlaintextLen+int64(finalRemaining) <= int64(MEMORY_THRESHOLD) {
			memoryBuffer = append(memoryBuffer, pendingTail[:finalRemaining]...)
		} else {
			if !useTempFile {
				useTempFile = true
				tmpFile, err = os.CreateTemp("", "flashswirl_*.tmp")
				if err != nil {
					return false, err
				}
				tmpFileName = tmpFile.Name()
				defer os.Remove(tmpFileName)
				defer tmpFile.Close()

				if len(memoryBuffer) > 0 {
					if _, writeErr := tmpFile.Write(memoryBuffer); writeErr != nil {
						return false, writeErr
					}
				}
				memoryBuffer = nil
			}
			if _, writeErr := tmpFile.Write(pendingTail[:finalRemaining]); writeErr != nil {
				return false, writeErr
			}
		}
		totalPlaintextLen += int64(finalRemaining)
	}

	if useTempFile && tmpFile != nil {
		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
	}

	remainingToWrite := totalPlaintextLen
	memoryPos := int64(0)

	for remainingToWrite > 0 {
		chunkSize := int(BUFFER_SIZE)
		if remainingToWrite < int64(chunkSize) {
			chunkSize = int(remainingToWrite)
		}

		var writeData []byte
		if !useTempFile {
			writeData = memoryBuffer[memoryPos : memoryPos+int64(chunkSize)]
			memoryPos += int64(chunkSize)
		} else {
			readCount, readErr := io.ReadFull(tmpFile, decryptBuffer[:chunkSize])
			if readErr != nil || readCount != chunkSize {
				return false, fmt.Errorf("临时文件读取错误")
			}
			writeData = decryptBuffer[:chunkSize]
		}

		if _, writeErr := output.Write(writeData); writeErr != nil {
			return false, writeErr
		}

		remainingToWrite -= int64(chunkSize)
	}

	return true, nil
}

// ---------------------------- 哈希与MAC函数 ----------------------------
func compress(state *[8]uint32, block []byte, rounds int, normalize bool) {
	ptr := unsafe.Pointer(&block[0])
	s0 := state[0] ^ readUint32LE((*byte)(ptr))
	s1 := state[1] ^ readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+4)))
	s2 := state[2] ^ readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+8)))
	s3 := state[3] ^ readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+12)))
	s4 := state[4] ^ readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+16)))
	s5 := state[5] ^ readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+20)))
	s6 := state[6] ^ readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+24)))
	s7 := state[7] ^ readUint32LE((*byte)(unsafe.Pointer(uintptr(ptr)+28)))

	o0, o1, o2, o3, o4, o5, o6, o7 := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]

	r := rounds
	if normalize {
		r = normalizeRounds(rounds)
	}

	for r >= 4 {
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		r -= 4
	}
	for r > 0 {
		s0, s1, s2, s3, s4, s5, s6, s7 = swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7)
		r--
	}

	state[0] = o0 ^ s0
	state[1] = o1 ^ s1
	state[2] = o2 ^ s2
	state[3] = o3 ^ s3
	state[4] = o4 ^ s4
	state[5] = o5 ^ s5
	state[6] = o6 ^ s6
	state[7] = o7 ^ s7
}

func hashWithState(initialState [8]uint32, input io.Reader, rounds int, out []byte) error {
	state := initialState

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	buffer := buf[:BUFFER_SIZE]

	var pending [2 * BLOCK_SIZE]byte
	pendingLen := 0
	totalBytes := uint64(0)

	for {
		n, err := input.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 && err == io.EOF {
			break
		}
		totalBytes += uint64(n)

		src := buffer[:n]
		for len(src) > 0 {
			space := BLOCK_SIZE - pendingLen
			copyLen := len(src)
			if copyLen > space {
				copyLen = space
			}
			copy(pending[pendingLen:], src[:copyLen])
			pendingLen += copyLen
			src = src[copyLen:]

			if pendingLen == BLOCK_SIZE {
				compress(&state, pending[:BLOCK_SIZE], rounds, true)
				pendingLen = 0
			}
		}
	}

	totalBits := totalBytes * 8
	pending[pendingLen] = 0x80
	pendingLen++
	pad := (BLOCK_SIZE - (pendingLen+8)%BLOCK_SIZE) % BLOCK_SIZE
	for i := 0; i < pad; i++ {
		pending[pendingLen] = 0
		pendingLen++
	}
	binary.LittleEndian.PutUint64(pending[pendingLen:], totalBits)
	pendingLen += 8

	for i := 0; i < pendingLen; i += BLOCK_SIZE {
		compress(&state, pending[i:i+BLOCK_SIZE], rounds, true)
	}

	stateToBytesWithBuffer(state, out)
	return nil
}

func Hash(input io.Reader, rounds int) ([]byte, error) {
	out := make([]byte, BLOCK_SIZE)
	err := hashWithState(cachedFixedState, input, rounds, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func hmacTo(key []byte, data io.Reader, rounds int, out []byte) error {
	if len(out) < BLOCK_SIZE {
		return fmt.Errorf("输出缓冲区太小")
	}

	keyIpad, keyOpad, err := prepareHmacPads(key, rounds)
	if err != nil {
		return err
	}

	keyState := keyToState(keyIpad[:])
	var innerInitialState [8]uint32
	for i := 0; i < 8; i++ {
		innerInitialState[i] = cachedFixedState[i] ^ keyState[i]
	}

	keyState = keyToState(keyOpad[:])
	var outerInitialState [8]uint32
	for i := 0; i < 8; i++ {
		outerInitialState[i] = cachedFixedState[i] ^ keyState[i]
	}

	var innerHash [BLOCK_SIZE]byte
	if err := hashWithState(innerInitialState, data, rounds, innerHash[:]); err != nil {
		return err
	}

	return hashWithState(outerInitialState, bytes.NewReader(innerHash[:]), rounds, out)
}

func HMAC(key []byte, data io.Reader, rounds int) ([]byte, error) {
	out := make([]byte, BLOCK_SIZE)
	err := hmacTo(key, data, rounds, out)
	return out, err
}

func HKDF(masterKey []byte, salt []byte, info []byte, length int, rounds int) ([]byte, error) {
	if length <= 0 || length > 255*BLOCK_SIZE {
		return nil, fmt.Errorf("输出长度必须在 1 到 %d 字节之间", 255*BLOCK_SIZE)
	}

	if len(salt) == 0 {
		salt = make([]byte, BLOCK_SIZE)
	}
	if len(salt) != BLOCK_SIZE {
		saltReader := bytes.NewReader(salt)
		hashedSalt, err := Hash(saltReader, rounds)
		if err != nil {
			return nil, err
		}
		salt = hashedSalt
	}

	prk := make([]byte, BLOCK_SIZE)
	if err := hmacTo(salt, bytes.NewReader(masterKey), rounds, prk); err != nil {
		return nil, err
	}
	defer clearBuffer(prk)

	numBlocks := (length + BLOCK_SIZE - 1) / BLOCK_SIZE
	output := make([]byte, length)
	pos := 0
	var prevBlock [BLOCK_SIZE]byte
	var currentBlock [BLOCK_SIZE]byte

	for i := 1; i <= numBlocks; i++ {
		blockInput := make([]byte, 0, len(info)+1+BLOCK_SIZE)
		if i == 1 {
			blockInput = append(blockInput, info...)
			blockInput = append(blockInput, byte(i))
		} else {
			blockInput = append(blockInput, prevBlock[:]...)
			blockInput = append(blockInput, info...)
			blockInput = append(blockInput, byte(i))
		}

		if err := hmacTo(prk, bytes.NewReader(blockInput), rounds, currentBlock[:]); err != nil {
			return nil, err
		}

		copy(output[pos:], currentBlock[:])
		pos += BLOCK_SIZE
		copy(prevBlock[:], currentBlock[:])
	}

	return output[:length], nil
}

func PBKDF2(password, salt []byte, iterations int, keyLength int, rounds int) ([]byte, error) {
	if iterations <= 0 {
		return nil, fmt.Errorf("迭代次数必须大于0")
	}
	if keyLength <= 0 {
		return nil, fmt.Errorf("密钥长度必须大于0")
	}

	numBlocks := (keyLength + BLOCK_SIZE - 1) / BLOCK_SIZE
	output := make([]byte, keyLength)
	pos := 0

	var u [BLOCK_SIZE]byte
	var f [BLOCK_SIZE]byte

	defer func() {
		for k := range u {
			u[k] = 0
		}
		for k := range f {
			f[k] = 0
		}
	}()

	for i := 1; i <= numBlocks; i++ {
		blockInput := make([]byte, len(salt)+4)
		copy(blockInput, salt)
		binary.LittleEndian.PutUint32(blockInput[len(salt):], uint32(i))

		if err := hmacTo(password, bytes.NewReader(blockInput), rounds, u[:]); err != nil {
			return nil, err
		}

		copy(f[:], u[:])

		for j := 1; j < iterations; j++ {
			if err := hmacTo(password, bytes.NewReader(u[:]), rounds, u[:]); err != nil {
				return nil, err
			}
			for k := 0; k < BLOCK_SIZE; k++ {
				f[k] ^= u[k]
			}
		}

		copyLen := BLOCK_SIZE
		if pos+copyLen > keyLength {
			copyLen = keyLength - pos
		}
		copy(output[pos:], f[:copyLen])
		pos += copyLen
	}

	return output, nil
}
