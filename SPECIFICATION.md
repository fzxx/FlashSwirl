# FlashSwirl 闪旋算法规范

**版本**: 1.1  
**作者**: 风之暇想  
**日期**: 2026-04-23

---

## 1. 概述

FlashSwirl（闪旋）是一种基于ARX（Add-Rotate-XOR）结构的对称加密算法，灵感来源于ChaCha20，但采用了不同的状态混合策略。

### 1.1 设计目标

- **高性能**: 批量处理、并行计算、内存池优化
- **高安全性**: 256位密钥，支持8轮和20轮运算
- **多功能**: 支持流加密、AEAD认证加密、哈希、HMAC、密钥派生
- **跨平台**: C++、Go、JavaScript三种语言实现

### 1.2 算法特点

| 特性 | 描述 |
|------|------|
| 结构 | ARX (Add-Rotate-XOR) |
| 状态大小 | 256位 (8×32位字) |
| 块大小 | 256位 (32字节) |
| 密钥长度 | 256位 (32字节) |
| Nonce长度 | 192位 (24字节) |
| AEAD标签 | 128位 (16字节) |
| 支持轮数 | 8轮(快速) / 20轮(标准) |
| 字节序 | 小端序 (Little-Endian) |

---

## 2. 算法参数

### 2.1 常量定义

```c
#define BLOCK_SIZE         32       // 算法块大小，单位为字节
#define KEY_SIZE           32       // 密钥长度，单位为字节
#define NONCE_SIZE         24       // 随机数长度，单位为字节
#define TAG_SIZE           16       // AEAD 认证标签长度，单位为字节
```

### 2.2 固定初始状态

算法使用一个固定的32字节初始状态（常量），用于初始化哈希和密钥派生：

```
固定初始状态 (十六进制):
46 6c 61 73 68 53 77 69 72 6c e9 97 aa e6 97 8b
20 46 65 6e 67 5a 68 69 58 69 61 58 69 61 6e 67

明文：
FlashSwirl闪旋 FengZhiXiaXiang
```

### 2.3 轮数规范

| 模式 | 轮数 | 用途 |
|------|------|------|
| FlashSwirl-8 | 8轮 | 高性能场景，速度优先 |
| FlashSwirl-20 | 20轮 | 标准安全级别，推荐默认使用 |

---

## 3. 数据结构

### 3.1 状态表示

算法内部状态由8个32位无符号整数组成：

```
状态: [s0, s1, s2, s3, s4, s5, s6, s7]
      每个 si 是 32位无符号整数 (uint32)
```

状态内存布局（小端序）：
```
字节偏移:  0  1  2  3   4  5  6  7   8  9 10 11  12 13 14 15
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
          |     s0      |     s1      |     s2      |     s3      |
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

字节偏移: 16 17 18 19  20 21 22 23  24 25 26 27  28 29 30 31
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
          |     s4      |     s5      |     s6      |     s7      |
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### 3.2 密钥格式

密钥为32字节数组：
```
K = [k0, k1, k2, ..., k31]
```

### 3.3 Nonce格式

Nonce为24字节数组：
```
N = [n0, n1, n2, ..., n23]
```

**重要**: Nonce必须使用密码学安全的随机数生成器生成，且每个密钥只能使用一次。

---

## 4. 核心运算

### 4.1 Quarter Round（四分之一轮）

Quarter Round是算法的基本运算单元，操作4个32位字：

```
输入: (a, b, c, d)
输出: (a', b', c', d')

a = a + b
d = (d XOR a) <<< 16
c = c + d
b = (b XOR c) <<< 12
a = a + b
d = (d XOR a) <<< 8
c = c + d
b = (b XOR c) <<< 7

返回: (a, b, c, d)
```

其中:
- `+` 表示模 2^32 加法
- `XOR` 表示按位异或
- `<<< n` 表示循环左移n位

### 4.2 Swirl Round（闪旋轮）

Swirl Round是算法的完整轮函数，由4个Quarter Round组成：

```
输入: 状态 [s0, s1, s2, s3, s4, s5, s6, s7]
输出: 新状态

// 第一组 Quarter Round
(s0, s1, s2, s3) = QuarterRound(s0, s1, s2, s3)
(s4, s5, s6, s7) = QuarterRound(s4, s5, s6, s7)

// 对角线 Quarter Round（混合两组）
(s0, s5, s2, s7) = QuarterRound(s0, s5, s2, s7)
(s1, s4, s3, s6) = QuarterRound(s1, s4, s3, s6)

返回: [s0, s1, s2, s3, s4, s5, s6, s7]
```

### 4.3 密钥到状态转换

将32字节密钥转换为8个32位字的状态：

```
输入: 密钥 K[0..31]
输出: 状态 [s0, s1, s2, s3, s4, s5, s6, s7]

s0 = K[0..3]   (小端序读取)
s1 = K[4..7]
s2 = K[8..11]
s3 = K[12..15]
s4 = K[16..19]
s5 = K[20..23]
s6 = K[24..27]
s7 = K[28..31]
```

小端序读取示例：
```
如果 K[0..3] = [0x01, 0x02, 0x03, 0x04]
则 s0 = 0x04030201
```

### 4.4 状态到字节转换

将8个32位字状态转换为32字节数组：

```
输入: 状态 [s0, s1, s2, s3, s4, s5, s6, s7]
输出: 字节数组 B[0..31]

B[0..3]   = s0 (小端序写入)
B[4..7]   = s1
B[8..11]  = s2
B[12..15] = s3
B[16..19] = s4
B[20..23] = s5
B[24..27] = s6
B[28..31] = s7
```

---

## 5. 流加密/解密

### 5.1 基础Nonce生成

```
输入: 密钥 K[0..31], Nonce N[0..23]
输出: 基础状态 baseNonce[8]

// 构建32字节基础块
for i = 0 to 31:
    if i < 24:
        baseBlock[i] = FIXED_INITIAL_STATE[i] XOR K[i] XOR N[i]
    else:
        baseBlock[i] = FIXED_INITIAL_STATE[i] XOR K[i]

baseNonce = keyToState(baseBlock)
返回 baseNonce
```

### 5.2 密钥流块生成

```
输入: 基础状态 baseNonce[8], 计数器 counter (uint64), 轮数 rounds
输出: 32字节密钥流块 keystream[32]

// 复制基础状态
state = baseNonce

// 混合计数器
state[6] = state[6] XOR (counter >> 32)
state[7] = state[7] XOR (counter & 0xFFFFFFFF)

// 保存原始状态
original = state

// 执行轮运算
for i = 1 to rounds:
    state = SwirlRound(state)

// 添加原始状态（ChaCha-like finalization）
for i = 0 to 7:
    state[i] = state[i] + original[i] (mod 2^32)

// 转换为字节
keystream = stateToBytes(state)
返回 keystream
```

### 5.3 流加密过程

```
输入: 密钥 K, Nonce N, 明文 P, 轮数 rounds
输出: 密文 C

baseNonce = makeBaseNonce(K, N)
counter = 0

for each 32-byte block of P:
    keystream = generateKeystreamBlock(baseNonce, counter, rounds)
    C[block] = P[block] XOR keystream
    counter = counter + 1

// 处理剩余字节（不足32字节）
remaining = length(P) mod 32
if remaining > 0:
    keystream = generateKeystreamBlock(baseNonce, counter, rounds)
    C[final] = P[final] XOR keystream[0..remaining-1]

返回 C
```

### 5.4 流解密过程

流解密与加密过程完全相同（XOR运算的自反性）：

```
Decrypt(K, N, C, rounds) = Encrypt(K, N, C, rounds)
```

---

## 6. AEAD认证加密

### 6.1 密钥派生

AEAD使用HKDF从主密钥派生加密密钥和认证密钥：

```
输入: 主密钥 masterKey[32], 轮数 rounds
输出: 加密密钥 encKey[32], 认证密钥 authKey[32]

encKey  = HKDF(masterKey, NULL, "aead-key", 32, rounds)
authKey = HKDF(masterKey, NULL, "tag-key", 32, rounds)
```

### 6.2 HMAC密钥准备

```
输入: 认证密钥 authKey
输出: ipad[32], opad[32]

if length(authKey) > 32:
    authKey = Hash(authKey, rounds)

for i = 0 to 31:
    if i < length(authKey):
        ipad[i] = authKey[i] XOR 0x36
        opad[i] = authKey[i] XOR 0x5C
    else:
        ipad[i] = 0x36
        opad[i] = 0x5C
```

### 6.3 AEAD加密

```
输入: 密钥 K, Nonce N, 明文 P, 附加数据 AD, 轮数 rounds
输出: 密文 C || 认证标签 Tag

// 派生密钥
encKey, authKey = deriveKeys(K, rounds)

// 准备HMAC pads
ipad, opad = prepareHmacPads(authKey, rounds)

// 生成基础Nonce
baseNonce = makeBaseNonce(encKey, N)

// 初始化HMAC内部状态
innerState = HashInit(ipad, rounds)
innerState.update(AD)

// 流加密并计算HMAC
counter = 0
for each block of P:
    keystream = generateKeystreamBlock(baseNonce, counter, rounds)
    ciphertextBlock = plaintextBlock XOR keystream
    innerState.update(ciphertextBlock)
    output(ciphertextBlock)
    counter = counter + 1

// 计算认证标签
innerHash = innerState.finalize()
outerState = HashInit(opad, rounds)
outerState.update(innerHash)
Tag = outerState.finalize()[0..15]

output(Tag)
```

### 6.4 AEAD解密

```
输入: 密钥 K, Nonce N, 密文 C || Tag, 附加数据 AD, 轮数 rounds
输出: 明文 P 或 验证失败

// 派生密钥
encKey, authKey = deriveKeys(K, rounds)

// 准备HMAC pads
ipad, opad = prepareHmacPads(authKey, rounds)

// 分离密文和标签
ciphertext = C[0..length-16]
receivedTag = C[length-16..length]

// 计算期望的认证标签
innerState = HashInit(ipad, rounds)
innerState.update(AD)
innerState.update(ciphertext)
innerHash = innerState.finalize()
outerState = HashInit(opad, rounds)
outerState.update(innerHash)
expectedTag = outerState.finalize()[0..15]

// 常数时间比较标签
if not constantTimeCompare(receivedTag, expectedTag):
    返回 验证失败

// 验证通过，解密密文
baseNonce = makeBaseNonce(encKey, N)
P = StreamDecrypt(baseNonce, ciphertext, rounds)
返回 P
```

---

## 7. 哈希函数

### 7.1 压缩函数

FlashSwirl哈希使用Davies-Meyer结构：

```
输入: 状态 state[8], 消息块 block[32], 轮数 rounds
输出: 新状态

// 消息注入
msgState[0] = state[0] XOR block[0..3]
msgState[1] = state[1] XOR block[4..7]
...
msgState[7] = state[7] XOR block[28..31]

// 保存原始状态
original = state

// 执行轮运算
for i = 1 to rounds:
    msgState = SwirlRound(msgState)

// Davies-Meyer: state = state XOR f(state XOR block)
for i = 0 to 7:
    state[i] = original[i] XOR msgState[i]
```

### 7.2 哈希计算

```
输入: 消息 M, 轮数 rounds
输出: 哈希值 H[32]

// 初始化状态
state = keyToState(FIXED_INITIAL_STATE)

// 填充和分块处理
M = M || 0x80 || 0x00... || length(M)*8 (64位小端序)

for each 32-byte block of M:
    compress(state, block, rounds)

H = stateToBytes(state)
返回 H
```

---

## 8. HMAC

### 8.1 HMAC计算

基于RFC 2104：

```
输入: 密钥 K, 消息 M, 轮数 rounds
输出: HMAC值

// 密钥处理
if length(K) > 32:
    K = Hash(K, rounds)

// 准备pads
ipad = K XOR 0x36 (重复到32字节)
opad = K XOR 0x5C (重复到32字节)

// HMAC = Hash(opad || Hash(ipad || message))
innerHash = Hash(ipad || M, rounds)
outerHash = Hash(opad || innerHash, rounds)

返回 outerHash
```

---

## 9. 密钥派生

### 9.1 HKDF (RFC 5869)

```
输入: 主密钥 masterKey, 盐 salt, 信息 info, 输出长度 length, 轮数 rounds
输出: 派生密钥

// 提取阶段
if salt为空:
    salt = 32个零字节
if length(salt) != 32:
    salt = Hash(salt, rounds)

PRK = HMAC(salt, masterKey, rounds)

// 扩展阶段
N = ceil(length / 32)
T = 空
for i = 1 to N:
    if i == 1:
        T_i = HMAC(PRK, info || 0x01, rounds)
    else:
        T_i = HMAC(PRK, T_{i-1} || info || i, rounds)
    T = T || T_i

返回 T[0..length-1]
```

### 9.2 PBKDF2 (RFC 2898)

```
输入: 密码 password, 盐 salt, 迭代次数 iterations, 密钥长度 keyLength, 轮数 rounds
输出: 派生密钥

N = ceil(keyLength / 32)

for i = 1 to N:
    U_1 = HMAC(password, salt || i (32位小端序), rounds)
    F = U_1
    for j = 2 to iterations:
        U_j = HMAC(password, U_{j-1}, rounds)
        F = F XOR U_j
    DK = DK || F

返回 DK[0..keyLength-1]
```

---

## 10. 测试向量

完整的测试向量请参见: [test_vectors.json](JS/test_vectors.json)

---

## 11. 安全性分析

### 11.1 安全强度

| 参数 | 安全级别 |
|------|----------|
| 密钥长度 | 256位 (抵抗暴力破解) |
| Nonce长度 | 192位 (防止Nonce碰撞) |
| AEAD标签 | 128位 (认证强度) |
| 轮数 | 20轮 (标准) / 8轮 (快速) |

### 11.2 设计原理

1. **ARX结构**: 仅使用加法、旋转和XOR运算，抵抗线性攻击和差分攻击
2. **双Quarter Round设计**: 两个独立的Quarter Round组，通过对角线混合实现更好的扩散
3. **ChaCha-like Finalization**: 轮运算后添加原始状态，防止逆向推导
4. **Davies-Meyer哈希**: 压缩函数使用 Davies-Meyer 结构，提供单向性

### 11.3 使用建议

1. **Nonce管理**: 每个密钥必须生成唯一的Nonce，推荐使用密码学安全的随机数生成器
2. **轮数选择**: 
   - 一般用途：使用20轮
   - 性能敏感场景：可使用8轮，但需评估安全风险
3. **密钥派生**: 从密码派生密钥时，使用PBKDF2并设置足够大的迭代次数（建议≥10000）

---

## 12. 参考实现

本项目提供三种语言的参考实现：

- **C++**: [CPP/FlashSwirlLib/](CPP/FlashSwirlLib/)
- **Go**: [GO/FlashSwirl/](GO/FlashSwirl/)
- **JavaScript**: [JS/FlashSwirl.js](JS/FlashSwirl.js)

所有实现都遵循本规范，并通过了相同的测试向量验证。

---

*本规范遵循开源原则，欢迎社区审查和改进。*
