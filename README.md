![Version](https://img.shields.io/badge/作者-风之暇想-blue.svg)   ![Languages](https://img.shields.io/badge/Languages-C++%20%7C%20Go%20%7C%20JavaScript-orange.svg)

![app.ico](app.ico)

**FlashSwirl 闪旋，一款高性能的对称加密算法库，提供流加密、AEAD认证加密、HASH、HMAC、HKDF、PBKDF2**

---

### 概述

由**风之暇想**研究的对称加密算法，基于ARX（Add-Rotate-XOR）结构设计，灵感来源于ChaCha20；加密库提供流加密、AEAD认证加密、HASH、HMAC、HKDF密钥派生、PBKDF2密钥派生的密码学功能。

### ✨ 特性

- **多种加密模式**：支持流加密（Stream）和AEAD认证加密
- **高性能设计**：批量处理、并行计算、内存池优化
- **跨平台支持**：提供C++、Go、JavaScript三种语言代码

### 📊 算法规范

[算法规范文档](SPECIFICATION.md)

---

## 📚 三种语言库调用说明

### C++ 版本

**使用示例：**

```cpp
#include "FlashSwirl.h"
#include <iostream>
#include <vector>

int main() {
    // 准备密钥和Nonce
    uint8_t key[32] = { /* 32字节密钥 */ };
    uint8_t nonce[24] = { /* 24字节随机Nonce，必须使用安全随机数生成 */ };

    // ===== 1. 流加密 =====
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    FlashSwirl_EncryptBuffer(key, 32, nonce, 24, data.data(), data.size(), 20);
    // data现在包含密文
    
    FlashSwirl_DecryptBuffer(key, 32, nonce, 24, data.data(), data.size(), 20);
    // data现在恢复为明文

    // ===== 2. AEAD认证加密 =====
    uint8_t plaintext[] = "Secret message";
    uint8_t ciphertext[256];
    int outLen = sizeof(ciphertext);
    uint8_t ad[] = "additional-data";
    
    FlashSwirl_EncryptAEADBuffer(key, 32, nonce, 24, 
                                  plaintext, sizeof(plaintext)-1,
                                  ciphertext, &outLen, ad, sizeof(ad)-1, 20);
    
    uint8_t decrypted[256];
    int plainLen = sizeof(decrypted);
    FlashSwirl_DecryptAEADBuffer(key, 32, nonce, 24,
                                  ciphertext, outLen,
                                  decrypted, &plainLen, ad, sizeof(ad)-1, 20);

    // ===== 3. HASH =====
    const char* message = "Hello, FlashSwirl!";
    uint8_t hash[32];
    FlashSwirl_Hash((const uint8_t*)message, strlen(message), 20, hash);

    // ===== 4. HMAC =====
    uint8_t hmacKey[] = "secret-key";
    uint8_t hmacOut[32];
    FlashSwirl_HMAC(hmacKey, sizeof(hmacKey)-1, 
                    (const uint8_t*)message, strlen(message), 
                    20, hmacOut);

    // ===== 5. HKDF密钥派生 =====
    uint8_t masterKey[32] = { /* 主密钥 */ };
    uint8_t salt[32] = { /* 盐值 */ };
    uint8_t info[] = "my-app";
    uint8_t derivedKey[32];
    FlashSwirl_HKDF(masterKey, 32, salt, 32, info, sizeof(info)-1, 32, 20, derivedKey);

    // ===== 6. PBKDF2密钥派生 =====
    const char* password = "user-password";
    uint8_t pbkdf2Salt[] = "random-salt";
    uint8_t keyFromPassword[32];
    FlashSwirl_PBKDF2((const uint8_t*)password, strlen(password),
                      pbkdf2Salt, sizeof(pbkdf2Salt)-1,
                      10000, 32, 20, keyFromPassword);

    return 0;
}
```

---

### Go 版本

[https://pkg.go.dev/github.com/fzxx/FlashSwirl/GO/FlashSwirl](https://pkg.go.dev/github.com/fzxx/FlashSwirl/GO/FlashSwirl)

**使用示例：**

```go
package main

import (
    "bytes"
    "crypto/rand"
    "fmt"
    
    "FlashSwirl"
)

func main() {
    // 准备密钥和Nonce
    key := make([]byte, 32)
    nonce := make([]byte, 24)
    rand.Read(key)
    rand.Read(nonce)

    // ===== 1. 流加密 =====
    plaintext := []byte("Secret message")
    var encrypted bytes.Buffer
    FlashSwirl.Encrypt(key, nonce, bytes.NewReader(plaintext), &encrypted, 20)
    
    var decrypted bytes.Buffer
    FlashSwirl.Decrypt(key, nonce, &encrypted, &decrypted, 20)
    fmt.Printf("Decrypted: %s\n", decrypted.Bytes())

    // ===== 2. AEAD认证加密 =====
    var aeadEncrypted bytes.Buffer
    additionalData := []byte("context info")
    FlashSwirl.EncryptAEAD(key, nonce, bytes.NewReader(plaintext), &aeadEncrypted, additionalData, 20)
    
    var aeadDecrypted bytes.Buffer
    valid, _ := FlashSwirl.DecryptAEAD(key, nonce, &aeadEncrypted, &aeadDecrypted, additionalData, 20)
    if valid {
        fmt.Printf("AEAD Decrypted: %s\n", aeadDecrypted.Bytes())
    }

    // ===== 3. HASH =====
    message := []byte("Hello, FlashSwirl!")
    hash, _ := FlashSwirl.Hash(bytes.NewReader(message), 20)
    fmt.Printf("Hash: %x\n", hash)

    // ===== 4. HMAC =====
    hmacKey := []byte("secret-key")
    hmacResult, _ := FlashSwirl.HMAC(hmacKey, bytes.NewReader(message), 20)
    fmt.Printf("HMAC: %x\n", hmacResult)

    // ===== 5. HKDF密钥派生 =====
    salt := []byte("random-salt")
    info := []byte("my-app")
    derivedKey, _ := FlashSwirl.HKDF(key, salt, info, 32, 20)
    fmt.Printf("Derived Key: %x\n", derivedKey)

    // ===== 6. PBKDF2密钥派生 =====
    password := []byte("user-password")
    pbkdf2Salt := []byte("random-salt")
    keyFromPassword, _ := FlashSwirl.PBKDF2(password, pbkdf2Salt, 10000, 32, 20)
    fmt.Printf("Key from password: %x\n", keyFromPassword)
}
```

---

### JavaScript 版本

[https://flashswirl.pages.dev/](https://flashswirl.pages.dev/)

**CDN引用**


```
<script src="https://cdn.jsdelivr.net/gh/fzxx/FlashSwirl/JS/FlashSwirl.js"></script>
```

```
<script src="https://cdn.statically.io/gh/fzxx/FlashSwirl@main/JS/FlashSwirl.js"></script>
```

**使用示例：**

```javascript
// 浏览器环境
// <script src="FlashSwirl.js"></script>

// Node.js环境
// const FlashSwirl = require('./FlashSwirl.js');

// 准备密钥和Nonce
const key = crypto.getRandomValues(new Uint8Array(32));
const nonce = crypto.getRandomValues(new Uint8Array(24));

// ===== 1. 流加密 =====
const plaintext = new TextEncoder().encode("Secret message");
const ciphertext = FlashSwirl.encrypt('stream', key, nonce, plaintext, new Uint8Array(0), 20);
const decrypted = FlashSwirl.decrypt('stream', key, nonce, ciphertext, new Uint8Array(0), 20);
console.log("Decrypted:", new TextDecoder().decode(decrypted));

// ===== 2. AEAD认证加密 =====
const additionalData = new TextEncoder().encode("context info");
const aeadCiphertext = FlashSwirl.encrypt('aead', key, nonce, plaintext, additionalData, 20);
const aeadDecrypted = FlashSwirl.decrypt('aead', key, nonce, aeadCiphertext, additionalData, 20);
console.log("AEAD Decrypted:", new TextDecoder().decode(aeadDecrypted));

// ===== 3. HASH =====
const message = new TextEncoder().encode("Hello, FlashSwirl!");
const hash = FlashSwirl.hash(message, 20);
console.log("Hash:", Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join(''));

// ===== 4. HMAC =====
const hmacKey = new TextEncoder().encode("secret-key");
const hmacResult = FlashSwirl.hmac(hmacKey, message, 20);
console.log("HMAC:", Array.from(hmacResult).map(b => b.toString(16).padStart(2, '0')).join(''));

// ===== 5. HKDF密钥派生 =====
const salt = new TextEncoder().encode("random-salt");
const info = new TextEncoder().encode("my-app");
const derivedKey = FlashSwirl.hkdf(key, salt, info, 32, 20);
console.log("Derived Key:", Array.from(derivedKey).map(b => b.toString(16).padStart(2, '0')).join(''));

// ===== 6. PBKDF2密钥派生 =====
const password = new TextEncoder().encode("user-password");
const pbkdf2Salt = new TextEncoder().encode("random-salt");
const keyFromPassword = FlashSwirl.pbkdf2(password, pbkdf2Salt, 10000, 32, 20);
console.log("Key from password:", Array.from(keyFromPassword).map(b => b.toString(16).padStart(2, '0')).join(''));
```

## 📖 更新日志

[更新日志](CHANGELOG.md)

## 📚许可证

[GNU General Public License 3.0](https://github.com/fzxx/FlashSwirl/blob/main/LICENSE)