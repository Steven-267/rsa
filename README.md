## 接口

```java
    /**
     * 修改密码
     * @param request
     * @return
     */
    @PostMapping("/resetPassword")
    public ResponseEntity<String> resetPassword(@RequestBody PasswordResetRequest request) {
        try {
            passwordResetService.resetPassword(request.getEncryptedPassword(), request.getSignature(), request.getTimestamp());
            return ResponseEntity.ok("Password reset successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to reset password: " + e.getMessage());
        }
    }
```

## 流程

### 密码重置接口的流程如下：

1. **客户端请求**：
   - 用户发起密码重置请求，提供加密的密码 (`encryptedPassword`)、签名 (`signature`) 以及时间戳 (`timestamp`)。
   - 请求数据被封装在 `PasswordResetRequest` 对象中，通过 HTTP POST 请求发送到服务器。
2. **控制器处理**：
   - 服务器端的控制器接收到 `PasswordResetRequest` 对象，解析其中的参数。
3. **解密和验证**：
   - 使用服务器存储的公钥解密 `encryptedPassword`，得到新密码。
   - 验证 `signature` 和 `timestamp` 以确保请求未被篡改。
4. **密码更新**：
   - 解密和签名验证通过后，更新用户的密码到数据库中。
5. **响应客户端**：
   - 如果成功，返回一个状态为 200 的响应，告知密码重置成功；如果失败，返回相应的错误信息。

### 总结：

- 客户端提交加密密码和签名
- 服务器解密和验证
- 验证通过后更新数据库

## 前端

### 1. **加密后的密码 (`encryptedPassword`)**

- **逻辑**：使用 RSA 公钥加密用户输入的密码。
- 步骤：
  1. 获取用户输入的密码。
  2. 使用 RSA 公钥对密码进行加密，确保传输过程中的安全性。

#### 示例（JavaScript）：

```js
async function encryptPassword(password, publicKey) {
    const encoder = new TextEncoder();
    const encodedPassword = encoder.encode(password);
    const importedPublicKey = await window.crypto.subtle.importKey(
        "spki",
        base64ToArrayBuffer(publicKey), // 将 Base64 公钥转换为 ArrayBuffer
        {
            name: "RSA-OAEP",
            hash: {name: "SHA-256"},
        },
        true,
        ["encrypt"]
    );
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        importedPublicKey,
        encodedPassword
    );
    return arrayBufferToBase64(encrypted); // 将加密后的 ArrayBuffer 转换为 Base64
}
```

- `base64ToArrayBuffer` 和 `arrayBufferToBase64` 函数用于 Base64 编码和解码。
- `window.crypto.subtle.encrypt` 用于通过 RSA-OAEP 算法加密密码。

### 2. **时间戳 (`timestamp`)**

- **逻辑**：生成当前请求的时间戳，通常以 ISO 8601 格式表示（用于防止重放攻击）。
- 步骤
  1. 获取当前系统时间。
  2. 将时间格式化为 ISO 8601 格式。

#### 示例（JavaScript）：

```
javascript


复制代码
function generateTimestamp() {
    return new Date().toISOString(); // 返回当前时间的 ISO 8601 格式
}
```

例如，生成的时间戳可能是：`"2024-09-27T08:21:00.000Z"`。

### 3. **签名 (`signature`)**

- **逻辑**：使用 RSA 私钥对数据进行签名，确保数据的完整性和真实性（可以对加密后的密码和时间戳进行签名）。

- 步骤

  ：

  1. 将加密后的密码和时间戳组合为一段字符串。
  2. 使用 RSA 私钥对该字符串生成签名，签名用以校验请求的真实性。

#### 示例（JavaScript）：

```
javascript


复制代码
async function signRequest(data, privateKey) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    const importedPrivateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        base64ToArrayBuffer(privateKey), // 将 Base64 私钥转换为 ArrayBuffer
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: {name: "SHA-256"},
        },
        true,
        ["sign"]
    );
    const signature = await window.crypto.subtle.sign(
        {
            name: "RSASSA-PKCS1-v1_5",
        },
        importedPrivateKey,
        encodedData
    );
    return arrayBufferToBase64(signature); // 将签名的 ArrayBuffer 转换为 Base64
}
```

- `window.crypto.subtle.sign` 用于生成签名，使用 `RSASSA-PKCS1-v1_5` 作为签名算法，`SHA-256` 作为哈希算法。

### 4. **完整示例**

将上面的步骤组合起来，最终生成请求参数：

```
javascript


复制代码
async function generatePasswordResetRequest(password, publicKey, privateKey) {
    // 1. 加密密码
    const encryptedPassword = await encryptPassword(password, publicKey);

    // 2. 生成时间戳
    const timestamp = generateTimestamp();

    // 3. 生成签名（加密后的密码和时间戳）
    const dataToSign = encryptedPassword + timestamp;
    const signature = await signRequest(dataToSign, privateKey);

    // 4. 构建请求对象
    const requestData = {
        encryptedPassword: encryptedPassword,
        signature: signature,
        timestamp: timestamp
    };

    return requestData;
}
```

### 5. 数据传递

通过上面的 `generatePasswordResetRequest` 函数，你会得到以下 JSON 格式的请求参数，可以发送到后端：

```
{
    "encryptedPassword": "加密后的Base64密码",
    "signature": "签名的Base64字符串",
    "timestamp": "当前时间的ISO 8601格式"
}
```

### 总结

- **加密后的密码**：使用 RSA 公钥加密用户的密码，保证传输安全。
- **时间戳**：生成当前请求的时间，用于防止重放攻击。
- **签名**：使用 RSA 私钥对加密后的密码和时间戳进行签名，保证数据的完整性和真实性。

如果你使用的加密和签名是后端完成的，这些逻辑可以简化为直接获取公钥和签名生成逻辑，并将其应用于请求的构建。如果有特定库或工具的需求，也可以相应调整代码。



## 用户自己实现加密过程（java）

前置准备，需要自己在数据库新建一个表，存放密钥对

```sql
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for rsa_keys
-- ----------------------------
DROP TABLE IF EXISTS `rsa_keys`;
CREATE TABLE `rsa_keys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `public_key` text NOT NULL,
  `private_key` text NOT NULL,
  `school_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `school_id` (`school_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
```

### 控制层

```java
    /**
     * todo 测试修改密码接口，上线需要注释
     * @param password
     * @return
     * @throws Exception
     */
    @PostMapping("testPassword")
    public R generatePasswordResetParams(@RequestParam String password) throws Exception {
        PasswordResetRequest result = passwordResetService.generatePasswordResetParams(password);
        return R.ok(result);
    }
```

### 服务层

```java
/**
     * todo 仅供测试使用，上线需要注销
     * @param password
     * @return
     */
    public PasswordResetRequest generatePasswordResetParams(String password) throws Exception {
        // 1. 加密密码
        String encryptedPassword = encryptPassword(password);

        // 2. 生成时间戳
        String timestamp = generateTimestamp();

        // 3. 生成签名 (加密后的密码 + 时间戳)
        String dataToSign = password + timestamp;
        String signature = signData(dataToSign);

        // 返回生成的参数
        return new PasswordResetRequest(encryptedPassword, signature, timestamp);
    }
    private String encryptPassword(String password) throws Exception {
        //查询密钥 -- 这里学校schoolId写死为0测试，如果自己搭建的话，需要联系管理员获取自己学校的id
        RsaKeys rsaKeys = userRepositoryMapper.selectKeyBySchoolId(0);
        String publicKeyStr = rsaKeys.getPublicKey();
        String privateKeyStr = rsaKeys.getPrivateKey();

        // 使用 RSA 公钥加密密码
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String signData(String data) throws Exception {
        //查询密钥 -- 这里学校schoolId写死为0测试,如果自己搭建的话，需要联系管理员获取自己学校的id
        RsaKeys rsaKeys = userRepositoryMapper.selectKeyBySchoolId(0);
        String privateKeyStr = rsaKeys.getPrivateKey();
        // 使用 RSA 私钥对数据进行签名
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());

        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private String generateTimestamp() {
        return new Date().toInstant().toString(); // 返回 ISO 8601 格式的时间戳
    }
```

### 返回实体类

```java
@Data
@AllArgsConstructor
@NoArgsConstructor
public class PasswordResetRequest implements Serializable {
    //加密的密码
    private String encryptedPassword;
    //签名
    private String signature;
    //时间戳
    private String timestamp;

}
```

### 密钥实体类

```java
@Data
@AllArgsConstructor
@NoArgsConstructor
public class RsaKeys {

    private int id; // 假设我们只保存一对密钥，ID可以固定为 1

    private String publicKey;

    private String privateKey;

    private Long schoolId;

}
```

搭建过程有问题可以联系管理员。

