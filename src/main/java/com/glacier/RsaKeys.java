package com.glacier;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RsaKeys {

    private int id; // 假设我们只保存一对密钥，ID可以固定为 1

    private String publicKey;

    private String privateKey;

    private Long schoolId;

}
