package com.glacier;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;


public class Main {

    public static void main(String[] args) throws Exception {
        //生成密钥对
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);

        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 将密钥编码为 Base64 字符串，便于存储到数据库
        String publicKeyEncoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyEncoded = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        System.out.println("publicKeyEncoded:"+publicKeyEncoded);
        System.out.println();
        System.out.println("privateKeyEncoded:"+privateKeyEncoded);
        System.out.println();

        //现在的密码是123456
        String oldPassword = "123456";
        System.out.println("The default password is 123456");

        System.out.println();

        //输入新密码
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please enter the new password");
        String password = scanner.nextLine();


        System.out.println();

        //根据输入的privateKey实现一下加密
        System.out.println("Please enter the privateKey");
        String scanPrivateKey = scanner.nextLine();
        String timestamp;
        String dataToSign;
        String signature;
        String encryptedPassword;
        //  加密密码
        try {
            encryptedPassword = encryptPassword(password,publicKeyEncoded,scanPrivateKey);
            System.out.println("encryptedPassword:"+ encryptedPassword);
            //  生成时间戳
            timestamp = generateTimestamp();
            System.out.println("timestamp:"+ timestamp);

            //  生成签名 (加密后的密码 + 时间戳)
            dataToSign = password + timestamp;
            signature = signData(dataToSign,scanPrivateKey);
            System.out.println("signature:"+ signature);
        }catch (Exception e){
            System.out.println("密钥错误");
            throw new IOException("密钥错误");
        }
        System.out.println();

        // 解密加密的密码
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        String decryptedPassword = new String(decryptedBytes);
        System.out.println("decryptedPassword:"+decryptedPassword);
        System.out.println();
        //发送三个参数，校验参数
        if (verifySignature(decryptedPassword, timestamp, signature,publicKey)) {
            // 验证通过，更新密码
            oldPassword = decryptedPassword;
            System.out.println("Password modification successful, new password is:"+decryptedPassword);
        } else {
            throw new Exception("Signature verification failed");
        }
    }
    public static String encryptPassword(String password,String publicKeyStr,String privateKeyStr) throws Exception {
        // 使用 RSA 公钥加密密码
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    private static String signData(String data,String privateKeyStr) throws Exception {
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

    private static String generateTimestamp() {
        return new Date().toInstant().toString(); // 返回 ISO 8601 格式的时间戳
    }


    private static boolean verifySignature(String data, String timestamp, String signature,PublicKey publicKey) throws Exception {
        String dataToVerify = data + timestamp;

        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        sign.update(dataToVerify.getBytes());

        return sign.verify(Base64.getDecoder().decode(signature));
    }
}