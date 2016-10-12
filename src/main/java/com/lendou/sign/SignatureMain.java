package com.lendou.sign;

import java.security.*;

/**
 * 签名算法
 */
public class SignatureMain {

    public static void main(String[] args) throws Exception {

        final String algoName = "SHA1withRSA";

        // 准备数据
        String text = "hello world, the guys!";
        byte[] data = text.getBytes("utf-8");

        // 准备密钥对
        KeyPair keyPair = getKeyPair();

        // 签名数据
        byte[] signData = sign(data, keyPair.getPrivate(), algoName);

        // 验证数据
        boolean ret = verify(data, signData, keyPair.getPublic(), algoName);

        // 生成 ret
        System.out.println(ret);
    }

    private static boolean verify(byte[] data, byte[] signData, PublicKey publicKey, String algo) throws Exception {

        // 创建一个Signature实例
        Signature sig = Signature.getInstance(algo);

        // 使用公钥初始化对象
        sig.initVerify(publicKey);

        // 验证数据
        sig.update(data);
        return sig.verify(signData);
    }

    private static byte[] sign(byte[] data, PrivateKey privateKey, String algo) throws Exception {

        // 创建一个Signature实例
        Signature sig = Signature.getInstance(algo);

        // 使用私钥初始化对象
        sig.initSign(privateKey);

        // 签名数据
        sig.update(data);
        return sig.sign();
    }

    private static KeyPair getKeyPair() throws Exception {

        // 创建实例
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

        // 初始化 - 算法无关的初始化
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(1024, random);

        // 生成一个KeyPair
        return keyGen.generateKeyPair();
    }
}