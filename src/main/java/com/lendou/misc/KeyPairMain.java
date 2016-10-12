package com.lendou.misc;

import org.apache.commons.codec.binary.Hex;

import java.security.*;

/**
 * 测试 KeyPair
 */
public class KeyPairMain {

    public static void main(String[] args) throws Exception {

        // 创建实例
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

        // 初始化 - 算法无关的初始化
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(1024, random);

        // 生成KeyPair
        KeyPair keyPair = keyGen.generateKeyPair();

        // 打印 KeyPair
        PrivateKey priKey = keyPair.getPrivate();
        System.out.println("===== priKey =====");
        System.out.println(priKey.getAlgorithm());
        System.out.println(Hex.encodeHexString(priKey.getEncoded()));
        System.out.println(priKey.getFormat());

        PublicKey pubKey = keyPair.getPublic();
        System.out.println("===== pubKey =====");
        System.out.println(pubKey.getAlgorithm());
        System.out.println(Hex.encodeHexString(pubKey.getEncoded()));
        System.out.println(pubKey.getFormat());

    }
}
