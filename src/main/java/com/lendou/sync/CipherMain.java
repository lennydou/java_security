package com.lendou.sync;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CipherMain {

    public static void main(String[] args) throws Exception {

        System.out.println("=== ECB ===");
        testECB();
        System.out.println();

        System.out.println("=== CBC ===");
        testCBC();
        System.out.println();

        System.out.println("=== CTR ===");
        testCTR();
        System.out.println();
    }

    private static void testECB() throws Exception {

        String text = "Hello world from lennydou!!!";
        byte[] data = text.getBytes("utf-8");

        // 产生一个 key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecretKey key = keyGen.generateKey();

        // 创建一个 Cipher
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        // 初始化 cipher
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // 加密
        byte[] cipherData = cipher.doFinal(data);
        System.out.println(Hex.encodeHexString(cipherData));

        // 重新初始化 cipher
        cipher.init(Cipher.DECRYPT_MODE, key);

        // 解密
        byte[] clearData = cipher.doFinal(cipherData);
        System.out.println(new String(clearData));
    }

    /**
     * AES/CBC/NoPadding
     * 密钥必须是16位的; IV必须是16位的
     * 待加密内容的长度必须是16位整数倍, 如果不是16位整数倍, 则会抛出异常 IllegalBlockSizeException: Input length not multiple of 16 bytes
     *
     * @throws Exception
     */
    private static void testCBC() throws Exception {
        String text = "Hello world from lennydou!!!";
        byte[] data = text.getBytes("utf-8");

        // 产生一个 key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecretKey key = keyGen.generateKey();

        // 创建一个 Cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // 初始化 cipher, 需要添加一个初始化向量参数
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(getIV()));

        // 加密
        byte[] cipherData = cipher.doFinal(data);
        System.out.println(Hex.encodeHexString(cipherData));

        // 重新初始化 cipher, 需要添加一个初始化向量参数
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(getIV()));

        // 解密
        byte[] clearData = cipher.doFinal(cipherData);
        System.out.println(new String(clearData));
    }

    private static void testCTR() throws Exception {

        String text = "Hello world from lennydou!!!";
        byte[] data = text.getBytes("utf-8");

        // 产生一个 key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecretKey key = keyGen.generateKey();

        // 创建一个 Cipher
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");

        // 初始化 cipher, 需要添加一个初始化向量参数
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(getIV()));

        // 加密
        byte[] cipherData = cipher.doFinal(data);
        System.out.println(Hex.encodeHexString(cipherData));

        // 重新初始化 cipher, 需要添加一个初始化向量参数
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(getIV()));

        // 解密
        byte[] clearData = cipher.doFinal(cipherData);
        System.out.println(new String(clearData));
    }

    /**
     * 初始化向量需要是16位的
     *
     * @return
     */
    private static byte[] getIV() {
        String ivStr = "1234567812345678";
        return ivStr.getBytes();
    }
}