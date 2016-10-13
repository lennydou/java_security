package com.lendou.sync;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * 基于 RC4 的 PBE 算法
 */
public class PBERC4Main {
    private static final String ALGO = "PBEWithSHA1AndRC4_128";

    private static final int ITER_COUNT = 20;

    public static void main(String[] args) throws Exception {

        // 材料
        String plainText = "hello world, lennydou!!!";
        String keyStr = "123456";
        byte[] salt = initSalt();
        System.out.println("  salt: " + Hex.encodeHexString(salt));

        // 加密
        byte[] secretContent = encrypt(plainText.getBytes("utf-8"), keyStr, salt);
        System.out.println("secret: " + Hex.encodeHexString(secretContent));

        // 解密
        byte[] plainContent = decrypt(secretContent, keyStr, salt);
        System.out.println(" plain: " + new String(plainContent));
    }

    /**
     * 把口令转成密钥
     */
    private static Key toKey(String pwd) throws Exception {

        // 密钥材料转换
        PBEKeySpec keySpec = new PBEKeySpec(pwd.toCharArray());

        // 实例化
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGO);

        // 生成密钥
        return keyFactory.generateSecret(keySpec);
    }

    /**
     * 生成盐
     */
    private static byte[] initSalt() {

        // 实例化安全随机数`
        SecureRandom random = new SecureRandom();

        // 产出盐
        return random.generateSeed(8);
    }

    /**
     * 加密
     */
    private static byte[] encrypt(byte[] data, String pwd, byte[] salt) throws Exception {

        // 转换密钥
        Key key = toKey(pwd);

        // 实例化PBE参数材料
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITER_COUNT);

        // 实例化
        Cipher cipher = Cipher.getInstance(ALGO);

        // 初始化
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        // 执行操作
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(byte[] data, String pwd, byte[] salt) throws Exception {

        // 转换密钥
        Key key = toKey(pwd);

        // 实例化PBE参数材料
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITER_COUNT);

        // 实例化
        Cipher cipher = Cipher.getInstance(ALGO);

        // 初始化
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        // 执行操作
        return cipher.doFinal(data);
    }
}
