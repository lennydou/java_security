package com.lendou.async;

import org.apache.commons.lang3.tuple.Pair;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 非对称加密算法 RSA, 真正的非对称加密算法
 * 公钥和私钥都可以进行加密或者解密
 */
public class RSAMain {

    private static final String KEY_ALGO = "RSA";
    private static final int KEY_SIZE = 512;

    /**
     * 生成对称密钥
     */
    private static Pair<RSAPrivateKey, RSAPublicKey> initKey() throws Exception {

        // 实例化密钥生成器
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGO);
        keyPairGen.initialize(KEY_SIZE);

        // 生成密钥对
        KeyPair keyPair = keyPairGen.genKeyPair();
        return Pair.of((RSAPrivateKey) keyPair.getPrivate(), (RSAPublicKey) keyPair.getPublic());
    }

    /**
     * 使用私钥加密
     *
     * @param data 待加密数据
     * @param priKey 私钥
     */
    private static final byte[] encryptWithPriKey(byte[] data, byte[] priKey) throws Exception {

        // 生成私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(priKey);
        PrivateKey privateKey = KeyFactory.getInstance(KEY_ALGO).generatePrivate(pkcs8KeySpec);

        // 对数据加密
        Cipher cipher = Cipher.getInstance(KEY_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * 使用公钥加密
     *
     * @param data 待加密数据
     * @param pubKey 公钥
     */
    private static final byte[] encryptWithPubKey(byte[] data, byte[] pubKey) throws Exception {

        // 生成公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKey);
        PublicKey publicKey = KeyFactory.getInstance(KEY_ALGO).generatePublic(x509KeySpec);

        // 对数据进行加密
        Cipher cipher = Cipher.getInstance(KEY_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     * 使用私钥解密
     *
     * @param data 待解密数据
     * @param priKey 私钥
     */
    private static final byte[] decryptWithPriKey(byte[] data, byte[] priKey) throws Exception {

        // 生成私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(priKey);
        PrivateKey privateKey = KeyFactory.getInstance(KEY_ALGO).generatePrivate(pkcs8KeySpec);

        // 对数据解密
        Cipher cipher = Cipher.getInstance(KEY_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * 使用公钥解密
     *
     * @param data 待解密数据
     * @param pubKey 公钥
     */
    private static final byte[] decryptWithPubKey(byte[] data, byte[] pubKey) throws Exception {

        // 生成公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKey);
        PublicKey publicKey = KeyFactory.getInstance(KEY_ALGO).generatePublic(x509KeySpec);

        // 对数据解密
        Cipher cipher = Cipher.getInstance(KEY_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {

        String plainText = "hello world, lennydou!!!";

        // 生成 RSA 密钥对
        Pair<RSAPrivateKey, RSAPublicKey> keyPair = initKey();

        // 使用私钥加密, 公钥解密
        byte[] data1 = encryptWithPriKey(plainText.getBytes("utf-8"), keyPair.getLeft().getEncoded());
        byte[] data2 = decryptWithPubKey(data1, keyPair.getRight().getEncoded());
        System.out.println(new String(data2));

        // 使用公钥加密, 私钥解密
        byte[] data3 = encryptWithPubKey(plainText.getBytes("utf-8"), keyPair.getRight().getEncoded());
        byte[] data4 = decryptWithPriKey(data3, keyPair.getLeft().getEncoded());
        System.out.println(new String(data4));
    }
}
