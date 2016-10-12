package com.lendou.async;

import org.apache.commons.lang3.tuple.Pair;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 常用非对称加密算法
 * DSA 是EIGamal算法的特殊实现
 *
 * JCE不支持EIGamal算法
 */
public class ElGamalMain {

    private static final String KEY_ALGO = "ElGamal";
    private static final int KEY_SIZE = 256;

    private static Pair<PrivateKey, PublicKey> initKey() throws Exception {

        // 实例化算法参数生成器
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(KEY_ALGO);
        apg.init(KEY_SIZE);

        // 生成算法参数
        AlgorithmParameters params = apg.generateParameters();
        DHParameterSpec elParams = params.getParameterSpec(DHParameterSpec.class);

        // 实例化密钥生成器
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGO);
        kpg.initialize(elParams, new SecureRandom());

        // 生成密钥对
        KeyPair keyPair = kpg.genKeyPair();

        // 取得密钥
        return Pair.of(keyPair.getPrivate(), keyPair.getPublic());
    }

    private static byte[] encryptByPubKey(byte[] data, byte[] key) throws Exception {

        // 公钥材料转换
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);

        // 实例化密钥工厂
        Key publicKey = KeyFactory.getInstance(KEY_ALGO).generatePublic(x509KeySpec);

        // 对数据进行加密
        Cipher cipher = Cipher.getInstance(KEY_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static byte[] decryptByPriKey(byte[] data, byte[] key) throws Exception {

        // 私钥材料转换
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);

        // 实例化密钥工厂, 并生成私钥
        Key privateKey = KeyFactory.getInstance(KEY_ALGO).generatePrivate(pkcs8KeySpec);

        // 解密数据
        Cipher cipher = Cipher.getInstance(KEY_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {

        String plainText = "hello world, lennydou!!!";

        Pair<PrivateKey, PublicKey> keyPair = initKey();
        byte[] data = encryptByPubKey(plainText.getBytes("utf-8"), keyPair.getRight().getEncoded());
        byte[] data2 = decryptByPriKey(data, keyPair.getLeft().getEncoded());

        System.out.println(new String(data2));
    }
}