package com.lendou.async;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * DH 测试示例
 * 非对称加密算法 - 密钥交换算法
 */
public class DHMain {

    // 非对称加密密钥算法
    private static final String KEY_ALGO = "DH";

    // 本地密钥算法, 即对称密钥算法
    private static final String SECRET_ALGO = "AES";

    // 密钥长度, 必须是 64 的倍数
    private static final int KEY_SIZE = 512;

    private static final String PUBLIC_KEY  = "DHPublicKey";

    private static final String PRIVATE_KEY = "DHPrivateKey";

    /**
     * 生成 Alice 的密钥对
     */
    private static Pair<DHPrivateKey, DHPublicKey> initAliceKey() throws Exception {

        // 实例化密钥生成器, 并初始化密钥是生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGO);
        keyPairGenerator.initialize(KEY_SIZE);

        // 生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 获得 Alice 公钥和私钥
        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();

        return Pair.of(privateKey, publicKey);
    }

    /**
     * 根据 Alice 公钥生成 Bob 密钥对
     *
     * @param key Alice 公钥
     */
    private static Pair<DHPrivateKey, DHPublicKey> initBobKey(byte[] key) throws Exception {

        // 解析 Alice 公钥, 转换密钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);

        // 实例化密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGO);

        // 产生 Alice 公钥
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

        // 由 Alice 公钥生成构建 Bob 密钥
        DHParameterSpec dhParamSpec = ((DHPublicKey) pubKey).getParams();

        // 实例并初始化密钥生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGO);
        keyPairGenerator.initialize(dhParamSpec);

        // 产生密钥对
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        // 获得 Bob 密钥对
        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();

        return Pair.of(privateKey, publicKey);
    }

    /**
     * 生成本地密钥
     * @param priKey
     * @param pubKey
     * @return
     * @throws Exception
     */
    private static byte[] getSecretKey(byte[] priKey, byte[] pubKey) throws Exception {

        // 实例化密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGO);

        // 初始化公钥并产生公钥, 密钥材料转换
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKey);
        PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);

        // 初始化并产生私钥, 密钥材料转换
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(priKey);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 实例化并初始化
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_ALGO);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        // 生成本地密钥
        SecretKey secretKey = keyAgreement.generateSecret(SECRET_ALGO);
        return secretKey.getEncoded();
    }

    /**
     * 加密数据
     *
     * @param data 待加密数据
     * @param key 对称加密密钥
     */
    private static byte[] encrypt(byte[] data, byte[] key) throws Exception {

        // 生成本地密钥
        SecretKey secretKey = new SecretKeySpec(key, SECRET_ALGO);

        // 数据加密
        Cipher cipher = Cipher.getInstance(SECRET_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    /**
     * 解密数据
     *
     * @param data 密文
     * @param key 对称加密密钥
     */
    private static byte[] decrypt(byte[] data, byte[] key) throws Exception {

        // 生成本地密钥
        SecretKey secretKey = new SecretKeySpec(key, SECRET_ALGO);

        // 数据加密
        Cipher cipher = Cipher.getInstance(SECRET_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {

        // 1. 生成 Alice 密钥对
        Pair<DHPrivateKey, DHPublicKey> aliceKeyPair = initAliceKey();
        System.out.println("Alice private key: " + Base64.encodeBase64String(aliceKeyPair.getLeft().getEncoded()));
        System.out.println(" Alice public key: " + Base64.encodeBase64String(aliceKeyPair.getRight().getEncoded()));

        // 2. 通过 Alice 公钥产生 Bob 密钥对
        Pair<DHPrivateKey, DHPublicKey> bobKeyPair = initBobKey(aliceKeyPair.getRight().getEncoded());
        System.out.println("Bob private key: " + Base64.encodeBase64String(bobKeyPair.getLeft().getEncoded()));
        System.out.println(" Bob public key: " + Base64.encodeBase64String(bobKeyPair.getRight().getEncoded()));

        // 3. 根据 Bob 私钥和 Alice 公钥生成 Bob 的对称密钥
        byte[] bobSecretKey = getSecretKey(bobKeyPair.getLeft().getEncoded(), aliceKeyPair.getRight().getEncoded());
        System.out.println("  Bob secret key: " + Base64.encodeBase64String(bobSecretKey));

        // 4. 根据 Alice 私钥和 Bob 公钥生成 Alice 对称密钥
        byte[] aliceSecretKey = getSecretKey(aliceKeyPair.getLeft().getEncoded(), bobKeyPair.getRight().getEncoded());
        System.out.println("Alice secret key: " + Base64.encodeBase64String(aliceSecretKey));
    }
}
