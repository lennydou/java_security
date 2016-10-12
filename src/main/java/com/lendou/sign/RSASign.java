package com.lendou.sign;

import org.apache.commons.lang3.tuple.Pair;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 使用 RSA 算法做数据签名
 */
public class RSASign {

    private static final String KEY_ALGO = "RSA";
    private static final String SIGN_ALGO = "MD5WithRSA";
    private static final int KEY_SIZE = 512;

    private static Pair<RSAPrivateKey, RSAPublicKey> initKey() throws Exception {

        // 实例化密钥生成器
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGO);
        kpg.initialize(KEY_SIZE);

        // 生成密钥对
        KeyPair keyPair = kpg.generateKeyPair();

        // 生成公钥和私钥
        return Pair.of((RSAPrivateKey) keyPair.getPrivate(), (RSAPublicKey) keyPair.getPublic());
    }

    private static byte[] sign(byte[] data, byte[] priKey) throws Exception {

        // 转换私钥材料
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(priKey);

        // 生成私钥
        PrivateKey privateKey = KeyFactory.getInstance(KEY_ALGO).generatePrivate(pkcs8KeySpec);

        // 实例化 Signature 对象
        Signature signature = Signature.getInstance(SIGN_ALGO);
        signature.initSign(privateKey);

        // 更新
        signature.update(data);

        // 生成签名信息
        return signature.sign();
    }

    private static boolean verify(byte[] data, byte[] pubKey, byte[] signData) throws Exception {

        // 转换公钥材料
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKey);

        // 生成公钥
        PublicKey publicKey = KeyFactory.getInstance(KEY_ALGO).generatePublic(x509KeySpec);

        // 实例化 Signature
        Signature signature = Signature.getInstance(SIGN_ALGO);
        signature.initVerify(publicKey);

        // 更新数据
        signature.update(data);

        // 验证签名
        return signature.verify(signData);
    }

    public static void main(String[] args) throws Exception {

        String plainText = "hello world, lennydou!!!";

        // 生成密钥对
        Pair<RSAPrivateKey, RSAPublicKey> keyPair = initKey();

        // 对 plainText 进行签名
        byte[] signData = sign(plainText.getBytes("utf-8"), keyPair.getLeft().getEncoded());

        // 对签名结果进行验证
        boolean ret = verify(plainText.getBytes("utf-8"), keyPair.getRight().getEncoded(), signData);

        System.out.println(ret);
    }
}
