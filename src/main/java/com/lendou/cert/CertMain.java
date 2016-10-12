package com.lendou.cert;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * 数字证书具备常规加密/解密必要的信息, 包含签名算法, 可用于网络加密/解密交互标识网络用户(计算机)身份.
 * 数字证书为发布公钥提供了一种简单的途径，其数字证书则成为加密算法以及公钥的载体
 *
 * 数字证书中最为常用的非对称加密算法是 RSA 算法, 与之配套的签名算法是 SHA1WithRSA 算法, 最为常用的消息摘要算法是 SHA1 算法
 */
public class CertMain {

    private static final String CERT_TYPE = "X.509";

    private static final String KEY_STORE_PATH = "/opt/keys/test/zlex.keystore";
    private static final String CERT_PATH = "/opt/keys/test/zlex.cer";
    private static final String ALIAS = "www.zlex.org";

    private static final String KEY_STORE_PWD = "123456";

    private static KeyStore getKeyStore() throws Exception {
        // 实例化密钥库
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        // 获得密钥库文件流
        FileInputStream fis = new FileInputStream(KEY_STORE_PATH);
        ks.load(fis, KEY_STORE_PWD.toCharArray());

        // 关闭密钥库文件流
        fis.close();

        return ks;
    }

    private static Certificate getCertFromStore() throws Exception {

        // 获得密钥库
        KeyStore ks = getKeyStore();

        // 获得证书
        return ks.getCertificate(ALIAS);
    }

    private static Certificate getCertFromFile() throws Exception {

        // 实例化证书工厂
        CertificateFactory certFactory = CertificateFactory.getInstance(CERT_TYPE);

        // 取得证书文件流
        FileInputStream fis = new FileInputStream(CERT_PATH);
        Certificate certificate = certFactory.generateCertificate(fis);
        fis.close();

        return certificate;
    }

    private static byte[] encryptByPriKey(byte[] data) throws Exception {

        // 取得私钥
        PrivateKey privateKey = (PrivateKey) getKeyStore().getKey(ALIAS, KEY_STORE_PWD.toCharArray());

        // 数据加密
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    private static byte[] decryptByPriKey(byte[] data) throws Exception {

        // 取得私钥
        PrivateKey privateKey = (PrivateKey) getKeyStore().getKey(ALIAS, KEY_STORE_PWD.toCharArray());

        // 数据解密
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    private static byte[] encryptByPubKey(byte[] data) throws Exception {

        // 取得公钥
        PublicKey publicKey = getCertFromFile().getPublicKey();

        // 数据加密
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    private static byte[] decryptByPubKey(byte[] data) throws Exception {

        // 取得公钥
        PublicKey publicKey = getCertFromFile().getPublicKey();

        // 数据加密
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    private static byte[] sign(byte[] data) throws Exception {

        // 从 KeyStore 中获得证书 (目的是为了获取其中的签名算法)
        X509Certificate x509Cert = (X509Certificate) getCertFromStore();
        String signAlgo = x509Cert.getSigAlgName();

        // 构建签名, 由证书指定签名算法
        Signature signature = Signature.getInstance(signAlgo);

        // 获取私钥
        PrivateKey privateKey = (PrivateKey) getKeyStore().getKey(ALIAS, KEY_STORE_PWD.toCharArray());

        // 初始化签名, 由私钥构建
        signature.initSign(privateKey);
        signature.update(data);

        return signature.sign();
    }

    private static boolean verify(byte[] data, byte[] signData) throws Exception {

        // 获得证书
        X509Certificate x509Cert = (X509Certificate) getCertFromStore();

        // 由证书构建签名
        Signature signature = Signature.getInstance(x509Cert.getSigAlgName());

        // 由证书初始化签名, 实际上是使用了证书中的公钥
        signature.initVerify(x509Cert);
        signature.update(data);

        return signature.verify(signData);
    }

    public static void main(String[] args) throws Exception {
        test1();
        System.out.println();

        test2();
        System.out.println();

        test3();
    }

    private static void test1() throws Exception {

        System.out.println("公钥加密 - 私钥解密");

        String plainText = "hello world, lennydou!!!";
        byte[] data = plainText.getBytes("utf-8");

        // 公钥加密
        byte[] secData = encryptByPubKey(data);

        // 私钥解密
        byte[] plainData = decryptByPriKey(secData);

        System.out.println("原文: " + plainText);
        System.out.println("结果: " + new String(plainData));
    }

    private static void test2() throws Exception {

        System.out.println("私钥加密 - 公钥解密");

        String plainText = "hello world, lennydou!!!";
        byte[] data = plainText.getBytes("utf-8");

        // 私钥加密
        byte[] secData = encryptByPriKey(data);

        // 公钥解密
        byte[] plainData = decryptByPubKey(secData);

        System.out.println("原文: " + plainText);
        System.out.println("结果: " + new String(plainData));
    }

    private static void test3() throws Exception {

        System.out.println("私钥签名, 公钥验证");

        String plainText = "hello world, lennydou!!!";
        byte[] data = plainText.getBytes("utf-8");

        // 私钥签名
        byte[] signData = sign(data);

        // 公钥验证
        boolean ret = verify(data, signData);

        System.out.println(ret);
    }
}