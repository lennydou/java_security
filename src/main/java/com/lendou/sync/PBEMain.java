package com.lendou.sync;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * 基于口令加密
 *
 * 口令并不能代替密钥, 密钥是经过加密算法加密得出的.
 * 口令本身并不能代替密码, 密钥是经过加密计算得出的.
 * 口令不可能很长, 单纯的口令很容易通过穷举攻击的方式破译. 这就需要盐.
 *
 * 盐能够阻止字典攻击, 或预先计算攻击. 它本身是一个随机信息, 相同的随机信息不可能使用两次.
 *
 * 将盐附加在口令上, 通过消息摘要算法经过迭代计算获得构建密钥/初始化向量的基本材料, 使得破译加密信息的难度加大.
 *
 * 常见算法是 PBEWithMD5AndDES, 该算法经过MD5和DES算法构建PBE算法.
 *
 * 盐就是按照明文进行传递的, 盐可以被恶意者获得，但是增大了他们的字典空间.
 * 但是如果只是破解某个人的密钥, 密钥空间并没有增大, 破解出来的时间还是固定的.
 *
 * 加盐加密是一种对系统登录口令的加密方式，它实现的方式是将每一个口令同一个叫做”盐“（salt）的n位随机数相关联。
 * 无论何时只要口令改变，随机数就改变。随机数以未加密的方式存放在口令文件中，这样每个人都可以读。
 * 不再只保存加密过的口令，而是先将口令和随机数连接起来然后一同加密，加密后的结果放在口令文件中。
 */
public class PBEMain {

    private static final String ALGO = "PBEWithMD5AndDES";

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
