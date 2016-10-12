package com.lendou.digest;

import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;

/**
 * 消息摘要算法
 *
 *   MD5 - 生成32字节结果
 * SHA-1 - 生成40字节结果
 */
public class MessageDigestMain {

    public static void main(String[] args) throws Exception {
        testMd("MD5");
        testMd("SHA");
        testMd("SHA-1");
        testMd("SHA-256");
    }

    private static void testMd(String mdAlgo) throws Exception {
        System.out.println("=== " + mdAlgo + " ===");
        String data = "hello world";

        MessageDigest digest = MessageDigest.getInstance(mdAlgo);
        digest.update(data.getBytes("utf-8"));

        byte[] hash = digest.digest();
        System.out.println(Hex.encodeHex(hash));

        // 当调用 digest() 方法之后, digest对象自动重置
        digest.update(data.getBytes("utf-8"));
        String result = Hex.encodeHexString(digest.digest());
        System.out.println(result + " - " + result.length());

        System.out.println();
    }
}
