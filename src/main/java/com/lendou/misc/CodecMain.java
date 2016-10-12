package com.lendou.misc;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.UnsupportedEncodingException;

/**
 * 测试 org.apache.common.codec
 */
public class CodecMain {

    public static void main(String[] args) throws UnsupportedEncodingException {
        testCrypt();
        System.out.println();

        testMd();
        System.out.println();

        testBase64();
        System.out.println();
    }

    private static void testCrypt() {
        String plainPwd = "lennydou123456";
        String strongPwd = Crypt.crypt(plainPwd);
        System.out.println("strongPwd1 - " + strongPwd + " - " + strongPwd.length());

        // 具体的密钥生成看 crypt 方法注释
        String strongPwd2 = Crypt.crypt(plainPwd, "abcdefghijk");
        System.out.println("strongPwd2 - " + strongPwd2 + " - " + strongPwd2.length());
    }

    private static void testMd() {
        String plain = "hello world, lennydou!!!";
        String md5Text = DigestUtils.md5Hex(plain);
        System.out.println(" md5 - " + md5Text + " - " + md5Text.length());

        String sha1Text = DigestUtils.sha1Hex(plain);
        System.out.println("sha1 - " + sha1Text + " - " + sha1Text.length());
    }

    private static void testBase64() throws UnsupportedEncodingException {
        String plain = "hello world, lennydou!!!";
        String base64Text = Base64.encodeBase64URLSafeString(plain.getBytes("utf-8"));

        System.out.println("plain - " + plain);
        System.out.println(base64Text + " - " + base64Text.length());
    }
}