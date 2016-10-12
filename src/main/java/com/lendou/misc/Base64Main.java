package com.lendou.misc;

import org.apache.commons.codec.binary.Base64;

/**
 * Base64测试
 */
public class Base64Main {

    public static void main(String[] args) throws Exception {
        String text = "aaabbbcccddeksfoajeojao;jfoiejwoafhjo;ewhafio;jfio;ewjo;fjao;ifjiewafe";
        byte[] data = text.getBytes("utf-8");
        System.out.println(Base64.encodeBase64String(data));
        System.out.println(Base64.encodeBase64URLSafeString(data));
    }
}
