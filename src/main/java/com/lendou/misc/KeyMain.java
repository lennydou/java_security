package com.lendou.misc;

import org.apache.commons.codec.binary.Hex;

import java.security.AlgorithmParameters;

/**
 * 密钥测试类
 */
public class KeyMain {

    public static void main(String[] args) throws Exception {
        test();
    }

    private static void test() throws Exception {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("DES");
        System.out.println(Hex.encodeHexString(ap.getEncoded()));
    }
}
