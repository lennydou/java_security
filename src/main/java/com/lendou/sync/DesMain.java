package com.lendou.sync;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * 测试 DES 加密算法
 *
 * https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html
 */
public class DesMain {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {

        // Create a DES key
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        SecretKey key = keyGen.generateKey();

        // Create a Cipher instance from Cipher class, specify the following information and separated by a slash (/)
        // DES  - Encryption algorithm
        // Mode - Electronic Codebook mode
        // PKCS5Padding - PKCS#5-style padding
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        // Convert a data to byte array
        String text = "hello world, guys!";
        System.out.println("   origin - " + text);

        byte[] data = text.getBytes();

        // Encrypt data
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data);

        System.out.println("encrypted - " + Hex.encodeHexString(encryptedData));

        // Decrypt data
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedData = cipher.doFinal(encryptedData);

        System.out.println("decrypted - "  + new String(decryptedData, "utf-8"));
    }
}