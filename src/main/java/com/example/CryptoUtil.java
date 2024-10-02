package com.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class CryptoUtil {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return base64UrlSafeEncode(encryptedBytes);
    }

    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(base64UrlSafeDecode(encryptedData));
        return new String(decryptedBytes);
    }

    private static String base64UrlSafeEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] base64UrlSafeDecode(String data) {
        return Base64.getUrlDecoder().decode(data);
    }

    public static void main(String[] args) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();

        String originalData = "nome_file";
        String encrypted = encrypt(originalData, key);
        String decrypted = decrypt(encrypted, key);

        System.out.println("Originale: " + originalData);
        System.out.println("Crittografato: " + encrypted);
        System.out.println("Decrittografato: " + decrypted);
    }
}
