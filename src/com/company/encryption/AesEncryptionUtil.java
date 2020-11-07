package com.company.encryption;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;

public class AesEncryptionUtil {

    private SecretKey secretKey;
    private Cipher cipherEncryption;
    private Cipher cipherDecryption;

    public AesEncryptionUtil(SecretKey secretKey) {
        this.secretKey = secretKey;
        this.setKey(this.secretKey);
    }

    public AesEncryptionUtil(String myKey) {
        this.secretKey = AesEncryptionUtil.stringToKey(myKey);
        this.setKey(this.secretKey);
    }

    public static String generateStringKey(String password)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKey secretKey = generateKey(password);
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static SecretKey stringToKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static SecretKey generateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
       String password =  UUID.randomUUID().toString();
       return generateKey(password);
    }

    public static SecretKey generateKey(String password)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] randomSalt = new byte[100];
        new Random().nextBytes(randomSalt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), randomSalt, 65536, 256);
        SecretKey tmpKey = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmpKey.getEncoded(), "AES");
        return secret;



    }

    public void setKey(String encodedKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKey secretKey = stringToKey(encodedKey);
        this.setKey(secretKey);
    }

    public void setKey(SecretKey secretKey) {

        try {

            this.secretKey = secretKey;
            cipherEncryption = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipherEncryption.init(Cipher.ENCRYPT_MODE, secretKey);

            cipherDecryption = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipherDecryption.init(Cipher.DECRYPT_MODE, secretKey);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] dataToEncrypt) {
        try {
            return cipherEncryption.doFinal(dataToEncrypt);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return new byte[0];
    }

    public void encrypt(ByteBuffer dataToEncrypt, ByteBuffer encryptedData) {
        try {
            cipherEncryption.doFinal(dataToEncrypt, encryptedData);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }

    public byte[] decrypt(byte[] dataToDecrypt) {
        try {
            return cipherDecryption.doFinal(dataToDecrypt);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return new byte[0];
    }

    public void decrypt(ByteBuffer encryptedData, ByteBuffer decryptedData) {
        try {
            cipherDecryption.doFinal(encryptedData, decryptedData);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }

    /*
     *
     *  Geberate key using
     *  Parameters: password
     *
     *  Algorithm: PBKDF2WithHmacSHA256
     *  IterationCount: 65536
     *  KeyLength: 256
     *
     *  On this we use Static Salt, this means that we can generate the same key, using the same password
     *
     */
    public static String generateStringKeyWithStaticSalt(String password)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return generateStringKeyWithStaticSalt("PBKDF2WithHmacSHA256", password, 65536, 256);
    }

    public static String generateStringKeyWithStaticSalt(String instanceName, String password,
                                                         int iterationCount, int keyLength) throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKey secretKey = generateKeyWithStaticSalt(instanceName, password, iterationCount,
                keyLength);
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static SecretKey generateKeyWithStaticSalt(String instanceName, String password,
                                                      int iterationCount, int keyLength) throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(instanceName);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), password.getBytes(), iterationCount,
                keyLength);
        return factory.generateSecret(spec);
    }


}
