package com.company;

import com.company.encryption.AesEncryptionUtil;
import com.company.encryption.RsaEncryptionUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;


public class Main {

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        aesEncryption();
        rsaEncryption();
    }

    private static void rsaEncryption() throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        byte[] dataToEncrypt = new byte[100];
        byte[] encryptedData;
        byte[] decryptedData;

        new Random().nextBytes(dataToEncrypt);

        KeyPair keyPair = RsaEncryptionUtil.generateKey();
        String publicKey = RsaEncryptionUtil.getKeyAsString(keyPair.getPublic());
        String privateKey = RsaEncryptionUtil.getKeyAsString(keyPair.getPrivate());

        RsaEncryptionUtil rsaEncryptionUtil  = new RsaEncryptionUtil();
        rsaEncryptionUtil.setKey(publicKey);

        long start = System.nanoTime();
        encryptedData = rsaEncryptionUtil.encrypt(dataToEncrypt);
        long encryptionTime = System.nanoTime() - start;

        start = System.nanoTime();
        decryptedData = rsaEncryptionUtil.decrypt(encryptedData, keyPair.getPrivate());
        long decryptionTime = System.nanoTime() - start;



        System.out.println("\n ------ RSA Algorithm ------ \n " );

        System.out.println("1. Data to be encrypted: "+ Base64.getEncoder().encodeToString(dataToEncrypt) );
        System.out.println("2. Encrypted data: "+ Base64.getEncoder().encodeToString(encryptedData) );
        System.out.println("3. Decrypted data: "+ Base64.getEncoder().encodeToString(decryptedData) );

        System.out.print("4. Encryption time (seconds): ");
        System.out.println(  encryptionTime / 1000000.0 );

        System.out.print("5. Decryption time (seconds): ");
       System.out.println(  decryptionTime / 1000000.0 );

    }

    private static void aesEncryption() throws InvalidKeySpecException, NoSuchAlgorithmException {

        byte[] dataToEncrypt = new byte[100];
        new Random().nextBytes(dataToEncrypt);

        SecretKey secretKey = AesEncryptionUtil.generateKey();
        AesEncryptionUtil aesEncryptionUtil = new AesEncryptionUtil(secretKey);

        long start = System.nanoTime();
        byte[] encryptedData = aesEncryptionUtil.encrypt(dataToEncrypt);
        long encryptionTime = System.nanoTime() - start;


         start = System.nanoTime();
        byte[] decryptedData = aesEncryptionUtil.decrypt(encryptedData);
        long decryptionTime = System.nanoTime() - start;

        System.out.println("\n ------ AES Algorithm ------ \n " );

        System.out.println("1. Data to be encrypted: "+ Base64.getEncoder().encodeToString(dataToEncrypt) );
        System.out.println("2. Encrypted data: "+ Base64.getEncoder().encodeToString(encryptedData) );
        System.out.println("3. Decrypted data: "+ Base64.getEncoder().encodeToString(decryptedData) );

        System.out.print("4. Encryption time (seconds): ");
        System.out.println(  encryptionTime / 1000000.0 );

        System.out.print("5. Decryption time (seconds): ");
        System.out.println(  decryptionTime / 1000000.0 );

    }

}
