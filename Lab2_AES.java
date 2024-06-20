package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class Lab2_2105088_Alanoud {
    private static final int keySize = 128;

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException {

            System.out.println("Enter the message : ");
            Scanner input = new Scanner(System.in);
            String MSG = input.nextLine();

            //Invoke methods that generate the key and initial vector(IV)
            SecretKey S_key = keyGenerator(keySize);
            IvParameterSpec initialV = IVgenerator();
            //Create the Cipher object with AES algorithm Using CBC mode
            Cipher cipher = Cipher .getInstance("AES/CBC/PKCS5Padding");

            String ciphertext = encrypt(cipher , MSG ,S_key , initialV);
            String plaintext = decrypt(cipher , ciphertext , S_key , initialV);

            System.out.println("Original message : " +MSG+ "\n"+ "Ciphertext : "
                    + ciphertext + "\n"+ "Plaintext : " +plaintext);

        }
        //------------------------------------------------------------------------------------------------------//

        //This method for generating the key
        public static SecretKey keyGenerator (int keySize) throws NoSuchAlgorithmException {
            KeyGenerator Generator = KeyGenerator.getInstance( "AES");
            Generator.init(keySize);
            SecretKey S_key = Generator.generateKey();
            return S_key;}

        //------------------------------------------------------------------------------------------------------//

        //this method for generating IV (initial vector). It is using in CBC mode
        // It has a fixed size(16),It should be random
        public static IvParameterSpec IVgenerator() {
            byte[] iv = new byte[16];
            //generate random number from random source
            SecureRandom randomNumber = new SecureRandom();
            randomNumber.nextBytes(iv);
            IvParameterSpec InitialV= new IvParameterSpec(iv);
            return  InitialV;

        }

        //------------------------------------------------------------------------------------------------------//

        //ENCRYPTION METHOD
        public static String encrypt(Cipher c,String MSG, SecretKey S_key , IvParameterSpec iv)
                throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

            //configure a cipher instance using the init() method with key,iv , and encryption mode (encryption).
            c.init(Cipher.ENCRYPT_MODE , S_key , iv);
            //encrypt input message by invoke doFinal method .It gets the input in bytes and return it in bytes
            byte [] MSG_bytes = MSG.getBytes();
            byte[] cipherText = c.doFinal(MSG_bytes);
            //convert the encrypted message to string
            return Base64.getEncoder().encodeToString(cipherText);
        }

        public static String decrypt(Cipher c, String cipherText , SecretKey S_key ,IvParameterSpec iv )
                throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            //configure a cipher instance using the init() method with key,iv , and encryption mode (decryption).
            c.init(Cipher.DECRYPT_MODE  , S_key , iv);
            // decrypt the message by invoke doFinal method
            byte[] plainText = c.doFinal(Base64.getDecoder().decode(cipherText)) ;
            //convert the decrypted bytes to string
            String S_Plaintext = new String(plainText);
            return  S_Plaintext;

        }



    }

