// Java program to implement the
// encryption and decryption

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Time;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec
        .IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind
        .DatatypeConverter;

// Creating the symmetric
// class which implements
// the symmetric
public class Symmetric_Encryption_Cryptography {

    //ADVANCED ENCRYPTION STANDARD
    private static final String AES
            = "AES";

    // We are using a Block cipher(CBC mode)
    private static final String AES_CIPHER_ALGORITHM
            = "AES/CBC/PKCS5PADDING";

    private static Scanner message;

    // Function to create a
    // secret key
    /*SecureRandom() constructs a random secured number generator using default random number algorithm.*/
    public static SecretKey createAESKey()
            throws Exception {
        // Creating a new instance of
        // SecureRandom class.
        SecureRandom securerandom = new SecureRandom();

        // Passing the string to
        // KeyGenerator
        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);


        // Initializing the KeyGenerator
        // with 256 bits.
        keygenerator.init(256, securerandom);
        SecretKey key = keygenerator.generateKey();

        return key;
    }

    public static SecretKey convertStringToSecretKeyto(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }

    public static SecretKey getKeyFromString(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), AES);
        return secret;
    }

    public static SecretKey decodeBase64ToAESKey(final String encodedKey)
            throws IllegalArgumentException {
        try {
            // throws IllegalArgumentException - if src is not in valid Base64
            // scheme
            final byte[] keyData = Base64.getDecoder().decode(encodedKey);
            final int keysize = keyData.length * Byte.SIZE;

            // this should be checked by a SecretKeyFactory, but that doesn't exist for AES
            switch (keysize) {
                case 128:
                case 192:
                case 256:
                    break;
                default:
                    throw new IllegalArgumentException("Invalid key size for AES: " + keysize);
            }

            if (Cipher.getMaxAllowedKeyLength("AES") < keysize) {
                // this may be an issue if unlimited crypto is not installed
                throw new IllegalArgumentException("Key size of " + keysize
                        + " not supported in this runtime");
            }

            // throws IllegalArgumentException - if key is empty
            final SecretKeySpec aesKey = new SecretKeySpec(keyData, "AES");
            return aesKey;
        } catch (final NoSuchAlgorithmException e) {
            // AES functionality is a requirement for any Java SE runtime
            throw new IllegalStateException(
                    "AES should always be present in a Java SE runtime", e);
        }
    }


    // Function to initialize a vector
    // with an arbitrary value
    public static byte[] createInitializationVector() {

        /*SecureRandom(byte[] seed) SecureRandom instance is seeded with the specified seed bytes. The parameters required by this constructor is a seed.*/
        // Used with encryption
        byte[] initializationVector
                = new byte[16];
        SecureRandom secureRandom
                = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    // This function takes plaintext,
    // the key with an initialization
    // vector to convert plainText
    // into CipherText.
    public static byte[] do_AESEncryption(
            String plainText,
            SecretKey secretKey,
            byte[] initializationVector)
            throws Exception {
        Cipher cipher
                = Cipher.getInstance(
                AES_CIPHER_ALGORITHM);

        IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                initializationVector);

        cipher.init(Cipher.ENCRYPT_MODE,
                secretKey,
                ivParameterSpec);

        return cipher.doFinal(
                plainText.getBytes());
    }

    // This function performs the
    // reverse operation of the
    // do_AESEncryption function.
    // It converts ciphertext to
    // the plaintext using the key.
    public static String do_AESDecryption(
            byte[] cipherText,
            SecretKey secretKey,
            byte[] initializationVector)
            throws Exception {
        Cipher cipher
                = Cipher.getInstance(
                AES_CIPHER_ALGORITHM);

        IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                initializationVector);

        cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                ivParameterSpec);

        byte[] result
                = cipher.doFinal(cipherText);

        return new String(result);
    }

    // Driver code
    public static void main(String args[])
            throws Exception {
        SecretKey Symmetrickey = createAESKey();
//        SecretKey Symmetrickey = getKeyFromString("CF2549D817BDCA65A1DEA033D87C248C1A9011AB7CB854EE8565874FE57B19BE", "SEENA_KEY_SALT");
        System.out.println(
                "The Symmetric Key is :"
                        + DatatypeConverter.printHexBinary(
                        Symmetrickey.getEncoded()));

        byte[] initializationVector
                = createInitializationVector();

        String plainText
                = "This is the message "
                + "I want To Encryp 01148204886.";

        // Encrypting the message
        // using the symmetric key
        byte[] cipherText
                = do_AESEncryption(
                plainText,
                Symmetrickey,
                initializationVector);

        System.out.println(
                "The ciphertext or "
                        + "Encrypted Message is: "
                        + DatatypeConverter.printHexBinary(
                        cipherText));

        // Decrypting the encrypted
        // message
        String decryptedText
                = do_AESDecryption(
                cipherText,
                Symmetrickey,
                initializationVector);

        System.out.println(
                "Your original message is: "
                        + decryptedText);
        System.out.println(System.currentTimeMillis());


    }
}
