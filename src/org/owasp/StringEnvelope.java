package org.owasp;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static java.lang.Math.min;

public class StringEnvelope {

    static final String HASH = "SHA-256";
    static final String HMAC = "HmacSHA256";
    static final String CIPHER = "AES";
    static final String ENCRYPTION = CIPHER + "/CBC/PKCS5Padding";

    public static Long sequence;

    public StringEnvelope(long sequence) {
        this.sequence = sequence;
    }

    private SecretKeySpec deriveKey(String purpose, String key)
            throws NoSuchAlgorithmException, NoSuchPaddingException {

           // derive Java encryption key from string
           // the purpose only serves as multiplexer to get different keys for different purpose
           MessageDigest md = MessageDigest.getInstance(HASH);

        md.update(purpose.getBytes());
           byte[] hash = md.digest(key.getBytes());

            SecretKeySpec keySpec = new SecretKeySpec(Arrays.copyOfRange(hash, 0,
                   Cipher.getInstance(CIPHER).getBlockSize()), CIPHER);
           return keySpec;
     }

    private byte[] deriveIv()
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        ByteBuffer b = ByteBuffer.allocate(Cipher.getInstance(ENCRYPTION).getBlockSize());
        b.putLong(sequence)  ;
        sequence += 1;
        return b.array();
    }

    private void checkSequence(byte[] iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException {

        ByteBuffer b = ByteBuffer.allocate(Cipher.getInstance(ENCRYPTION).getBlockSize());
        b.put(iv);
        System.out.println(b.toString());

        if (b.getLong(0) < sequence)
              throw new IllegalArgumentException("Invalid sequence " + b.getLong());
    }

     public String wrap(String plaintext, String key)
             throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

         // derive two separate sub-keys for encryption and MAC from the supplied string key
         SecretKeySpec macKeySpec = deriveKey("hmac", key);
         SecretKeySpec encKeySpec = deriveKey("encryption", key)  ;

         // encrypt plaintext
         Cipher cipher = Cipher.getInstance(ENCRYPTION);

         IvParameterSpec ivSpec = new IvParameterSpec(deriveIv());

         cipher.init(Cipher.ENCRYPT_MODE, encKeySpec, ivSpec);
         byte[] rawEncrypted = cipher.doFinal(plaintext.getBytes());

         // calculate HMAC over raw encrypted data
         Mac mac = Mac.getInstance(HMAC);
         mac.init(macKeySpec);
         byte[] rawHmac = mac.doFinal(rawEncrypted);

         String strIv = Base64.encode(ivSpec.getIV());
         System.out.println("strIv=" + strIv + " " + ivSpec.getIV().length);
         String strMac = Base64.encode(rawHmac);
         System.out.println("strMac=" + strMac)    ;
         String strEncrypted = Base64.encode(rawEncrypted);
         System.out.println("strEncrypted=" + strEncrypted)    ;

         return strIv + "-" + strMac + "-" + strEncrypted;
     }

    public String unwrap(String envelope, String key)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        if(!envelope.contains("-"))
            throw new IllegalArgumentException("StringEnvelope " + envelope + " should contain -")  ;

        // split into ciphertext and MAC
        String[] parts = envelope.split("-");
        String strIv = parts[0];
        String strMac = parts[1];
        String strEncrypted = parts[2];

        System.out.println("strIv=" + strIv);
        System.out.println("strMac=" + strMac);
        System.out.println("strEncrypted=" + strEncrypted);

        byte[] rawIv = Base64.decode(strIv);
        byte[] rawEncrypted = Base64.decode(strEncrypted);
        byte[] rawMac = Base64.decode(strMac); // received MAC
        byte[] rawRecvMac; // MAC of received cryptogram

        // check sequence number
        checkSequence(rawIv);

        // derive two separate sub-keys for encryption and MAC from the supplied string key
        SecretKeySpec macKeySpec = deriveKey("hmac", key);
        SecretKeySpec encKeySpec = deriveKey("encryption", key)  ;

        // validate MAC
        Mac mac = Mac.getInstance(HMAC);
        mac.init(macKeySpec);
        rawRecvMac = mac.doFinal(rawEncrypted);

        // constant-time compare of MACs
        boolean macsEqual = false;
        for(int i=0; i<min(rawRecvMac.length, rawMac.length); i++) {
             if(rawRecvMac[i] == rawMac[i])
                 macsEqual = true;
            else
                 macsEqual = false;
        }

        if(!macsEqual)
            throw new IllegalArgumentException("Encrypted data MAC does not match");

        // decrypt authentic data
        IvParameterSpec ivSpec = new IvParameterSpec(rawIv);
        Cipher cipher = Cipher.getInstance(ENCRYPTION);
        cipher.init(Cipher.DECRYPT_MODE, encKeySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(rawEncrypted);

        return decrypted.toString();

    }
}
