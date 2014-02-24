package org.owasp;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Arrays;

import static java.lang.Math.min;

public class StringEnvelope {

    static final String HASH = "SHA-256";
    static final String HMAC = "HmacSHA256";
    static final String CIPHER = "AES";
    static final String ENCRYPTION = CIPHER + "/CBC/PKCS5Padding";
    static SecureRandom secureRandom = new SecureRandom();

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
        byte[] iv = new byte[Cipher.getInstance(ENCRYPTION).getBlockSize()];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public String wrap(String plaintext, String key)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException {

        // derive two separate sub-keys for encryption and MAC from the supplied string key
        SecretKeySpec macKeySpec = deriveKey("hmac", key);
        SecretKeySpec encKeySpec = deriveKey("encryption", key);

        // encrypt plaintext
        Cipher cipher = Cipher.getInstance(ENCRYPTION);

        IvParameterSpec ivSpec = new IvParameterSpec(deriveIv());

        cipher.init(Cipher.ENCRYPT_MODE, encKeySpec, ivSpec);
        byte[] rawEncrypted = cipher.doFinal(plaintext.getBytes("UTF8"));

        // calculate HMAC over raw encrypted data
        Mac mac = Mac.getInstance(HMAC);
        mac.init(macKeySpec);
        byte[] rawHmac = mac.doFinal(rawEncrypted);

        String strIv = Base64.encode(ivSpec.getIV());
        String strMac = Base64.encode(rawHmac);
        String strEncrypted = Base64.encode(rawEncrypted);

        return strIv + "-" + strMac + "-" + strEncrypted;
    }

    public String unwrap(String envelope, String key)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        if (!envelope.contains("-"))
            throw new IllegalArgumentException("StringEnvelope " + envelope + " should contain -");

        // split into ciphertext and MAC
        String[] parts = envelope.split("-");
        String strIv = parts[0];
        String strMac = parts[1];
        String strEncrypted = parts[2];

        byte[] rawIv = Base64.decode(strIv);
        byte[] rawEncrypted = Base64.decode(strEncrypted);
        byte[] rawMac = Base64.decode(strMac); // received MAC
        byte[] rawRecvMac; // MAC of received cryptogram

        // derive two separate sub-keys for encryption and MAC from the supplied string key
        SecretKeySpec macKeySpec = deriveKey("hmac", key);
        SecretKeySpec encKeySpec = deriveKey("encryption", key);

        // validate MAC
        Mac mac = Mac.getInstance(HMAC);
        mac.init(macKeySpec);
        rawRecvMac = mac.doFinal(rawEncrypted);

        // constant-time compare of MACs
        boolean macsEqual = false;
        for (int i = 0; i < min(rawRecvMac.length, rawMac.length); i++) {
            if (rawRecvMac[i] == rawMac[i])
                macsEqual = true;
            else
                macsEqual = false;
        }

        if (!macsEqual)
            throw new IllegalArgumentException("Encrypted data MAC does not match");

        // decrypt authentic data
        IvParameterSpec ivSpec = new IvParameterSpec(rawIv);
        Cipher cipher = Cipher.getInstance(ENCRYPTION);
        cipher.init(Cipher.DECRYPT_MODE, encKeySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(rawEncrypted);

        return new String(decrypted, "UTF8");

    }
}
