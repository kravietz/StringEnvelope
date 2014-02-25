package org.owasp;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Arrays;

@SuppressWarnings("BooleanMethodIsAlwaysInverted")
public class StringEnvelope {

    private static final String HASH = "SHA-256";
    private static final String HMAC = "HmacSHA256";
    private static final String CIPHER = "AES";
    private static final String ENCRYPTION = CIPHER + "/CBC/PKCS5Padding";
    private static final SecureRandom secureRandom = new SecureRandom();

    private static boolean isEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    private static SecretKeySpec deriveKey(String purpose, String key)
    throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {

        // derive Java encryption key from string
        // the purpose only serves as multiplexer to get different keys for different purpose
        MessageDigest md = MessageDigest.getInstance(HASH);

        md.update(purpose.getBytes("UTF-8"));
        byte[] hash = md.digest(key.getBytes("UTF-8"));

        return new SecretKeySpec(Arrays.copyOfRange(hash, 0,
                Cipher.getInstance(CIPHER).getBlockSize()), CIPHER);
    }

    private static byte[] deriveIv()
    throws NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] iv = new byte[Cipher.getInstance(ENCRYPTION).getBlockSize()];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static String wrap(String plaintext, String key)
    throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException {

        // derive two separate sub-keys for encryption and MAC from the supplied string key
        SecretKeySpec macKeySpec = deriveKey("hmac", key);
        SecretKeySpec encKeySpec = deriveKey("encryption", key);

        // encrypt plaintext
        Cipher cipher = Cipher.getInstance(ENCRYPTION);

        IvParameterSpec ivSpec = new IvParameterSpec(deriveIv());

        cipher.init(Cipher.ENCRYPT_MODE, encKeySpec, ivSpec);
        byte[] rawEncrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));

        // calculate HMAC over raw encrypted data
        Mac mac = Mac.getInstance(HMAC);
        mac.init(macKeySpec);
        byte[] rawHmac = mac.doFinal(rawEncrypted);

        String strIv = Base64.encode(ivSpec.getIV());
        String strMac = Base64.encode(rawHmac);
        String strEncrypted = Base64.encode(rawEncrypted);

        return strIv + "-" + strMac + "-" + strEncrypted;
    }

    public static String unwrap(String envelope, String key)
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

        if (!isEqual(rawMac, rawRecvMac))
            throw new IllegalArgumentException("Encrypted data MAC does not match");

        // decrypt authentic data
        IvParameterSpec ivSpec = new IvParameterSpec(rawIv);
        Cipher cipher = Cipher.getInstance(ENCRYPTION);
        cipher.init(Cipher.DECRYPT_MODE, encKeySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(rawEncrypted);

        return new String(decrypted, "UTF8");

    }

    private static final String[][] testVectors = {
            {"deriveKey", "test key 1", "", "QtzGfMLFHf+iAbNAq0iAuQ=="},
            {"deriveKey", "test key 2", "", "Uc10OVlLnyx/q15eyQL64w=="},
            {"deriveKey", "test key ąćęłńóśżź", "", "JTfvXe9hs1ER+VdLN8cMcQ=="},
            // derive() output will be each time different, so we check length
            {"deriveIv", "", "", "16"},
            // wrap() output will be each time different so we check length
            {"wrap", "test key", "test input", "94"},
            {"wrap", "ąćęłńóśżź", "ąćęłńóśżź", "114"},
            {"wrap", "Poćmękłanobzdrężyłłopaćpolerta", "комплекс карательных мер, проводившихся большевиками в ходе Гражданской войны", "134"},
            // unwrap test will replace expect with the original plaintext
            {"unwrap", "test key", "test input", "plaintext"},
            {"unwrap", "ąćęłńóśżź", "ąćęłńóśżź", "plaintext"},
            {"unwrap", "Poćmękłanobzdrężyłłopaćpolerta", "комплекс карательных мер, проводившихся большевиками в ходе Гражданской войны", "plaintext"},
    };

    public static boolean selfTest()
            throws NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        int fails = 0;
        int i = 0;


        for (i = 0; i < testVectors.length; i++) {
            String[] vector = testVectors[i];
            String function = vector[0];
            String input1 = vector[1];
            String input2 = vector[2];
            String expect = vector[3];
            String actual = "";

            if (function.equals("deriveKey")) {
                final String purpose = "self test";
                SecretKeySpec secretKeySpec = deriveKey(purpose, input1);
                actual = Base64.encode(secretKeySpec.getEncoded());
            }
            if (function.equals("deriveIv")) {
                byte[] iv = deriveIv();
                actual = Integer.toString(iv.length);
            }
            if (function.equals("wrap")) {
                String key = input2;
                String plaintext = input1;
                actual = Integer.toString(wrap(plaintext, key).length());
            }
            if (function.equals("unwrap")) {
                String key = input2;
                String plaintext = input1;
                expect = plaintext;
                actual = unwrap(wrap(plaintext, key), key);
            }

            System.out.println("function='" + function + "' input1='" + input1 + "' input2='" + input2 + "' expect='" + expect + "' actual='" + actual + "'");

            if (!actual.equals(expect))
                fails++;
        }

        // deriveIv() - each should be unique
        System.out.print("deriveIv() continuous uniqueness test");
        for (i = 0; i < 10; i++) {
            String buf, newbuf;
            System.out.print(".");

            buf = wrap("plaintext", "key");
            newbuf = wrap("plaintext", "key");

            if (buf.equals(newbuf)) {
                System.out.print("!");
                fails++;
            }

        }
        System.out.println("");

        // wrap() - each should be unique
        System.out.print("wrap() continuous uniqueness test");
        for (i = 0; i < 10; i++) {
            byte[] buf, newbuf;
            System.out.print(".");

            buf = deriveIv();
            newbuf = deriveIv();

            if (buf.equals(newbuf)) {
                System.out.print("!");
                fails++;
            }

        }
        System.out.println("");

        // unwrap() - continous integrity test
        System.out.println("unwrap() continuous integrity test");
        for (i = 0; i < 100; i++) {
            byte[] ciphertext = wrap("plaintext", "key").getBytes();
            // modify ciphertext at random offset (can be inIV, MAC or ciphertext)
            int index = secureRandom.nextInt(ciphertext.length);
            ciphertext[index] ^= 1;
            try {
                unwrap(new String(ciphertext, "UTF8"), "key");
                fails++;
            } catch (IllegalArgumentException e) {
                System.out.println(e);
            } catch (BadPaddingException e) {
                System.out.println(e);
            }

        }
        System.out.println("");

        // end of tests
        System.out.println("fails=" + fails);
        return fails == 0;
    }
}
