package org.owasp;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class Main {

    public static void main(String[] args)
            throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException,
            UnsupportedEncodingException {

        final String key = "test key 1";
        final String plaintext = "this is the message";

        StringEnvelope env = new StringEnvelope();

        env.selfTest();

        System.out.println("Plaintext=" + plaintext);
        String wrapped = env.wrap(plaintext, key);

        System.out.println("Encrypted=" + wrapped);

        System.out.println("Decrypted=" + env.unwrap(wrapped, key));
    }
}
