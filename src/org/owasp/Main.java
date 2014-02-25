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

        final String key = "this is key";
        final String plaintext = "this is the message";

        StringEnvelope env = new StringEnvelope();

        System.out.println("Plaintext=" + plaintext);
        String wrapped = env.wrap(plaintext, key);

        System.out.println("Encrypted=" + wrapped);

        System.out.println("Decrypted=" + env.unwrap(wrapped, key));
    }
}
