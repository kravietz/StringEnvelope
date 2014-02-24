package org.owasp;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args)
            throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
	StringEnvelope env = new StringEnvelope((long) 123);

    String wrapped = env.wrap("ss", "aaa");
    System.out.println(wrapped);
    env.unwrap(wrapped, "aaa");
    }
}
