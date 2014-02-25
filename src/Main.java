import org.owasp.StringEnvelope;

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

        final String key = "key";
        final String plaintext = "комплекс карательных мер";

        StringEnvelope env = new StringEnvelope();

        assert env.selfTest();

        System.out.println("Plaintext=" + plaintext);
        String wrapped = env.wrap(plaintext, key);

        System.out.println("Encrypted=" + wrapped);

        System.out.println("Decrypted=" + env.unwrap(wrapped, key));

        System.out.println("Configuration: " + env.getInfo());
    }
}
