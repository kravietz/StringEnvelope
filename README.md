StringEnvelope
==============

Easy to use class providing integrity, authenticity and confidentiality protection for strings in Java. Usage:

    StringEnvelope env = new StringEnvelope();
    String ciphertext = env.wrap("plaintext", "key");

The `wrap()` methods returns a BASE64 encoded object with integrity and authenticity protection embedded. Example:

    Mt2sTCX+FbKeIxCRLFHY5A==-hSQPO5vOZgJpo3X/OqrqWGulP905BQlA3Ued9xa0LAo=-LJECPots4J/DX+im2b4wWA==

International scripts are fully supported with UTF-8 encoding:

    wrap("комплекс карательных мер", "key")
    hwSh9urBMkH5vw09J22l2A==-AA2Pbyyylqpvl7TBvtG+l98FYYr7EooGpZG6k56A2sM=-IsUMNpIcxVO+XxPpK265NUtZQ1N9U9dMvu77Nj9TF9P9f6Mo6Yn4W8q3iZ9p3uKe
    unwrap(...) = "комплекс карательных мер"

The `unwrap()` method provides decryption with identity and authenticity validation:

    String plaintext = env.unwrap(ciphertext, "key");

On integrity error an exception will be thrown, so `try/catch` should be used. Details on why decryption
failed are returned in the exception, but it's usually because the encrypted block was modified or malformed:

    try {
        String plaintext = env.unwrap(ciphertext, "key");
    catch (IllegalArgumentException e) {
        System.out.println("Decryption failed: " + e);
    }

The class also has a built-in self-test method that returns `true` if the implementation works as expected.

    if (!env.selfTest())
            throw new InternalError("self test failed");

The self-test should be normally called when the class is initialised so that possible buggy or old Java
implementations can be detected before they impair the encryption.

# Integration with Play framework

See [play-crypto](https://github.com/kravietz/play-crypto/) for sample Play framework application using StringEnvelope.
