package org.sperle.keepass.crypto.bc;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.sperle.keepass.crypto.PasswordCipher;

public class RC4Cipher implements PasswordCipher {
    public static final String NAME = "RC4";

    public String getName() {
        return NAME;
    }

    public byte[] encrypt(byte[] key, byte[] plainText) {
        StreamCipher cipher = new RC4Engine();
        cipher.init(true, new KeyParameter(key));
        byte[] encyptedText = new byte[plainText.length];
        cipher.processBytes(plainText, 0, plainText.length, encyptedText, 0);
        return encyptedText;
    }

    public byte[] decrypt(byte[] key, byte[] cipherText) {
        StreamCipher cipher = new RC4Engine();
        cipher.init(false, new KeyParameter(key));
        byte[] plainText = new byte[cipherText.length];
        cipher.processBytes(cipherText, 0, cipherText.length, plainText, 0);
        return plainText;
    }
}
