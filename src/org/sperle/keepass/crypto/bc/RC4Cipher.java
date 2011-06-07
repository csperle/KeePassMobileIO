package org.sperle.keepass.crypto.bc;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.sperle.keepass.crypto.PasswordCipher;

/**
 * This password cipher uses the 'RC4' algorithm to encrypt and decrypt a password.
 */
public class RC4Cipher implements PasswordCipher {
    public static final String NAME = "RC4";
    public static final int KEY_LENGTH = 92;

    private transient byte[] key;
    
    public RC4Cipher(byte[] key) {
        this.key = key;
    }
    
    public String getName() {
        return NAME;
    }

    public byte[] encrypt(byte[] plainPassword) {
        StreamCipher cipher = new RC4Engine();
        cipher.init(true, new KeyParameter(key));
        byte[] encyptedText = new byte[plainPassword.length];
        cipher.processBytes(plainPassword, 0, plainPassword.length, encyptedText, 0);
        return encyptedText;
    }

    public byte[] decrypt(byte[] cipherPassword) {
        StreamCipher cipher = new RC4Engine();
        cipher.init(false, new KeyParameter(key));
        byte[] plainText = new byte[cipherPassword.length];
        cipher.processBytes(cipherPassword, 0, cipherPassword.length, plainText, 0);
        return plainText;
    }
}
