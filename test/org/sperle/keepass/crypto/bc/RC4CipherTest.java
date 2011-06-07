package org.sperle.keepass.crypto.bc;

import org.bouncycastle.util.encoders.Hex;
import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.crypto.KeePassCryptoException;
import org.sperle.keepass.util.Passwords;

public class RC4CipherTest extends KeePassMobileIOTest {
    private static final byte[] TEST_KEY = new byte[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39};
    private static final String PLAIN_TEXT = "Fränz jagt im komplett verwahrlößten Taxi quér durch Bayern!";
    private static final String CIPHER_TEXT = "4de3c0271dbf78a272e3c241bcb71813092faf717cdc78095b0f2bf0849301fe3859c5eec0d9dbe9496cc8f8d14f3311b3bb7354a941f10f74ee9727d43b2009";
    
    private RC4Cipher rc4;
    
    public RC4CipherTest() {
        super(1, "RC4CipherTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testRC4();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
        rc4 = new RC4Cipher(TEST_KEY);
    }

    public void testRC4() throws KeePassCryptoException {
	byte[] cipherText = rc4.encrypt(Passwords.fromString(PLAIN_TEXT));
	assertEquals(CIPHER_TEXT, new String(Hex.encode(cipherText)));
	byte[] plainText = rc4.decrypt(cipherText);
	assertEquals(PLAIN_TEXT, Passwords.toString(plainText));
    }
}
