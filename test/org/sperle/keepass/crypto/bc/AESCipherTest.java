package org.sperle.keepass.crypto.bc;

import org.bouncycastle.util.encoders.Hex;
import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.crypto.KeePassCryptoException;

public class AESCipherTest extends KeePassMobileIOTest {
    private static final String MASTER_PASSWORD = "0123456789abcdef0123456789abcdef";
    private static final String PLAIN_TEXT = "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern";
    private static final String CIPHER_TEXT = "774aa61d147d85f111bf3a517b9f0000fb98b438ea40eeaab6b115307487ab88aafb1986e70fb4f25f312420f73daf7bb01bf3043b8adabe58f6232cab505a24";
    private AESCipher aes;
    
    public AESCipherTest() {
        super(1, "AESCipherTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testAES();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
	aes = new AESCipher();
    }

    public void testAES() throws KeePassCryptoException {
	byte[] cipherText = aes.encrypt(Hex.decode(MASTER_PASSWORD.getBytes()), PLAIN_TEXT.getBytes(), null, 1, true, null);
	assertEquals(CIPHER_TEXT, new String(Hex.encode(cipherText)));
	assertEquals(PLAIN_TEXT, new String(aes.decrypt(Hex.decode(MASTER_PASSWORD.getBytes()), cipherText, null, null)).trim());
    }
}
