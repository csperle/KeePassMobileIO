package org.sperle.keepass.crypto.bc;

import org.bouncycastle.util.encoders.Hex;
import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.crypto.KeePassCryptoException;

public class RC4CipherTest extends KeePassMobileIOTest {
    private static final String MASTER_PASSWORD = "SeCr_3t!";
    private static final String PLAIN_TEXT = "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern";
    private static final String CIPHER_TEXT = "eaa24dfa3b5bff157c841aeaaf32e3a323e3394e352a4cf348cd1b445397f5b91faf2c69d049e117f68e07bedb6f3feadc5d0a6f158da5a0f26690";
    
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
        rc4 = new RC4Cipher();
    }

    public void testRC4() throws KeePassCryptoException {
	byte[] cipherText = rc4.encrypt(Hex.decode(MASTER_PASSWORD.getBytes()), PLAIN_TEXT.getBytes());
	assertEquals(CIPHER_TEXT, new String(Hex.encode(cipherText)));
	assertEquals(PLAIN_TEXT, new String(rc4.decrypt(Hex.decode(MASTER_PASSWORD.getBytes()), cipherText)).trim());
    }
}
