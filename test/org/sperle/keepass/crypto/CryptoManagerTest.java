package org.sperle.keepass.crypto;

import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.crypto.bc.AESCipher;
import org.sperle.keepass.crypto.bc.SHA256Hash;

public class CryptoManagerTest extends KeePassMobileIOTest {
    
    private CryptoManager cm;
    
    public CryptoManagerTest() {
        super(2, "CryptoManagerTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testHashFunctions();break;
        case 1:testBlockCipher();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
	cm = new CryptoManager();
    }
    
    public void testHashFunctions() {
	assertNull(cm.getHash(SHA256Hash.NAME));
	cm.addHash(new SHA256Hash());
	assertNotNull(cm.getHash(SHA256Hash.NAME));
    }
    
    public void testBlockCipher() {
	assertNull(cm.getKdbCipher(AESCipher.NAME));
	cm.addKdbCipher(new AESCipher());
	assertNotNull(cm.getKdbCipher(AESCipher.NAME));
    }
}
