package org.sperle.keepass.crypto;

import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.crypto.bc.AESCipher;
import org.sperle.keepass.crypto.bc.RC4Cipher;
import org.sperle.keepass.crypto.bc.SHA256Hash;
import org.sperle.keepass.rand.JdkRandom;
import org.sperle.keepass.util.ByteArrays;
import org.sperle.keepass.util.Passwords;

public class CryptoManagerTest extends KeePassMobileIOTest {
    
    private CryptoManager cm;
    
    public CryptoManagerTest() {
        super(3, "CryptoManagerTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testHashFunctions();break;
        case 1:testBlockCipher();break;
        case 2:testPasswordCipher();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
	cm = new CryptoManager(new JdkRandom());
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
    
    public void testPasswordCipher() {
        byte[] password = Passwords.fromString("test");
        assertNull(cm.getPasswordCipher(RC4Cipher.NAME));
        PasswordCipher passwordCipher = new RC4Cipher();
        cm.addPasswordCipher(passwordCipher);
        
        try {
            passwordCipher.encrypt(password);
            fail();
        } catch(IllegalStateException e) {
            // OK
        }
        
        passwordCipher = cm.getPasswordCipher(RC4Cipher.NAME);
        assertNotNull(passwordCipher);
        byte[] encryptedPassword = passwordCipher.encrypt(password);
        assertFalse(ByteArrays.equals(password, encryptedPassword));
    }
}
