package org.sperle.keepass.kdb.v1;

import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.TestRandom;
import org.sperle.keepass.crypto.CryptoManager;
import org.sperle.keepass.crypto.bc.AESCipher;
import org.sperle.keepass.crypto.bc.SHA256Hash;
import org.sperle.keepass.kdb.KeePassDatabaseException;
import org.sperle.keepass.kdb.PerformanceStatistics;
import org.sperle.keepass.util.BinaryData;
import org.sperle.keepass.util.ByteArrays;
import org.sperle.keepass.util.Passwords;

public class KeePassDatabaseAESCryptoAlgorithmV1Test extends KeePassMobileIOTest {
    private static final byte[] MASTER_PASSWORD = Passwords.getEncodedMasterPassword("TestMasterPassword");
    
    private KeePassDatabaseAESCryptoAlgorithmV1 aes;
    
    public KeePassDatabaseAESCryptoAlgorithmV1Test() {
        super(3, "KeePassDatabaseAESCryptoAlgorithmV1Test");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testMissingCipher();break;
        case 1:testWrongAlgorithm();break;
        case 2:testEncryptDecrypt();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
	CryptoManager cm = new CryptoManager(null);
	cm.addHash(new SHA256Hash());
	cm.addKdbCipher(new AESCipher());
	aes = new KeePassDatabaseAESCryptoAlgorithmV1(cm);
    }

    public void testMissingCipher() throws Exception {
        try {
            CryptoManager cm = new CryptoManager(null);
            cm.addHash(new SHA256Hash());
            new KeePassDatabaseAESCryptoAlgorithmV1(cm);
            fail("Should fail with IllegalArgumentException");
        } catch (IllegalStateException e) {}
    }
    
    public void testWrongAlgorithm() throws Exception {
	byte[] algorithm = new byte[4];
	BinaryData.fromInt(KdbAlgorithmV1.FLAG_ARCFOUR + KdbAlgorithmV1.FLAG_TWOFISH, algorithm, 0);
	KeePassDatabaseV1 kdb = getKdb(8, algorithm);
	assertFalse(aes.canHandle(kdb));
    }
    
    public void testEncryptDecrypt() throws Exception {
	KeePassDatabaseV1 kdb = getKdb(0, new byte[0]);
	assertTrue(aes.canHandle(kdb));
	
	byte[] masterSeed = new byte[]{32, -93, -19, 66, -56, 100, -89, -33, -91, 17, 12, -63, 88, -94, 88, -124};
	byte[] masterSeed2 = new byte[]{101, 61, -33, -22, 70, 48, 52, -32, -2, 89, 45, 74, 99, -128, -9, 49, 121, 102, 29, -21, -85, 99, -62, -82, 60, 60, -73, -64, 45, 89, 92, 59};
	int numKeyEncRounds = 6000;
	byte[] encryptionIV = new byte[]{-13, -81, -32, -37, 102, -68, 28, -74, 28, 98, 19, 64, 126, 123, -117, 104};
	byte[] keyFile = new byte[]{124, -22, 85, -99, -55, -81, 6, 6, -99, -128, -91, -49, 122, 112, -13, -64, 47, 99, 42, 51, -101, 60, -33, 22, 71, 48, 102, -32, -2, -1, 4, 74};
	
	KdbGroupV1 root = new KdbGroupV1();
	root.setId(1);
        kdb.addGroup(root, null);
	KdbEntryV1 entry = new KdbEntryV1(null);
	entry.setId(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
	kdb.addEntry(entry, root);
	
	byte[] plainContentData = kdb.getPlainContentData(null, true);
	byte[] encryptedContentData = aes.encrypt(plainContentData, masterSeed, masterSeed2, numKeyEncRounds, encryptionIV, MASTER_PASSWORD, keyFile, null);
	assertFalse(ByteArrays.equals(plainContentData, encryptedContentData));
	PerformanceStatistics ps = new PerformanceStatistics();
	byte[] decryptedContentData = aes.decrypt(encryptedContentData, masterSeed, masterSeed2, numKeyEncRounds, encryptionIV, MASTER_PASSWORD, keyFile, ps, null);
	assertTrue(ByteArrays.equals(plainContentData, decryptedContentData));
	assertNotEquals(0, ps.getMasterKeyEncryptionTime());
	//assertNotEquals(0, ps.getDecryptionTime()); PC is too fast!
    }
    
    private static KeePassDatabaseV1 getKdb(int offset, byte[] data) throws KeePassDatabaseException {
	KeePassDatabaseV1 kdb = new KeePassDatabaseV1(new TestRandom());
	byte[] header = new byte[KeePassDatabaseV1.HEADER_LENGTH];
	BinaryData.fromInt(KeePassDatabaseV1.SIGNATURE1, header, 0);
	BinaryData.fromInt(KeePassDatabaseV1.SIGNATURE2, header, 4);
	BinaryData.fromInt(KdbAlgorithmV1.FLAG_SHA2 + KdbAlgorithmV1.FLAG_AES, header, 8);
	BinaryData.fromInt(KeePassDatabaseV1.VERSION, header, 12);
	ByteArrays.copyCompletelyTo(data, header, offset);
	kdb.extractHeader(header);
	kdb.verifyHeader();
	return kdb;
    }
}
