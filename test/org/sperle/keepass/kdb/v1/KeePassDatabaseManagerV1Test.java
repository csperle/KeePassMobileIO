package org.sperle.keepass.kdb.v1;

import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.TestRandom;
import org.sperle.keepass.crypto.CryptoManager;
import org.sperle.keepass.crypto.bc.AESCipher;
import org.sperle.keepass.crypto.bc.RC4Cipher;
import org.sperle.keepass.crypto.bc.SHA256Hash;
import org.sperle.keepass.io.IOManager;
import org.sperle.keepass.kdb.AbstractKeePassDatabase;
import org.sperle.keepass.kdb.DoNothingOnCloseStrategy;
import org.sperle.keepass.kdb.KdbGroup;
import org.sperle.keepass.kdb.KeePassDatabase;
import org.sperle.keepass.rand.JdkRandom;
import org.sperle.keepass.util.ByteArrays;
import org.sperle.keepass.util.Passwords;


public class KeePassDatabaseManagerV1Test extends KeePassMobileIOTest {
    private static final String TEST1_DB = "testpass.kdb";
    private static final String TEST1_PASSWORD = "ÖÄÜöäüß_@!\"§$%&/()[]=*\\n";
    private static final String TEST1_SAVED = "testpass_saved.kdb";
    
    private static final String TEST2_DB = "testkey64.kdb";
    private static final String TEST2_KEYFILE = "pwsafe64.key";
    private static final String TEST2_SAVED = "testkey64_saved.kdb";
    
    private static final String TEST3_DB = "testkey32.kdb";
    private static final String TEST3_KEYFILE = "pwsafe32.key";
    private static final String TEST3_SAVED = "testkey32_saved.kdb";
    private static final byte[] TEST3_KEYFILE_CONTENT = new byte[] {(byte) 0xDF, 0x5E, 0x7A, 0x32, 0x20, 0x38, 0x40, 0x38, 0x2F, 0x35, (byte) 0xFC, 0x32, 0x5C, 0x70, 0x32, 0x5E, 0x2E, 0x35, (byte) 0xE9, 0x34, 0x7B, 0x33, 0x20, 0x2B, 0x66, 0x2A, 0x66, 0x36, 0x21, 0x36, 0x25, 0x3F};
    
    private static final String TEST4_DB = "testkeypng.kdb";
    private static final String TEST4_KEYFILE = "keepass.png";
    private static final String TEST4_SAVED = "testkeypng_saved.kdb";
    
    private static final String TEST5_DB = "testpasskeypng.kdb";
    private static final String TEST5_KEYFILE = "keepass.png";
    private static final String TEST5_PASSWORD = "123456";
    private static final String TEST5_SAVED = "testpasskeypng_saved.kdb";
    
    private IOManager fileManager;
    private TestRandom rand;
    private KeePassDatabaseManagerV1 dm;
    
    public KeePassDatabaseManagerV1Test() {
        super(10, "KeePassDatabaseManagerV1Test");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testLoadPassword();break;
        case 1:testLoadPasswordEncrypted();break;
        case 2:testSavePassword();break;
        case 3:testSavePasswordEncrypted();break;
        // TODO test save algorithm with key file:
        case 4:testLoadKeyFile64();break;
        case 5:testLoadKeyFile32();break;
        case 6:testLoadKeyFilePng();break;
        case 7:testLoadPassKeyFilePng();break;
        case 8:testChangeKeyEncRounds();break;
        //case 9:testChangePassword();break;
        case 9:testAddRemoveGroup();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
	CryptoManager cm = new CryptoManager(new JdkRandom());
	cm.addHash(new SHA256Hash());
	cm.addKdbCipher(new AESCipher());
	cm.addPasswordCipher(new RC4Cipher());
	fileManager = new TestIOManager();
	rand = new TestRandom();
	dm = new KeePassDatabaseManagerV1(fileManager, cm, new DoNothingOnCloseStrategy(), rand);
	dm.registerCryptoAlgorithm(new KeePassDatabaseAESCryptoAlgorithmV1(cm));
    }
    
    public void testLoadPassword() throws Exception {
	KeePassDatabaseV1 db = (KeePassDatabaseV1)dm.load(TEST1_DB, TEST1_PASSWORD, null, false, null);
	
	assertFalse(db.hasChanged());
	
	assertFalse(ByteArrays.equals(Passwords.getEncodedMasterPassword(TEST1_PASSWORD), db.getMasterPasswordEncrypted()));
        assertTrue(ByteArrays.equals(Passwords.getEncodedMasterPassword(TEST1_PASSWORD), db.getMasterPassword()));
        
	assertTrue(db.getAlgorithm().isSha2());
	assertTrue(db.getAlgorithm().isAes());
	assertFalse(db.getAlgorithm().isArc4());
	assertFalse(db.getAlgorithm().isTwofish());
	
	assertEquals(8, db.getNumGroups());
	assertEquals(5, db.getNumEntries());
	assertEquals(6000, db.getNumKeyEncRounds());
	
	assertEquals(8, db.getGroups().size());
	assertEquals(5, db.getEntries().size());
	
	assertEquals(2116301545, ((KdbGroupV1)db.getGroups().elementAt(0)).getId());
	assertEquals("General", ((KdbGroupV1)db.getGroups().elementAt(0)).getName());
	
	KdbEntryV1 entry = (KdbEntryV1)db.getEntries().elementAt(2);
        assertEquals("Test Umlaute", entry.getTitle());
	assertEquals("ÖÄÜöäüß", entry.getUsername());
	
	assertNull(entry.getPasswordEncrypted());
        assertTrue(ByteArrays.equals(Passwords.fromString("_@!\"§$%&/()[]=*\\n"), entry.getPasswordPlain()));
        assertEquals("_@!\"§$%&/()[]=*\\n", Passwords.toString(entry.getPassword()));
	
	assertEquals(2448, db.getPerformanceStatistics().getEncryptedContentDataLength());
	assertEquals(2434, db.getPerformanceStatistics().getPlainContentDataLength());
	//assertNotEquals(0, db.getPerformanceStatistics().getContentHashCalculationTime()); PC is too fast!
	//assertNotEquals(0, db.getPerformanceStatistics().getContentExtractionTime()); PC is too fast!
    }
    
    public void testLoadPasswordEncrypted() throws Exception {
        KeePassDatabaseV1 db = (KeePassDatabaseV1)dm.load(TEST1_DB, TEST1_PASSWORD, null, true, null);
        
        KdbEntryV1 entry = (KdbEntryV1)db.getEntries().elementAt(2);
        assertNull(entry.getPasswordPlain());
        assertFalse(ByteArrays.equals(Passwords.fromString("_@!\"§$%&/()[]=*\\n"),entry.getPasswordEncrypted()));
        assertEquals("_@!\"§$%&/()[]=*\\n", Passwords.toString(entry.getPassword()));
    }
    
    public void testLoadKeyFile64() throws Exception {
        KeePassDatabaseV1 db = (KeePassDatabaseV1)dm.load(TEST2_DB, null, TEST2_KEYFILE, false, null);
        
        assertEquals(8, db.getNumGroups());
        assertEquals(5, db.getNumEntries());
        assertEquals("General", ((KdbGroupV1)db.getGroups().elementAt(0)).getName());
        KdbEntryV1 entry = (KdbEntryV1)db.getEntries().elementAt(2);
        assertEquals("Test Umlaute", entry.getTitle());
        assertEquals("ÖÄÜöäüß", entry.getUsername());
        assertNull(entry.getPasswordEncrypted());
        assertEquals("_@!\"§$%&/()[]=*\\n", Passwords.toString(entry.getPasswordPlain()));
        assertEquals("_@!\"§$%&/()[]=*\\n", Passwords.toString(entry.getPassword()));
    }
    
    public void testLoadKeyFile32() throws Exception {
        KeePassDatabaseV1 db = (KeePassDatabaseV1)dm.load(TEST3_DB, null, TEST3_KEYFILE, false, null);
        
        assertNotNull(db.getKeyFileEncrypted());
        assertFalse(ByteArrays.equals(TEST3_KEYFILE_CONTENT, db.getKeyFileEncrypted()));
        assertTrue(ByteArrays.equals(TEST3_KEYFILE_CONTENT, db.getKeyFile()));
        
        assertEquals(8, db.getNumGroups());
        assertEquals(5, db.getNumEntries());
        assertEquals("General", ((KdbGroupV1)db.getGroups().elementAt(0)).getName());
        KdbEntryV1 entry = (KdbEntryV1)db.getEntries().elementAt(2);
        assertEquals("Test Umlaute", entry.getTitle());
        assertEquals("ÖÄÜöäüß", entry.getUsername());
        assertEquals("_@!\"§$%&/()[]=*\\n", Passwords.toString(entry.getPassword()));
    }
    
    public void testLoadKeyFilePng() throws Exception {
        KeePassDatabaseV1 db = (KeePassDatabaseV1)dm.load(TEST4_DB, null, TEST4_KEYFILE, false, null);
        
        assertEquals(8, db.getNumGroups());
        assertEquals(5, db.getNumEntries());
        assertEquals("General", ((KdbGroupV1)db.getGroups().elementAt(0)).getName());
        KdbEntryV1 entry = (KdbEntryV1)db.getEntries().elementAt(2);
        assertEquals("Test Umlaute", entry.getTitle());
        assertEquals("ÖÄÜöäüß", entry.getUsername());
        assertEquals("_@!\"§$%&/()[]=*\\n", Passwords.toString(entry.getPassword()));
    }
    
    public void testLoadPassKeyFilePng() throws Exception {
        KeePassDatabaseV1 db = (KeePassDatabaseV1)dm.load(TEST5_DB, TEST5_PASSWORD, TEST5_KEYFILE, false, null);
        
        assertEquals(8, db.getNumGroups());
        assertEquals(5, db.getNumEntries());
        assertEquals("General", ((KdbGroupV1)db.getGroups().elementAt(0)).getName());
        KdbEntryV1 entry = (KdbEntryV1)db.getEntries().elementAt(2);
        assertEquals("Test Umlaute", entry.getTitle());
        assertEquals("ÖÄÜöäüß", entry.getUsername());
        assertEquals("_@!\"§$%&/()[]=*\\n", Passwords.toString(entry.getPassword()));
    }
    
    public void testSavePassword() throws Exception {
        KeePassDatabase db = dm.load(TEST1_DB, TEST1_PASSWORD, null, false, null);
        dm.save(db, TEST1_SAVED, null, true);
        assertFalse(db.hasChanged());
        assertTrue(fileManager.equals(TEST1_DB, TEST1_SAVED));
    }
    
    public void testSavePasswordEncrypted() throws Exception {
        KeePassDatabaseV1 db = (KeePassDatabaseV1)dm.load(TEST1_DB, TEST1_PASSWORD, null, true, null);
        dm.save(db, TEST1_SAVED, null, true);
        assertFalse(db.hasChanged());
        assertTrue(fileManager.equals(TEST1_DB, TEST1_SAVED));
    }
    
    public void testChangeKeyEncRounds() throws Exception {
        KeePassDatabase db = dm.load(TEST1_DB, TEST1_PASSWORD, null, false, null);
        assertEquals(6000, db.getNumKeyEncRounds());
        db.setNumKeyEncRounds(50);
        assertTrue(db.hasChanged());
        dm.save(db, TEST1_SAVED, null, true);
        KeePassDatabase db2 = dm.load(TEST1_SAVED, TEST1_PASSWORD, null, false, null);
        assertEquals(50, db2.getNumKeyEncRounds());
    }
    
// TODO rewrite test: change password using the KeePassMobile facade
//    public void testChangePassword() throws Exception {
//        KeePassDatabase db = dm.load(TEST1_DB, TEST1_PASSWORD, null, false, null);
//        db.setMasterPassword(Passwords.getEncodedMasterPassword("@!\"§$%&/()[]=*\\n ÖÄÜöäüß"));
//        assertTrue(db.hasChanged());
//        dm.save(db, TEST1_SAVED, null, true);
//        assertFalse(fileManager.equals(TEST1_DB, TEST1_SAVED));
//        
//        try {
//            dm.load(TEST1_SAVED, TEST1_PASSWORD, null, false, null);
//            fail("Should not be loadable with old password");
//        } catch (Exception e) {
//            // OK
//        }
//        
//        KeePassDatabase db2 = dm.load(TEST1_SAVED, "@!\"§$%&/()[]=*\\n ÖÄÜöäüß", null, false, null);
//        assertEquals(2116301545, ((KdbGroupV1)db2.getGroups().elementAt(0)).getId());
//        assertEquals("General", ((KdbGroupV1)db2.getGroups().elementAt(0)).getName());
//    }
    
    public void testAddRemoveGroup() throws Exception {
        rand.setRandomInt(new int[]{1});
        
        KeePassDatabase db = dm.load(TEST1_DB, TEST1_PASSWORD, null, false, null);
        assertEquals(8, db.getNumGroups());
        
        KdbGroup g1 = db.createGroup(null);
        assertEquals(9, db.getNumGroups());
        
        dm.save(db, TEST1_SAVED, null, true);
        assertFalse(fileManager.equals(TEST1_DB, TEST1_SAVED));
        KeePassDatabase db2 = dm.load(TEST1_SAVED, TEST1_PASSWORD, null, false, null);
        assertEquals(9, db2.getNumGroups());
        
        db2.removeGroup(((AbstractKeePassDatabase)db2).getGroup(g1.getId()));
        assertEquals(8, db2.getNumGroups());
        
        dm.save(db2, TEST2_SAVED, null, true);
        assertTrue(fileManager.equals(TEST1_DB, TEST2_SAVED));
        
        KeePassDatabase db3 = dm.load(TEST2_SAVED, TEST1_PASSWORD, null, false, null);
        assertEquals(8, db3.getNumGroups());
    }
}
