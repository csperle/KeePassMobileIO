package org.sperle.keepass.kdb.v1;

import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.TestRandom;
import org.sperle.keepass.kdb.KdbEntry;
import org.sperle.keepass.kdb.KdbGroup;
import org.sperle.keepass.kdb.KeePassDatabaseException;
import org.sperle.keepass.util.BinaryData;
import org.sperle.keepass.util.ByteArrays;
import org.sperle.keepass.util.Passwords;

public class KeePassDatabaseV1Test extends KeePassMobileIOTest {
    private KeePassDatabaseV1 kdb;
    private TestRandom rand;
    
    public KeePassDatabaseV1Test() {
        super(24, "KeePassDatabaseV1Test");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testSignatureCorrect();break;
        case 1:testSignatureIncorrect();break;
        case 2:testAlgorithm();break;
        case 3:testVersion();break;
        case 4:testWrongVersion();break;
        case 5:testMasterSeed();break;
        case 6:testEncryptionIV();break;
        case 7:testNumGroups();break;
        case 8:testNumEntries();break;
        case 9:testContentHash();break;
        case 10:testMasterSeed2();break;
        case 11:testNumKeyEncRounds();break;
        case 12:testGroupsAndEntries();break;
        case 13:testCreateGroup();break;
        case 14:testAddGroup();break;
        case 15:testRemoveGroup();break;
        case 16:testCreateEntry();break;
        case 17:testAddEntry();break;
        case 18:testRemoveEntry();break;
        case 19:testGetPlainContentData();break;
        case 20:testCheckNewBackupFlag();break;
        case 21:testBackup();break;
        case 22:testMove();break;
        case 23:testExtractHeaderAndDeleteSensibleData();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
        rand = new TestRandom();
	kdb = new KeePassDatabaseV1(rand);
    }

    public void testSignatureCorrect() throws Exception {
	kdb.extractHeader(getValidKdbHeader());
	assertTrue(kdb.isSignatureCorrect());
	assertTrue(kdb.verifyHeader());
    }
    
    public void testSignatureIncorrect() throws Exception {
        try {
            byte[] signature1 = new byte[4];
            BinaryData.fromInt(KeePassDatabaseV1.SIGNATURE1 + 1, signature1, 0);
            kdb.extractHeader(getValidKdbHeader(0, signature1));
            assertFalse(kdb.isSignatureCorrect());
            assertTrue(kdb.verifyHeader());
            fail("Should fail with KeePassDatabaseException");
        } catch (KeePassDatabaseException e) {
        }
    }
    
    public void testAlgorithm() throws Exception {
	byte[] algorithm = new byte[4];
	BinaryData.fromInt(KdbAlgorithmV1.FLAG_ARCFOUR + KdbAlgorithmV1.FLAG_TWOFISH, algorithm, 0);
	kdb.extractHeader(getValidKdbHeader(8, algorithm));
	assertFalse(kdb.getAlgorithm().isSha2());
	assertFalse(kdb.getAlgorithm().isAes());
	assertTrue(kdb.getAlgorithm().isArc4());
	assertTrue(kdb.getAlgorithm().isTwofish());
	assertTrue(kdb.verifyHeader());
    }
    
    public void testVersion() throws Exception {
	kdb.extractHeader(getValidKdbHeader());
	assertTrue(kdb.isVersionCorrect());
	assertTrue(kdb.verifyHeader());
    }
    
    public void testWrongVersion() throws Exception {
        try {
            byte[] version = new byte[4];
            BinaryData.fromInt(KeePassDatabaseV1.VERSION + 1, version, 0);
            kdb.extractHeader(getValidKdbHeader(12, version));
            assertFalse(kdb.isVersionCorrect());
            assertTrue(kdb.verifyHeader());
            fail("Should fail with KeePassDatabaseException");
        } catch (KeePassDatabaseException e) {
        }
    }
    
    public void testMasterSeed() throws Exception {
	byte[] seed = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, -0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01};
	kdb.extractHeader(getValidKdbHeader(16, seed));
	assertTrue(ByteArrays.equals(seed, kdb.getMasterSeed()));
	assertTrue(kdb.verifyHeader());
    }
    
    public void testEncryptionIV() throws Exception {
	byte[] iv = new byte[] {-0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	kdb.extractHeader(getValidKdbHeader(32, iv));
	assertTrue(ByteArrays.equals(iv, kdb.getEncryptionIV()));
	assertTrue(kdb.verifyHeader());
    }
    
    public void testNumGroups() throws Exception {
	byte[] groups = new byte[4];
	BinaryData.fromInt(7, groups, 0);
	kdb.extractHeader(getValidKdbHeader(48, groups));
	assertEquals(7, kdb.getNumGroups());
	assertTrue(kdb.verifyHeader());
    }
    
    public void testNumEntries() throws Exception {
	byte[] entries = new byte[4];
	BinaryData.fromInt(23, entries, 0);
	kdb.extractHeader(getValidKdbHeader(52, entries));
	assertEquals(23, kdb.getNumEntries());
	assertTrue(kdb.verifyHeader());
    }
    
    public void testContentHash() throws Exception {
	byte[] hash = new byte[] {-0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		                  -0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	kdb.extractHeader(getValidKdbHeader(56, hash));
	assertTrue(ByteArrays.equals(hash, kdb.getContentHash()));
	assertTrue(kdb.verifyHeader());
    }
    
    public void testMasterSeed2() throws Exception {
	byte[] ms2 = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, -0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01,
		                  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, -0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01};
	kdb.extractHeader(getValidKdbHeader(88, ms2));
	assertTrue(ByteArrays.equals(ms2, kdb.getMasterSeed2()));
	assertTrue(kdb.verifyHeader());
    }
    
    public void testNumKeyEncRounds() throws Exception {
	byte[] rounds = new byte[4];
	BinaryData.fromInt(71, rounds, 0);
	kdb.extractHeader(getValidKdbHeader(120, rounds));
	assertEquals(71, kdb.getNumKeyEncRounds());
	assertTrue(kdb.verifyHeader());
    }
    
    public void testExtractHeaderAndDeleteSensibleData() throws Exception {
        byte[] header = getValidKdbHeader();
        byte[] seed = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, -0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01};
        ByteArrays.copyCompletelyTo(seed, header, 16);
        byte[] iv = new byte[] {-0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        ByteArrays.copyCompletelyTo(iv, header, 32);
        byte[] groups = new byte[4];
        BinaryData.fromInt(13, groups, 0);
        ByteArrays.copyCompletelyTo(groups, header, 48);
        byte[] entries = new byte[4];
        BinaryData.fromInt(17, entries, 0);
        ByteArrays.copyCompletelyTo(entries, header, 52);
        byte[] hash = new byte[] {-0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                -0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        ByteArrays.copyCompletelyTo(hash, header, 56);
        byte[] ms2 = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, -0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, -0x08, -0x07, -0x06, -0x05, -0x04, -0x03, -0x02, -0x01};
        ByteArrays.copyCompletelyTo(ms2, header, 88);
        byte[] rounds = new byte[4];
        BinaryData.fromInt(301, rounds, 0);
        ByteArrays.copyCompletelyTo(rounds, header, 120);
        kdb.extractHeader(header);
        
        // delete sensible data (like it is done in the KeePassDatabase Manager)!
        ByteArrays.fillCompletelyWith(header, (byte)0);
        
        assertTrue(ByteArrays.equals(seed, kdb.getMasterSeed()));
        assertTrue(ByteArrays.equals(iv, kdb.getEncryptionIV()));
        assertEquals(13, kdb.getNumGroups());
        assertEquals(17, kdb.getNumEntries());
        assertTrue(ByteArrays.equals(hash, kdb.getContentHash()));
        assertTrue(ByteArrays.equals(ms2, kdb.getMasterSeed2()));
        assertEquals(301, kdb.getNumKeyEncRounds());
        assertTrue(kdb.verifyHeader());
    }
    
    public void testGroupsAndEntries() throws Exception {
	kdb.setNumGroups(1);
	kdb.setNumEntries(1);
	
	// add group
	byte[] contentData = new byte[44];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_ID, contentData, 0);
	BinaryData.fromInt(4, contentData, 2);
	BinaryData.fromInt(31, contentData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, contentData, 10);
	BinaryData.fromInt(0, contentData, 12);
	
	// add entry
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_ID, contentData, 16);
	BinaryData.fromInt(16, contentData, 18);
	ByteArrays.copyCompletelyTo(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}, contentData, 22);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, contentData, 38);
	BinaryData.fromInt(0, contentData, 40);
	kdb.extractContent(contentData, null);
	
	// test group
	assertNotNull(kdb.getGroups());
	assertTrue(kdb.getGroups().size() == 1);
	KdbGroupV1 group = (KdbGroupV1)kdb.getGroups().elementAt(0);
	assertNotNull(group);
	assertEquals(31, group.getId());
	
	// test entry
	assertNotNull(kdb.getEntries());
	assertTrue(kdb.getEntries().size() == 1);
	KdbEntryV1 entry = (KdbEntryV1)kdb.getEntries().elementAt(0);
	assertNotNull(entry);
	assertTrue(ByteArrays.equals(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}, entry.getId()));
    }
    
    public void testCreateGroup() throws Exception {
        rand.setRandomInt(new int[]{1,1,1,1,1,1,3});
        
        assertEquals(0, kdb.getGroups().size());
        assertEquals(0, kdb.getNumGroups());
        assertFalse(kdb.hasChanged());
        
        KdbGroup group1 = kdb.createGroup(null);
        assertNotNull(group1);
        assertEquals(1, kdb.getGroups().size());
        assertEquals(group1, kdb.getGroups().elementAt(0));
        assertEquals(1, group1.getId());
        assertEquals(0, group1.getTreeLevel());
        assertEquals(1, kdb.getNumGroups());
        assertTrue(kdb.hasChanged());
        
        KdbGroup group2 = kdb.createGroup(group1);
        assertNotNull(group2);
        assertEquals(2, kdb.getGroups().size());
        assertEquals(group2, kdb.getGroups().elementAt(1));
        assertEquals(3, group2.getId());
        assertEquals(1, group2.getTreeLevel());
        assertEquals(2, kdb.getNumGroups());
    }
    
    public void testAddGroup() throws Exception {
        assertEquals(0, kdb.getGroups().size());
        assertEquals(0, kdb.getEntries().size());
        assertEquals(0, kdb.getNumGroups());
        assertEquals(0, kdb.getNumEntries());
        assertFalse(kdb.hasChanged());
        
        KdbGroupV1 group1 = new KdbGroupV1();
        group1.setId(1);
        kdb.addGroup(group1, null);
        
        assertEquals(1, kdb.getGroups().size());
        assertEquals(group1, kdb.getGroups().elementAt(0));
        assertEquals(0, group1.getTreeLevel());
        assertEquals(1, kdb.getNumGroups());
        assertTrue(kdb.hasChanged());
        
        try {
            kdb.addGroup(group1, null);
            fail("Should fail with IllegalStateException");
        } catch (IllegalStateException e) {
            // OK: can not add two groups with same id
        }
        assertEquals(1, kdb.getGroups().size());
        assertEquals(group1, kdb.getGroups().elementAt(0));
        assertEquals(1, kdb.getNumGroups());
        
        KdbGroupV1 group2 = new KdbGroupV1();
        group2.setId(2);
        kdb.addGroup(group2, null);
        
        assertEquals(2, kdb.getGroups().size());
        assertEquals(group1, kdb.getGroups().elementAt(0));
        assertEquals(group2, kdb.getGroups().elementAt(1));
        assertEquals(0, group2.getTreeLevel());
        assertEquals(2, kdb.getNumGroups());
        
        KdbGroupV1 group3 = new KdbGroupV1();
        group3.setId(3);
        kdb.addGroup(group3, group1);
        
        // assert:
        // +- group1
        // |    +- group3
        // +- group2
        assertEquals(3, kdb.getGroups().size());
        assertEquals(group1, kdb.getGroups().elementAt(0));
        assertEquals(group3, kdb.getGroups().elementAt(1));
        assertEquals(group2, kdb.getGroups().elementAt(2));
        assertEquals(1, group3.getTreeLevel());
        assertEquals(3, kdb.getNumGroups());
        
        KdbGroupV1 group4 = new KdbGroupV1();
        group4.setId(4);
        kdb.addGroup(group4, group1);
        
        // assert:
        // +- group1
        // |    +- group3
        // |    +- group4
        // +- group2
        assertEquals(4, kdb.getGroups().size());
        assertEquals(group1, kdb.getGroups().elementAt(0));
        assertEquals(group3, kdb.getGroups().elementAt(1));
        assertEquals(group4, kdb.getGroups().elementAt(2));
        assertEquals(group2, kdb.getGroups().elementAt(3));
        assertEquals(1, group4.getTreeLevel());
        assertEquals(4, kdb.getNumGroups());
    }
    
    public void testRemoveGroup() throws Exception {
        rand.setRandomInt(new int[]{1,2,3});
        
        KdbGroup root = kdb.createGroup(null);
        KdbGroup group = kdb.createGroup(root);
        KdbEntry entry = kdb.createEntry(group);
        
        assertEquals(2, kdb.getGroups().size());
        assertEquals(1, kdb.getEntries().size());
        assertEquals(2, kdb.getNumGroups());
        assertEquals(1, kdb.getNumEntries());
        
        try {
            kdb.removeGroup(group);
            fail("Should fail with IllegalStateException");
        } catch (IllegalStateException e) {
            // OK: can not remove group with entry
        }
        
        try {
            kdb.removeGroup(root);
            fail("Should fail with IllegalStateException");
        } catch (IllegalStateException e) {
            // OK: can not remove group with group
        }
        
        kdb.removeEntry(entry);
        kdb.removeGroup(group);
        kdb.removeGroup(root);
        
        assertEquals(0, kdb.getGroups().size());
        assertEquals(0, kdb.getEntries().size());
        assertEquals(0, kdb.getNumGroups());
        assertEquals(0, kdb.getNumEntries());
    }
    
    public void testCreateEntry() throws Exception {
        rand.setRandomInt(new int[]{2,2,2,2,2,4});
        
        assertEquals(0, kdb.getEntries().size());
        assertEquals(0, kdb.getNumEntries());
        assertFalse(kdb.hasChanged());
        
        try {
            kdb.createEntry(null);
            fail("Should fail with IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            // OK: can not add entry without group
        }
        
        KdbGroupV1 root = new KdbGroupV1();
        root.setId(14);
        kdb.addGroup(root, null);
        
        KdbEntry entry1 = kdb.createEntry(root);
        assertNotNull(entry1);
        assertEquals(1, kdb.getEntries().size());
        assertEquals(entry1, kdb.getEntries().elementAt(0));
        assertTrue(ByteArrays.equals(new byte[]{2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2}, entry1.getId()));
        assertEquals(14, entry1.getGroupId());
        assertEquals(1, kdb.getNumEntries());
        assertTrue(kdb.hasChanged());
        
        KdbEntry entry2 = kdb.createEntry(root);
        assertNotNull(entry2);
        assertEquals(2, kdb.getEntries().size());
        assertEquals(entry2, kdb.getEntries().elementAt(1));
        assertTrue(ByteArrays.equals(new byte[]{4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4}, entry2.getId()));
        assertEquals(14, entry2.getGroupId());
        assertEquals(2, kdb.getNumEntries());
    }
    
    public void testAddEntry() throws Exception {
        assertTrue(kdb.getEntries().size() == 0);
        assertFalse(kdb.hasChanged());
        
        KdbGroupV1 root = new KdbGroupV1();
        root.setId(9);
        kdb.addGroup(root, null);
        
        KdbEntryV1 entry = new KdbEntryV1(null);
        entry.setId(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        kdb.addEntry(entry, root);
        
        assertEquals(1, kdb.getEntries().size());
        assertEquals(entry, kdb.getEntries().elementAt(0));
        assertEquals(1, kdb.getNumEntries());
        assertEquals(9, entry.getGroupId());
        assertTrue(kdb.hasChanged());
        
        try {
            kdb.addEntry(entry, root);
            fail("Should fail with IllegalStateException");
        } catch (IllegalStateException e) {
            // OK: can not add two entries with same id
        }
        assertEquals(1, kdb.getEntries().size());
        assertEquals(entry, kdb.getEntries().elementAt(0));
        assertEquals(1, kdb.getNumEntries());
    }
    
    public void testRemoveEntry() throws Exception {
        rand.setRandomInt(new int[]{1,2});
        
        KdbGroup root = kdb.createGroup(null);
        KdbEntry entry = kdb.createEntry(root);
        
        assertEquals(1, kdb.getEntries().size());
        assertEquals(1, kdb.getNumEntries());
        
        kdb.removeEntry(entry);
        
        assertEquals(0, kdb.getEntries().size());
        assertEquals(0, kdb.getNumEntries());
    }
    
    public void testGetPlainContentData() throws Exception {
        KdbGroupV1 group = new KdbGroupV1();
        group.setId(15);
        kdb.addGroup(group, null);
        KdbEntryV1 entry = new KdbEntryV1(null);
        entry.setId(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        kdb.addEntry(entry, group);
        assertTrue(ByteArrays.equals(new byte[]{1, 0, 4, 0, 0, 0, 15, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0,
                0, 1, 0, 16, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 0, 0, 0, 15, 0, 0,
                0, -1, -1, 0, 0, 0, 0}, kdb.getPlainContentData(null, true)));
    }
    
    public void testCheckNewBackupFlag() throws Exception {
        assertFalse(kdb.hasNewBackupFlag());
        KdbGroupV1 group = new KdbGroupV1();
        group.setId(1);
        group.setInternalFlags(8192+2048+1024+512+256+128+64+32+16+8+4+2+1);
        kdb.addGroup(group, null);
        kdb.checkNewBackupFlag();
        assertFalse(kdb.hasNewBackupFlag());
        group.setInternalFlags(group.getInternalFlags() | 4096);
        kdb.checkNewBackupFlag();
        assertTrue(kdb.hasNewBackupFlag());
    }
    
    public void testBackup() {
        rand.setRandomInt(new int[]{15});
        
        KdbGroupV1 general = new KdbGroupV1();
        general.setId(1);
        general.setName("General");
        kdb.addGroup(general, null);
        KdbGroupV1 backup = new KdbGroupV1();
        backup.setId(2);
        backup.setName("Backup");
        kdb.addGroup(backup, null);
        KdbEntryV1 entry = new KdbEntryV1(null);
        entry.setId(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        entry.setTitle("Test Entry");
        entry.setUsername("Test User");
        entry.setPassword(Passwords.fromString("Test Passwd"));
        entry.setUrl("Test URL");
        entry.setNotes("Test Notes");
        kdb.addEntry(entry, general);
        kdb.initChangeEventSupport();
        
        // automatically backup through change
        entry.setTitle("Test Entry Changed");
        
        assertEquals(1, kdb.getEntries(backup).size());
        
        KdbEntryV1 backupEntry = (KdbEntryV1)kdb.getEntries(backup).elementAt(0);
        assertFalse(ByteArrays.equals(entry.getId(), backupEntry.getId()));
        assertEquals("Test Entry", backupEntry.getTitle());
        assertEquals("Test User", backupEntry.getUsername());
        assertEquals("Test Passwd", Passwords.toString(backupEntry.getPassword()));
        assertEquals("Test URL", backupEntry.getUrl());
        assertEquals("Test Notes", backupEntry.getNotes());
    }
    
    public void testMove() {
        KdbGroupV1 general = new KdbGroupV1();
        general.setId(1);
        general.setName("General");
        kdb.addGroup(general, null);
        KdbGroupV1 fromGroup = new KdbGroupV1();
        fromGroup.setId(2);
        fromGroup.setName("Backup");
        kdb.addGroup(fromGroup, general);
        KdbGroupV1 toGroup = new KdbGroupV1();
        toGroup.setId(3);
        toGroup.setName("General");
        kdb.addGroup(toGroup, null);
        
        KdbEntryV1 entry = new KdbEntryV1(null);
        entry.setId(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        kdb.addEntry(entry, fromGroup);
        
        assertEquals(1, kdb.getEntries(fromGroup).size());
        assertEquals(0, kdb.getEntries(toGroup).size());
        
        kdb.moveEntry(entry, toGroup);
        
        assertEquals(0, kdb.getEntries(fromGroup).size());
        assertEquals(1, kdb.getEntries(toGroup).size());
        assertEquals(entry,(KdbEntryV1)kdb.getEntries(toGroup).elementAt(0));;
    }
    
    private static byte[] getValidKdbHeader() {
        return getValidKdbHeader(0, null);
    }
    
    private static byte[] getValidKdbHeader(int offset, byte[] data) {
	byte[] header = new byte[KeePassDatabaseV1.HEADER_LENGTH];
	BinaryData.fromInt(KeePassDatabaseV1.SIGNATURE1, header, 0);
	BinaryData.fromInt(KeePassDatabaseV1.SIGNATURE2, header, 4);
	BinaryData.fromInt(KdbAlgorithmV1.FLAG_SHA2 + KdbAlgorithmV1.FLAG_AES, header, 8);
	BinaryData.fromInt(KeePassDatabaseV1.VERSION, header, 12);
	if(data != null) {
	    ByteArrays.copyCompletelyTo(data, header, offset);
	}
	return header;
    }
}
