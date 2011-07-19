package org.sperle.keepass.kdb.v1;

import org.bouncycastle.util.encoders.Hex;
import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.TestRandom;
import org.sperle.keepass.crypto.bc.RC4Cipher;
import org.sperle.keepass.kdb.KdbChangeEvent;
import org.sperle.keepass.kdb.KdbChangeListener;
import org.sperle.keepass.kdb.KdbDate;
import org.sperle.keepass.util.BinaryData;
import org.sperle.keepass.util.ByteArrays;
import org.sperle.keepass.util.Passwords;

public class KdbEntryV1Test extends KeePassMobileIOTest {
    private static final byte[] TEST_PASSWORD = Passwords.fromString("Täßt $_% Pásswörd!");
    
    private KdbEntryV1 entry;
    
    public KdbEntryV1Test() {
        super(19, "KdbEntryV1Test");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testId();break;
        case 1:testGroupId();break;
        case 2:testIconId();break;
        case 3:testTitle();break;
        case 4:testUrl();break;
        case 5:testUsername();break;
        case 6:testPassword();break;
        case 7:testNotes();break;
        case 8:testCreationTime();break;
        case 9:testLastModificationTime();break;
        case 10:testLastAccessTime();break;
        case 11:testExpirationTime();break;
        case 12:testBinaryDescription();break;
        case 13:testBinaryData();break;
        case 14:testGetPlainContentData();break;
        case 15:testCreation();break;
        case 16:testCreationEncrypted();break;
        case 17:testIsInternal();break;
        case 18:testEventSupport();break;
        default:break;
        }
    }

    public void setUp() throws Exception {
	entry = new KdbEntryV1(null);
    }

    public void testId() {
	byte[] entryData = new byte[24];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_ID, entryData, 0);
	BinaryData.fromInt(16, entryData, 2);
	ByteArrays.copyCompletelyTo(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}, entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 22);
	entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertTrue(ByteArrays.equals(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}, entry.getId()));
    }
    
    public void testGroupId() throws Exception {
	byte[] entryData = new byte[12];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_GROUPID, entryData, 0);
	BinaryData.fromInt(4, entryData, 2);
	BinaryData.fromInt(33, entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 10);
	entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals(33, entry.getGroupId());
    }
    
    public void testIconId() throws Exception {
	byte[] entryData = new byte[12];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_ICONID, entryData, 0);
	BinaryData.fromInt(4, entryData, 2);
	BinaryData.fromInt(211, entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 10);
	entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals(211, entry.getIconId());
    }
    
    public void testTitle() throws Exception {
        byte[] entryData = constructEntyDataFromString(KdbEntryV1.FIELDTYPE_TITLE, "Test Entry");
	entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals("Test Entry", entry.getTitle());
    }
    
    public void testUrl() throws Exception {
	byte[] entryData = constructEntyDataFromString(KdbEntryV1.FIELDTYPE_URL, "http://www.keepass.org/");
        entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals("http://www.keepass.org/", entry.getUrl());
    }
    
    public void testUsername() throws Exception {
	byte[] entryData = constructEntyDataFromString(KdbEntryV1.FIELDTYPE_USERNAME, "testuser");
        entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals("testuser", entry.getUsername());
    }
    
    public void testPassword() throws Exception {
	byte[] entryData = constructEntyDataFromPassword(KdbEntryV1.FIELDTYPE_PASSWORD, Passwords.fromString("geheim"));
        entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals("geheim", Passwords.toString(entry.getPassword()));
    }
    
    public void testNotes() throws Exception {
	byte[] entryData = constructEntyDataFromString(KdbEntryV1.FIELDTYPE_NOTES, "This is my little test note!");
        entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals("This is my little test note!", entry.getNotes());
    }
    
    public void testCreationTime() throws Exception {
        KdbDate creationDate = new KdbDate(2008, 12, 13, 12, 58, 55);
	byte[] entryData = new byte[13];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_CREATIONTIME, entryData, 0);
	BinaryData.fromInt(5, entryData, 2);
	creationDate.toBinaryData(entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 11);
	entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals(creationDate, entry.getCreationTime());
    }
    
    public void testLastModificationTime() throws Exception {
	KdbDate lastModificationTime = new KdbDate(2008, 12, 13, 12, 59, 1);
	byte[] entryData = new byte[13];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_LASTMODIFICATIONTIME, entryData, 0);
	BinaryData.fromInt(5, entryData, 2);
	lastModificationTime.toBinaryData(entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 11);
	entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals(lastModificationTime, entry.getLastModificationTime());
    }
    
    public void testLastAccessTime() throws Exception {
	KdbDate lastAccessTime = new KdbDate(2008, 12, 13, 13, 1, 31);
	byte[] entryData = new byte[13];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_LASTACCESSTIME, entryData, 0);
	BinaryData.fromInt(5, entryData, 2);
	lastAccessTime.toBinaryData(entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 11);
	entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals(lastAccessTime, entry.getLastAccessTime());
    }
    
    public void testExpirationTime() throws Exception {
	KdbDate expirationTime = new KdbDate(2008, 12, 13, 13, 7, 49);
	byte[] entryData = new byte[13];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_EXPIRATIONTIME, entryData, 0);
	BinaryData.fromInt(5, entryData, 2);
	expirationTime.toBinaryData(entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 11);
	entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals(expirationTime, entry.getExpirationTime());
    }
    
    public void testBinaryDescription() throws Exception {
	byte[] entryData = constructEntyDataFromString(KdbEntryV1.FIELDTYPE_BINARYDESCRIPTION, "This binäry is just for testing purpose!");
        entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertEquals("This binäry is just for testing purpose!", entry.getBinaryDescription());
    }
    
    public void testBinaryData() {
	byte[] entryData = new byte[32];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_BINARYDATA, entryData, 0);
	BinaryData.fromInt(24, entryData, 2);
	ByteArrays.copyCompletelyTo(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24}, entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 30);
	entry.extract(entryData, 0);
	ByteArrays.fillCompletelyWith(entryData, (byte)0);
	assertTrue(ByteArrays.equals(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24}, entry.getBinaryData()));
    }
    
    public void testGetPlainContentData() throws Exception {
        KdbEntryV1 entry = new KdbEntryV1(null);
        entry.setId(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        assertTrue(ByteArrays.equals(new byte[]{1, 0, 16, 0, 0, 0, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, -1, -1, 0, 0, 0, 0}, entry.getPlainContentData(true)));
        entry.setTitle("a1");
        assertTrue(ByteArrays.equals(new byte[]{1, 0, 16, 0, 0, 0, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 4, 0, 3, 0, 0, 0, 97, 49, 0, -1, -1, 0, 0, 0, 0}, entry.getPlainContentData(true)));
    }
    
    private byte[] constructEntyDataFromString(int fieldtype, String s) {
        return constructEntyDataFromBinaryData(fieldtype, BinaryData.fromString(s));
    }
    
    private byte[] constructEntyDataFromPassword(int fieldtype, byte[] p) {
        return constructEntyDataFromBinaryData(fieldtype, BinaryData.fromPassword(p));
    }
    
    private byte[] constructEntyDataFromBinaryData(int fieldtype, byte[] data) {
        byte[] entryData = new byte[8+data.length];
        BinaryData.fromUnsignedShort(fieldtype, entryData, 0);
        BinaryData.fromInt(data.length, entryData, 2);
        ByteArrays.copyCompletelyTo(data, entryData, 6);
        BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 6+data.length);
        return entryData;
    }
    
    public void testCreation() throws Exception {
        KdbGroupV1 group = new KdbGroupV1();
        group.setId(12);
        
        byte[] id = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        KdbEntryV1 entry = new KdbEntryV1(null, id, group);
        assertTrue(ByteArrays.equals(id, entry.getId()));
        assertEquals(12, entry.getGroupId());
        
        entry.setPassword(TEST_PASSWORD);
        
        assertNull(entry.getPasswordEncrypted());
        assertTrue(ByteArrays.equals(TEST_PASSWORD, entry.getPasswordPlain()));
        assertTrue(ByteArrays.equals(TEST_PASSWORD, entry.getPassword()));
    }
    
    public void testCreationEncrypted() throws Exception {
        byte[] TEST_KEY = new byte[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39};
        
        KdbGroupV1 group = new KdbGroupV1();
        group.setId(12);
        
        byte[] id = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        KdbEntryV1 entry = new KdbEntryV1(new RC4Cipher(TEST_KEY), id, group);
        entry.setPassword(TEST_PASSWORD);
        
        assertNull(entry.getPasswordPlain());
        assertFalse(ByteArrays.equals(TEST_PASSWORD, entry.getPasswordEncrypted()));
        assertTrue(ByteArrays.equals(TEST_PASSWORD, entry.getPassword()));
    }
    
    public void testIsInternal() {
        assertFalse(entry.isInternal());
        entry.setTitle("Meta-Info");
        assertFalse(entry.isInternal());
        entry.setUsername("SYSTEM");
        assertFalse(entry.isInternal());
        entry.setPassword(Passwords.EMPTY_PASSWORD);
        assertFalse(entry.isInternal());
        entry.setUrl("$");
        assertTrue(entry.isInternal());
    }
    
    public void testEventSupport() {
        final boolean[] changeListenerworks = new boolean[] {false, false};
        entry.addChangeListener(new KdbChangeListener() {
            public void beforeChange(KdbChangeEvent e) {
                changeListenerworks[0] = true;
            }
            public void afterChange(KdbChangeEvent e) {
                changeListenerworks[1] = true;
            }
        });
        entry.setTitle("Test title");
        assertTrue(changeListenerworks[0]);
        assertTrue(changeListenerworks[1]);
    }
}
