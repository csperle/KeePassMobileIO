package org.sperle.keepass.kdb.v1;

import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.kdb.KdbChangeEvent;
import org.sperle.keepass.kdb.KdbChangeListener;
import org.sperle.keepass.kdb.KdbDate;
import org.sperle.keepass.util.BinaryData;
import org.sperle.keepass.util.ByteArrays;

public class KdbEntryV1Test extends KeePassMobileIOTest {
    private KdbEntryV1 entry;
    
    public KdbEntryV1Test() {
        super(18, "KdbEntryV1Test");
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
        case 16:testIsInternal();break;
        case 17:testEventSupport();break;
        default:break;
        }
    }

    public void setUp() throws Exception {
	entry = new KdbEntryV1();
    }

    public void testId() {
	byte[] entryData = new byte[24];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_ID, entryData, 0);
	BinaryData.fromInt(16, entryData, 2);
	ByteArrays.copyCompletelyTo(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}, entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 22);
	entry.extract(entryData, 0);
	assertTrue(ByteArrays.equals(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}, entry.getId()));
    }
    
    public void testGroupId() throws Exception {
	byte[] entryData = new byte[12];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_GROUPID, entryData, 0);
	BinaryData.fromInt(4, entryData, 2);
	BinaryData.fromInt(33, entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 10);
	entry.extract(entryData, 0);
	assertEquals(33, entry.getGroupId());
    }
    
    public void testIconId() throws Exception {
	byte[] entryData = new byte[12];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_ICONID, entryData, 0);
	BinaryData.fromInt(4, entryData, 2);
	BinaryData.fromInt(211, entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 10);
	entry.extract(entryData, 0);
	assertEquals(211, entry.getIconId());
    }
    
    public void testTitle() throws Exception {
	entry.extract(constructEntyDataFromString(KdbEntryV1.FIELDTYPE_TITLE, "Test Entry"), 0);
	assertEquals("Test Entry", entry.getTitle());
    }
    
    public void testUrl() throws Exception {
	entry.extract(constructEntyDataFromString(KdbEntryV1.FIELDTYPE_URL, "http://www.keepass.org/"), 0);
	assertEquals("http://www.keepass.org/", entry.getUrl());
    }
    
    public void testUsername() throws Exception {
	entry.extract(constructEntyDataFromString(KdbEntryV1.FIELDTYPE_USERNAME, "testuser"), 0);
	assertEquals("testuser", entry.getUsername());
    }
    
    public void testPassword() throws Exception {
	entry.extract(constructEntyDataFromString(KdbEntryV1.FIELDTYPE_PASSWORD, "geheim"), 0);
	assertEquals("geheim", entry.getPassword());
    }
    
    public void testNotes() throws Exception {
	entry.extract(constructEntyDataFromString(KdbEntryV1.FIELDTYPE_NOTES, "This is my little test note!"), 0);
	assertEquals("This is my little test note!", entry.getNotes());
    }
    
    public void testCreationTime() throws Exception {
        KdbDate creationDate = new KdbDate(2008, 12, 13, 12, 58, 55);
	byte[] groupData = new byte[13];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_CREATIONTIME, groupData, 0);
	BinaryData.fromInt(5, groupData, 2);
	creationDate.toBinaryData(groupData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, groupData, 11);
	entry.extract(groupData, 0);
	assertEquals(creationDate, entry.getCreationTime());
    }
    
    public void testLastModificationTime() throws Exception {
	KdbDate lastModificationTime = new KdbDate(2008, 12, 13, 12, 59, 1);
	byte[] groupData = new byte[13];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_LASTMODIFICATIONTIME, groupData, 0);
	BinaryData.fromInt(5, groupData, 2);
	lastModificationTime.toBinaryData(groupData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, groupData, 11);
	entry.extract(groupData, 0);
	assertEquals(lastModificationTime, entry.getLastModificationTime());
    }
    
    public void testLastAccessTime() throws Exception {
	KdbDate lastAccessTime = new KdbDate(2008, 12, 13, 13, 1, 31);
	byte[] groupData = new byte[13];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_LASTACCESSTIME, groupData, 0);
	BinaryData.fromInt(5, groupData, 2);
	lastAccessTime.toBinaryData(groupData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, groupData, 11);
	entry.extract(groupData, 0);
	assertEquals(lastAccessTime, entry.getLastAccessTime());
    }
    
    public void testExpirationTime() throws Exception {
	KdbDate expirationTime = new KdbDate(2008, 12, 13, 13, 7, 49);
	byte[] groupData = new byte[13];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_EXPIRATIONTIME, groupData, 0);
	BinaryData.fromInt(5, groupData, 2);
	expirationTime.toBinaryData(groupData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, groupData, 11);
	entry.extract(groupData, 0);
	assertEquals(expirationTime, entry.getExpirationTime());
    }
    
    public void testBinaryDescription() throws Exception {
	entry.extract(constructEntyDataFromString(KdbEntryV1.FIELDTYPE_BINARYDESCRIPTION, "This binäry is just for testing purpose!"), 0);
	assertEquals("This binäry is just for testing purpose!", entry.getBinaryDescription());
    }
    
    public void testBinaryData() {
	byte[] entryData = new byte[32];
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_BINARYDATA, entryData, 0);
	BinaryData.fromInt(24, entryData, 2);
	ByteArrays.copyCompletelyTo(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24}, entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 30);
	entry.extract(entryData, 0);
	assertTrue(ByteArrays.equals(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24}, entry.getBinaryData()));
    }
    
    public void testGetPlainContentData() throws Exception {
        KdbEntryV1 entry = new KdbEntryV1();
        entry.setId(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        assertTrue(ByteArrays.equals(new byte[]{1, 0, 16, 0, 0, 0, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, -1, -1, 0, 0, 0, 0}, entry.getPlainContentData(true)));
        entry.setTitle("a1");
        assertTrue(ByteArrays.equals(new byte[]{1, 0, 16, 0, 0, 0, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 4, 0, 3, 0, 0, 0, 97, 49, 0, -1, -1, 0, 0, 0, 0}, entry.getPlainContentData(true)));
    }
    
    private byte[] constructEntyDataFromString(int fieldtype, String s) {
	int len = BinaryData.getLength(s);
	byte[] entryData = new byte[8+len];
	BinaryData.fromUnsignedShort(fieldtype, entryData, 0);
	BinaryData.fromInt(len, entryData, 2);
	ByteArrays.copyCompletelyTo(BinaryData.fromString(s), entryData, 6);
	BinaryData.fromUnsignedShort(KdbEntryV1.FIELDTYPE_TERMINATOR, entryData, 6+len);
	return entryData;
    }
    
    public void testCreation() throws Exception {
        KdbGroupV1 group = new KdbGroupV1();
        group.setId(12);
        
        byte[] id = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        KdbEntryV1 entry = new KdbEntryV1(id, group);
        assertTrue(ByteArrays.equals(id, entry.getId()));
        assertEquals(12, entry.getGroupId());
    }
    
    public void testIsInternal() {
        assertFalse(entry.isInternal());
        entry.setTitle("Meta-Info");
        assertFalse(entry.isInternal());
        entry.setUsername("SYSTEM");
        assertFalse(entry.isInternal());
        entry.setPassword("");
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
