package org.sperle.keepass.kdb.v1;

import org.sperle.keepass.KeePassMobileIOTest;
import org.sperle.keepass.kdb.KdbChangeEvent;
import org.sperle.keepass.kdb.KdbChangeListener;
import org.sperle.keepass.kdb.KdbDate;
import org.sperle.keepass.kdb.KeePassDatabase;
import org.sperle.keepass.util.BinaryData;
import org.sperle.keepass.util.ByteArrays;

public class KdbGroupV1Test extends KeePassMobileIOTest {
    private KdbGroupV1 group;
    
    public KdbGroupV1Test() {
        super(12, "KdbGroupV1Test");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testGroupId();break;
        case 1:testGroupName();break;
        case 2:testCreationTime();break;
        case 3:testLastModificationTime();break;
        case 4:testLastAccessTime();break;
        case 5:testExpirationTime();break;
        case 6:testImageId();break;
        case 7:testTreeLevel();break;
        case 8:testInternalFlags();break;
        case 9:testGetPlainContentData();break;
        case 10:testCreation();break;
        case 11:testEventSupport();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
	group = new KdbGroupV1();
    }

    public void testGroupId() throws Exception {
	byte[] groupData = new byte[12];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_ID, groupData, 0);
	BinaryData.fromInt(4, groupData, 2);
	BinaryData.fromInt(31, groupData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, groupData, 10);
	group.extract(groupData, 0);
	assertEquals(31, group.getId());
    }

    public void testGroupName() throws Exception {
	byte[] groupData = new byte[19];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_NAME, groupData, 0);
	BinaryData.fromInt(BinaryData.getLength("Test Group"), groupData, 2);
	ByteArrays.copyCompletelyTo(BinaryData.fromString("Test Group"), groupData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, groupData, 17);
	group.extract(groupData, 0);
	assertEquals("Test Group", group.getName());
    }
    
    public void testCreationTime() throws Exception {
	KdbDate creationDate = new KdbDate(2008, 12, 13, 12, 58, 55);
	byte[] groupData = new byte[13];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_CREATIONTIME, groupData, 0);
	BinaryData.fromInt(5, groupData, 2);
	creationDate.toBinaryData(groupData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, groupData, 11);
	group.extract(groupData, 0);
	assertEquals(creationDate, group.getCreationTime());
    }
    
    public void testLastModificationTime() throws Exception {
        KdbDate lastModificationTime = new KdbDate(2008, 12, 13, 12, 59, 1);
	byte[] groupData = new byte[13];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_LASTMODIFICATIONTIME, groupData, 0);
	BinaryData.fromInt(5, groupData, 2);
	lastModificationTime.toBinaryData(groupData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, groupData, 11);
	group.extract(groupData, 0);
	assertEquals(lastModificationTime, group.getLastModificationTime());
    }
    
    public void testLastAccessTime() throws Exception {
        KdbDate lastAccessTime = new KdbDate(2008, 12, 13, 13, 1, 31);
	byte[] groupData = new byte[13];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_LASTACCESSTIME, groupData, 0);
	BinaryData.fromInt(5, groupData, 2);
	lastAccessTime.toBinaryData(groupData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, groupData, 11);
	group.extract(groupData, 0);
	assertEquals(lastAccessTime, group.getLastAccessTime());
    }
    
    public void testExpirationTime() throws Exception {
        KdbDate expirationTime = new KdbDate(2008, 12, 13, 13, 7, 49);
	byte[] groupData = new byte[13];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_EXPIRATIONTIME, groupData, 0);
	BinaryData.fromInt(5, groupData, 2);
	expirationTime.toBinaryData(groupData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, groupData, 11);
	group.extract(groupData, 0);
	assertEquals(expirationTime, group.getExpirationTime());
    }
    
    public void testImageId() throws Exception {
	byte[] groupData = new byte[12];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_ICONID, groupData, 0);
	BinaryData.fromInt(4, groupData, 2);
	BinaryData.fromInt(99, groupData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, groupData, 10);
	group.extract(groupData, 0);
	assertEquals(99, group.getIconId());
    }
    
    public void testTreeLevel() throws Exception {
	byte[] groupData = new byte[10];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TREELEVEL, groupData, 0);
	BinaryData.fromInt(2, groupData, 2);
	BinaryData.fromUnsignedShort(99, groupData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, groupData, 8);
	group.extract(groupData, 0);
	assertEquals(99, group.getTreeLevel());
    }
    
    public void testInternalFlags() throws Exception {
	byte[] groupData = new byte[12];
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_INTERNALFLAGS, groupData, 0);
	BinaryData.fromInt(4, groupData, 2);
	BinaryData.fromInt(11111, groupData, 6);
	BinaryData.fromUnsignedShort(KdbGroupV1.FIELDTYPE_TERMINATOR, groupData, 10);
	group.extract(groupData, 0);
	assertEquals(11111, group.getInternalFlags());
    }
    
    public void testGetPlainContentData() throws Exception {
        KdbGroupV1 group = new KdbGroupV1();
        group.setId(15);
        assertTrue(ByteArrays.equals(new byte[]{1, 0, 4, 0, 0, 0, 15, 0, 0, 0, -1, -1, 0, 0, 0, 0}, group.getPlainContentData(true)));
        group.setName("a1");
        assertTrue(ByteArrays.equals(new byte[]{1, 0, 4, 0, 0, 0, 15, 0, 0, 0, 2, 0, 3, 0, 0, 0, 97, 49, 0, -1, -1, 0, 0, 0, 0}, group.getPlainContentData(true)));
    }
    
    public void testCreation() throws Exception {
        KdbGroupV1 root = new KdbGroupV1(15, null);
        assertEquals(15, root.getId());
        assertEquals(KeePassDatabase.ROOT_LEVEL, root.getTreeLevel());
    }
    
    public void testEventSupport() {
        final boolean[] changeListenerworks = new boolean[] {false, false};
        group.addChangeListener(new KdbChangeListener() {
            public void beforeChange(KdbChangeEvent e) {
                changeListenerworks[0] = true;
            }
            public void afterChange(KdbChangeEvent e) {
                changeListenerworks[1] = true;
            }
        });
        group.setName("Test name");
        assertTrue(changeListenerworks[0]);
        assertTrue(changeListenerworks[1]);
    }
}
