package org.sperle.keepass.io.j2me;

import java.io.IOException;

import org.sperle.keepass.KeePassMobileIOTest;

public class J2meIOManagerTest extends KeePassMobileIOTest {
    private J2meIOManager io;
    
    public J2meIOManagerTest() {
        super(2, "J2meIOManagerTest");
    }

    public void test(int testNumber) throws Throwable {
        switch (testNumber) {
        case 0:testGetTempFilenameNew();break;
        case 1:testGetTempFilenameExists();break;
        default:break;
        }
    }
    
    public void setUp() throws Exception {
        io = new J2meIOManager();
    }

    public void testGetTempFilenameNew() throws IOException {
        io = new J2meIOManager() {
            public boolean exists(String filename) throws IOException {
                return false;
            }
        };
        assertEquals("test_0.tmp", io.getTempFilename("test.kdb"));
        assertEquals("test_0.tmp", io.getTempFilename("test"));
        assertEquals("file:///root/test_0.tmp", io.getTempFilename("file:///root/test.kdb"));
        assertEquals("file:///root.tmp/test_0.tmp", io.getTempFilename("file:///root.tmp/test.kdb"));
        assertEquals("file:///root.tmp/test_0.tmp", io.getTempFilename("file:///root.tmp/test"));
    }
    
    public void testGetTempFilenameExists() throws IOException {
        io = new J2meIOManager() {
            private int exists = 3;
            public boolean exists(String filename) throws IOException {
                return exists-- > 0 ? true : false;
            }
        };
        assertEquals("file:///root/test_3.tmp", io.getTempFilename("file:///root/test.kdb"));
    }
}
