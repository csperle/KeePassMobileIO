package org.sperle.keepass;

import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.sperle.keepass.io.IOManager;
import org.sperle.keepass.kdb.v1.KeePassDatabaseManagerV1Test;
import org.sperle.keepass.monitor.ProgressMonitor;
import org.sperle.keepass.util.ByteArrays;

import jmunit.framework.cldc11.TestCase;

public abstract class KeePassMobileIOTest extends TestCase {

    private Hashtable savedFiles = new Hashtable();
    
    public KeePassMobileIOTest(int num, String name) {
        super(num, name);
    }
    
    public class TestIOManager implements IOManager {

        public boolean exists(String name) throws IOException {
            throw new IllegalStateException("TestIOManager is only for loading kdb files");
        }

        public byte[] loadBinary(String filename, ProgressMonitor pm) throws IOException {
            if(savedFiles.containsKey(filename)) {
                return (byte[])savedFiles.get(filename);
            } else {
                InputStream is = null;
                byte buf[] = null;
                try {
                    is = KeePassDatabaseManagerV1Test.class.getResourceAsStream(filename);
                    buf = new byte[is.available()];
                    int read = is.read(buf);
                    if(read != buf.length) {
                        throw new IOException("Could not read whole file [" + filename + "]!");
                    }
                } finally {
                    try {if(is != null) is.close();} catch (IOException e) {}
                }
                return buf;
            }
        }
        
        public void saveBinary(String filename, byte[] binary, ProgressMonitor pm) throws IOException {
            savedFiles.put(filename, binary);
        }
        
        public void delete(String filename) throws IOException {
            savedFiles.remove(filename);
        }
        
        public boolean equals(String filename1, String filename2) throws IOException {
            return ByteArrays.equals(loadBinary(filename1, null), loadBinary(filename2, null));
        }

        public long getFileSize(String filename) throws IOException {
            long size = -1;
            InputStream is = null;
            try {
                is = KeePassDatabaseManagerV1Test.class.getResourceAsStream(filename);
                size = is.available();
            } finally {
                try {if(is != null) is.close();} catch (IOException e) {}
            }
            return size;
        }

        public byte[] generateHash(String filename, int packetSize) throws IOException {
            InputStream is = null;
            byte[] hash = null;
            try {
                is = KeePassDatabaseManagerV1Test.class.getResourceAsStream(filename);
                byte[] buf = new byte[packetSize];
                int read = -1;
                SHA256Digest md = new SHA256Digest();
                while((read = is.read(buf)) > -1) {
                    md.update(buf, 0, read, null);
                }
                hash = new byte[md.getDigestSize()];
                md.doFinal(hash, 0);
            } finally {
                try {if(is != null) is.close();} catch (IOException e) {}
            }
            return hash;
        }
    }
}
