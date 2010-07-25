/*
    Copyright (c) 2009-2010 Christoph Sperle <keepassmobile@gmail.com>
    
    This file is part of KeePassMobile.

    KeePassMobile is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    KeePassMobile is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KeePassMobile.  If not, see <http://www.gnu.org/licenses/>.

*/

package org.sperle.keepass.io.j2me;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.microedition.io.Connector;
import javax.microedition.io.file.FileConnection;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.sperle.keepass.io.IOManager;
import org.sperle.keepass.monitor.ProgressMonitor;
import org.sperle.keepass.util.ByteArrays;

// TODO test this class
public class J2meIOManager implements IOManager {

    public boolean exists(String filename) throws IOException {
        FileConnection conn = null;
        try {
            conn = (FileConnection) Connector.open(filename, Connector.READ);
            return conn.exists();
        } finally {
            try {if(conn != null) conn.close();} catch (IOException e) {}
        }
    }
    
    protected void rename(String path, String oldFilename, String newFilename) throws IOException {
        FileConnection conn = null;
        try {
            conn = (FileConnection) Connector.open(path+oldFilename, Connector.READ_WRITE);
            if(conn.exists()) conn.rename(newFilename);
        } finally {
            try {if(conn != null) conn.close();} catch (IOException e) {}
        }
    }
    
    public byte[] loadBinary(String filename, ProgressMonitor pm) throws IOException {
        FileConnection conn = null;
        InputStream is = null;
        byte[] file = new byte[0];
        try {
            conn = (FileConnection) Connector.open(filename, Connector.READ);
            if(pm != null) pm.nextStep(((int)(conn.fileSize() / 1024)) + 1, "pm_load");
            is = conn.openInputStream();
            byte[] buf = new byte[1024];
            int read = -1;
            while((read = is.read(buf)) > -1) {
                file = ByteArrays.append(file, buf, 0, read);
                if(pm != null) {
                    if(pm.isCanceled()) return null;
                    pm.tick();
                }
            }
        } finally {
            try {if(is != null) is.close();} catch (IOException e) {}
            try {if(conn != null) conn.close();} catch (IOException e) {}
        }
        
        return file;
    }
    
    public void saveBinary(String filename, byte[] binary, ProgressMonitor pm) throws IOException {
        if(!exists(filename)) {
            saveBinaryInternal(filename, binary, pm);
        } else {
            String tempFilename = getTempFilename(filename);
            saveBinaryInternal(tempFilename, binary, pm);
            delete(filename);
            rename(getPath(filename), getFilename(tempFilename), getFilename(filename));
        }
    }
    
    private String getFilename(String filename) {
        int lastFolderDelim = filename.lastIndexOf('/');
        return filename.substring(lastFolderDelim + 1, filename.length());
    }

    private String getPath(String filename) {
        int lastFolderDelim = filename.lastIndexOf('/');
        return filename.substring(0, lastFolderDelim + 1);
    }

    protected String getTempFilename(String filename) throws IOException {
        String tempBasename = filename;
        int fileTypeDelim = filename.lastIndexOf('.');
        int lastFolderDelim = filename.lastIndexOf('/');
        if(fileTypeDelim >= 0 && fileTypeDelim > lastFolderDelim) {
            tempBasename = tempBasename.substring(0, fileTypeDelim);
        }
        int i = 0;
        String tempFilename = null;
        do {
            tempFilename = tempBasename + "_"+ (i++) + ".tmp";
        } while(exists(tempFilename));
        return tempFilename;
    }
    
    private void saveBinaryInternal(String filename, byte[] binary, ProgressMonitor pm) throws IOException {
        FileConnection conn = null;
        try {
            conn = (FileConnection) Connector.open(filename, Connector.READ_WRITE);
            if(!conn.exists()) {
                conn.create();
            } else {
                conn.truncate(0);
            }
            saveBinaryInternal(conn, binary, pm);
        } finally {
            try {if(conn != null) conn.close();} catch (IOException e) {}
        }
    }
    
    private void saveBinaryInternal(FileConnection file, byte[] binary, ProgressMonitor pm) throws IOException {
        if(pm != null) pm.nextStep(1, "pm_save");
        OutputStream os = null;
        try {
            os = file.openOutputStream();
            os.write(binary);
            os.flush();
            if(pm != null) pm.tick();
        } finally {
            try {if(os != null) os.close();} catch (IOException e) {}
        }
    }
    
    public void delete(String filename) throws IOException {
        FileConnection conn = null;
        try {
            conn = (FileConnection) Connector.open(filename, Connector.READ_WRITE);
            if(conn.exists()) conn.delete();
        } finally {
            try {if(conn != null) conn.close();} catch (IOException e) {}
        }
    }
    
    public long getFileSize(String filename) throws IOException {
        long size = -1;
        FileConnection conn = null;
        try {
            conn = (FileConnection) Connector.open(filename, Connector.READ);
            size = conn.fileSize();
        } finally {
            try {if(conn != null) conn.close();} catch (IOException e) {}
        }
        
        return size;
    }
    
    public boolean equals(String filename1, String filename2) throws IOException {
        byte[] file1 = loadBinary(filename1, null);
        byte[] file2 = loadBinary(filename2, null);
        return ByteArrays.equals(file1, file2);
    }

    public byte[] generateHash(String filename, int packetSize) throws IOException {
        FileConnection conn = null;
        byte[] hash = null;
        try {
            conn = (FileConnection) Connector.open(filename, Connector.READ);
            InputStream is = conn.openInputStream();
            byte[] buf = new byte[packetSize];
            int read = -1;
            SHA256Digest md = new SHA256Digest();
            while((read = is.read(buf)) > -1) {
                md.update(buf, 0, read, null);
            }
            hash = new byte[md.getDigestSize()];
            md.doFinal(hash, 0);
        } finally {
            try {if(conn != null) conn.close();} catch (IOException e) {}
        }
        
        return hash;
    }
}
