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

package org.sperle.keepass.kdb;

/**
 * Saves the performance statistics for decrypting the database.
 */
public class PerformanceStatistics {
    private long loadTime;
    private long masterKeyEncryptionTime;
    private long decryptionTime;
    private long contentHashCalculationTime;
    private long contentExtractionTime;
    
    private int encryptedContentDataLength;
    private int plainContentDataLength;

    public void setLoadTime(long loadTime) {
        this.loadTime = loadTime;
    }
    public long getLoadTime() {
        return loadTime;
    }
    
    public long getMasterKeyEncryptionTime() {
        return masterKeyEncryptionTime;
    }
    public void setMasterKeyEncryptionTime(long masterKeyEncryptionTime) {
        this.masterKeyEncryptionTime = masterKeyEncryptionTime;
    }
    
    public long getDecryptionTime() {
        return decryptionTime;
    }
    public void setDecryptionTime(long decryptionTime) {
        this.decryptionTime = decryptionTime;
    }
    
    public long getContentHashCalculationTime() {
        return contentHashCalculationTime;
    }
    public void setContentHashCalculationTime(long contentHashCalculationTime) {
        this.contentHashCalculationTime = contentHashCalculationTime;
    }
    
    public long getContentExtractionTime() {
        return contentExtractionTime;
    }
    public void setContentExtractionTime(long contentExtractionTime) {
        this.contentExtractionTime = contentExtractionTime;
    }
    
    public int getEncryptedContentDataLength() {
        return encryptedContentDataLength;
    }
    public void setEncryptedContentDataLength(int encryptedContentDataLength) {
        this.encryptedContentDataLength = encryptedContentDataLength;
    }
    
    public int getPlainContentDataLength() {
        return plainContentDataLength;
    }
    public void setPlainContentDataLength(int plainContentDataLength) {
        this.plainContentDataLength = plainContentDataLength;
    }
}
