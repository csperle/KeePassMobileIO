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

package org.sperle.keepass.kdb.v1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;

import org.sperle.keepass.crypto.CryptoManager;
import org.sperle.keepass.crypto.Hash;
import org.sperle.keepass.crypto.KeePassCryptoException;
import org.sperle.keepass.crypto.bc.RC4Cipher;
import org.sperle.keepass.io.IOManager;
import org.sperle.keepass.kdb.CloseStrategy;
import org.sperle.keepass.kdb.KdbEntry;
import org.sperle.keepass.kdb.KeePassDatabase;
import org.sperle.keepass.kdb.KeePassDatabaseCryptoAlgorithm;
import org.sperle.keepass.kdb.KeePassDatabaseException;
import org.sperle.keepass.kdb.KeePassDatabaseManager;
import org.sperle.keepass.kdb.PerformanceStatistics;
import org.sperle.keepass.monitor.ProgressMonitor;
import org.sperle.keepass.rand.Random;
import org.sperle.keepass.util.BinaryData;
import org.sperle.keepass.util.ByteArrays;
import org.sperle.keepass.util.Passwords;

/**
 * This KeePass database manager loads and saves V1 databases.
 */
public class KeePassDatabaseManagerV1 implements KeePassDatabaseManager {
    private final IOManager fileManager;
    private final CryptoManager cryptoManager;
    private final CloseStrategy closeStrategy;
    private final Random rand;
    
    private Hashtable cryptoAlgorithms = new Hashtable();
    
    public KeePassDatabaseManagerV1(IOManager fileManager, CryptoManager cryptoManager, CloseStrategy closeStrategy, Random rand) {
	this.fileManager = fileManager;
	this.cryptoManager = cryptoManager;
	this.closeStrategy = closeStrategy;
	this.rand = rand;
    }
    
    public KeePassDatabase create(String name, String masterPassword, String keyFileName, boolean usePasswordEncryption) throws IOException {
        byte[] keyFile = null;
        if(keyFileName != null) {
            keyFile = loadKeyFile(keyFileName);
        }
        
        try {
            KeePassDatabaseV1 kdb = new KeePassDatabaseV1(rand, cryptoManager.getPasswordCipher(RC4Cipher.NAME),
                usePasswordEncryption, name, Passwords.getEncodedMasterPassword(masterPassword), keyFile);
            kdb.init();
            
            return kdb;
        } finally { // delete all sensible data
            ByteArrays.fillCompletelyWith(keyFile, (byte)0);
        }        
    }
    
    public KeePassDatabase load(String fileName, String masterPassword, String keyFileName, boolean usePasswordEncryption, ProgressMonitor pm) throws IOException, KeePassCryptoException, KeePassDatabaseException {
        if(masterPassword == null && keyFileName == null) {
            throw new IllegalArgumentException("must provide master password or key file");
        }
        
        byte[] keyFile = null;
        byte[] data = null;
        byte[] encryptedContentData = null;
        byte[] plainContentData = null;
        try {
            if(keyFileName != null) {
                keyFile = loadKeyFile(keyFileName);
            }
            
            if(pm != null) pm.setSteps(5);
            PerformanceStatistics ps = new PerformanceStatistics();
            long start = System.currentTimeMillis();
            data = fileManager.loadBinary(fileName, pm);
    	    if(data == null) return null; // user canceled
    	    ps.setLoadTime(System.currentTimeMillis() - start);
    	
    	    KeePassDatabaseV1 kdb = new KeePassDatabaseV1(rand, cryptoManager.getPasswordCipher(RC4Cipher.NAME),
    	            usePasswordEncryption, fileName, Passwords.getEncodedMasterPassword(masterPassword), keyFile);
    	    kdb.extractHeader(data);
    	    kdb.verifyHeader();
    	    
    	    KeePassDatabaseCryptoAlgorithm cryptoAlgorithmToUse = getCryptoAlgorithmThatCanHandle(kdb);
    	    
    	    encryptedContentData = kdb.getEncryptedContent(data);
    	    ps.setEncryptedContentDataLength(encryptedContentData.length);
    	    
    	    plainContentData = cryptoAlgorithmToUse.decrypt(encryptedContentData, kdb.getMasterSeed(), 
    	            kdb.getMasterSeed2(), kdb.getNumKeyEncRounds(), kdb.getEncryptionIV(), Passwords.getEncodedMasterPassword(masterPassword), keyFile, ps, pm);
    	    if(plainContentData == null) return null; // user canceled
    	    ps.setPlainContentDataLength(plainContentData.length);
    	    
    	    start = System.currentTimeMillis();
    	    byte[] hash = calculateContentHash(plainContentData, cryptoManager.getHash("SHA256"), pm);
    	    if(hash == null) return null; // user canceled
    	    kdb.verifyContent(hash);
    	    ps.setContentHashCalculationTime(System.currentTimeMillis() - start);
    	    
    	    start = System.currentTimeMillis();
    	    kdb.extractContent(plainContentData, pm);
    	    if(pm != null && pm.isCanceled()) return null;
    	    ps.setContentExtractionTime(System.currentTimeMillis() - start);
    	    kdb.setPerformanceStatistics(ps);
    	    kdb.checkNewBackupFlag();
    	    kdb.initChangeEventSupport();
    	    return kdb;
        } finally { // delete all sensible data
            ByteArrays.fillCompletelyWith(keyFile, (byte)0);
            ByteArrays.fillCompletelyWith(data, (byte)0);
            ByteArrays.fillCompletelyWith(encryptedContentData, (byte)0);
            ByteArrays.fillCompletelyWith(plainContentData, (byte)0);
        }
    }
    
    public void registerCryptoAlgorithm(KeePassDatabaseCryptoAlgorithm cryptoAlgorithm) {
	cryptoAlgorithms.put(cryptoAlgorithm.getName(), cryptoAlgorithm);
    }
    
    public void saveAttachment(KdbEntry entry, String foldername) throws IOException {
        fileManager.saveBinary(foldername+(foldername.endsWith("/") ? "" : "/")+entry.getBinaryDescription(), entry.getBinaryData(), null);
    }
    
    public void addAttachment(KdbEntry entry, String filename) throws IOException {
        byte[] data = fileManager.loadBinary(filename, null);
        entry.addAttachment(filename.substring(filename.lastIndexOf('/') + 1, filename.length()), data);
    }
    
    public void setMasterPassword(KeePassDatabase kdb, byte[] masterPassword) throws KeePassDatabaseException {
        if(!(kdb instanceof KeePassDatabaseV1)) {
            throw new KeePassDatabaseException("KeePass database version not supported!");
        }
        KeePassDatabaseV1 kdbV1 = (KeePassDatabaseV1)kdb;
        kdbV1.setMasterPassword(masterPassword);
    }
    
    public void setKeyFile(KeePassDatabase kdb, String filename) throws IOException, KeePassDatabaseException {
        if(!(kdb instanceof KeePassDatabaseV1)) {
            throw new KeePassDatabaseException("KeePass database version not supported!");
        }
        KeePassDatabaseV1 kdbV1 = (KeePassDatabaseV1)kdb;
        
        byte[] keyFile = null;
        try {
            keyFile = loadKeyFile(filename);
            kdbV1.setKeyFile(keyFile);
        } finally { // delete all sensible data
            ByteArrays.fillCompletelyWith(keyFile, (byte)0);
        }
    }
    
    public void removeKeyFile(KeePassDatabase kdb) throws KeePassDatabaseException {
        if(!(kdb instanceof KeePassDatabaseV1)) {
            throw new KeePassDatabaseException("KeePass database version not supported!");
        }
        KeePassDatabaseV1 kdbV1 = (KeePassDatabaseV1)kdb;
        kdbV1.removeKeyFile();
    }
    
    public boolean save(KeePassDatabase kdb, String fileName, ProgressMonitor pm) throws IOException, KeePassDatabaseException, KeePassCryptoException {
        return save(kdb, fileName, pm, false);
    }
    
    public void close(KeePassDatabase kdb) {
        closeStrategy.close(kdb);
    }
    
    protected boolean save(KeePassDatabase kdb, String fileName, ProgressMonitor pm, boolean forTest) throws IOException, KeePassDatabaseException, KeePassCryptoException {
        if(!(kdb instanceof KeePassDatabaseV1)) {
            throw new KeePassDatabaseException("KeePass database version not supported!");
        }
        KeePassDatabaseV1 kdbV1 = (KeePassDatabaseV1)kdb;
        
        byte[] plainContentData = null;
        byte[] encryptedContentData = null;
        byte[] encryptedDB = null;
        try {
            KeePassDatabaseCryptoAlgorithm cryptoAlgorithmToUse = getCryptoAlgorithmThatCanHandle(kdbV1);
            
            if(pm != null) pm.setSteps(5);
            plainContentData = kdbV1.getPlainContentData(pm, false);
            if(plainContentData == null) return false; // user canceled
            
            if(!forTest) kdbV1.reinitBeforeSave();
            encryptedContentData = cryptoAlgorithmToUse.encrypt(plainContentData, kdbV1.getMasterSeed(), 
                    kdbV1.getMasterSeed2(), kdbV1.getNumKeyEncRounds(), kdbV1.getEncryptionIV(), kdbV1.getMasterPassword(), kdbV1.getKeyFile(), pm);
            if (encryptedContentData == null) return false; // user canceled
            byte[] hash = calculateContentHash(plainContentData, cryptoManager.getHash("SHA256"), pm);
            if(hash == null) return false; // user canceled
            kdbV1.setContentHash(hash);
            // TODO this statement uses too much memory! ->
            encryptedDB = ByteArrays.append(kdbV1.getHeader(), encryptedContentData);
            fileManager.saveBinary(fileName, encryptedDB, pm);
            kdbV1.setFileName(fileName);
            kdbV1.resetChanged();
            return true;
        } finally { // delete all sensible data
            ByteArrays.fillCompletelyWith(plainContentData, (byte)0);
            ByteArrays.fillCompletelyWith(encryptedContentData, (byte)0);
            ByteArrays.fillCompletelyWith(encryptedDB, (byte)0);
        }
    }
    
    private KeePassDatabaseCryptoAlgorithm getCryptoAlgorithmThatCanHandle(KeePassDatabaseV1 kdb) throws KeePassDatabaseException {
        Enumeration e = cryptoAlgorithms.elements();
        while (e.hasMoreElements()) {
                KeePassDatabaseCryptoAlgorithm cryptoAlgorithm = (KeePassDatabaseCryptoAlgorithm) e.nextElement();
            if(cryptoAlgorithm.canHandle(kdb)) {
                return cryptoAlgorithm;
            }
        }
        throw new KeePassDatabaseException("Encryption algorithm not supported!");
    }
    
    private byte[] calculateContentHash(byte[] plainContentData, Hash hash, ProgressMonitor pm) throws KeePassDatabaseException {
        return hash.getHash(new byte[][]{plainContentData}, pm);
    }
    
    private byte[] loadKeyFile(String keyFileName) throws IOException {
        long keyFileSize = fileManager.getFileSize(keyFileName);
        if(keyFileSize == 32) {
            return fileManager.loadBinary(keyFileName, null);
        } if(keyFileSize == 64) {
            return BinaryData.fromHexString(new String(fileManager.loadBinary(keyFileName, null)));
        } else {
            if(keyFileSize < 64) {
                throw new IllegalArgumentException("key file to short");
            }
            return fileManager.generateHash(keyFileName, 2048);
        }
    }
}
