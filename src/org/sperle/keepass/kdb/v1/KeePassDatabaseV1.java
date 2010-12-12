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

import java.util.Vector;

import org.sperle.keepass.crypto.PasswordCipher;
import org.sperle.keepass.kdb.AbstractKeePassDatabase;
import org.sperle.keepass.kdb.KdbEntry;
import org.sperle.keepass.kdb.KdbGroup;
import org.sperle.keepass.kdb.KeePassDatabase;
import org.sperle.keepass.kdb.KeePassDatabaseException;
import org.sperle.keepass.kdb.PerformanceStatistics;
import org.sperle.keepass.monitor.ProgressMonitor;
import org.sperle.keepass.rand.Random;
import org.sperle.keepass.util.BinaryData;
import org.sperle.keepass.util.ByteArrays;

/**
 * A KeePass database V1.
 */
public final class KeePassDatabaseV1 extends AbstractKeePassDatabase {
    // KDB V1 header
    public static final int HEADER_LENGTH = 124;
    
    // KDB V1 signature
    public static final int SIGNATURE1 = 0x9AA2D903;
    public static final int SIGNATURE2 = 0xB54BFB65;
    
    // KDB V1 version
    public static final int VERSION = 0x00030002;
    
    // KDB V1 default number of KeyEncRounds
    public static final int DEFAULT_NUMKEYENCROUNDS = 300; // KeePass: 6000
    
    // header
    private int[] signature = new int[2]; // init: SIGNATURE; change: never
    private KdbAlgorithmV1 algorithm; // init: SHA-256/AES; change: never (user choice)
    private int version; // init: VERSION; change: never
    private byte[] masterSeed = new byte[16]; // init: none; change: random
    private byte[] encryptionIV = new byte[16]; // init: none; change: random
    private int numGroups; // init: 0; change: creation/deletion of group
    private int numEntries; // init: 0; change: creation/deletion of entry
    private byte[] contentHash = new byte[32]; // init: none; change: content change
    private byte[] masterSeed2 = new byte[32]; // init: none; change: random
    private int numKeyEncRounds; // init: DEFAULT_NUMKEYENCROUNDS; change: never (user choice)
    
    // master password & key file
    protected static final int PASSWORDKEY_LENGTH = 92;
    private transient byte[] masterPasswordEncrypted;
    private transient String masterPasswordPlain;
    private transient byte[] keyFileEncrypted;
    private transient byte[] keyFilePlain;
    private transient byte[] passwordKey; 
    
    // content
    private Vector groups = new Vector();
    private Vector entries = new Vector();
    
    // object graph
    private transient Random rand;
    private transient PasswordCipher cipher;
    private transient PerformanceStatistics performanceStatistics;
    
    // used for testing
    protected KeePassDatabaseV1(Random rand) {
        this(rand, null, null, null, null);
    }
    
    public KeePassDatabaseV1(Random rand, PasswordCipher cipher, String fileName, String masterPassword, byte[] keyFile) {
        super(fileName);
        this.rand = rand;
        this.cipher = cipher;
        this.passwordKey = (cipher != null && rand != null ? rand.nextBytes(PASSWORDKEY_LENGTH) : null);
        setMasterPassword(masterPassword);
        setKeyFile(keyFile);
        this.changed = false;
    }
    
    protected void init() {
        signature[0] = SIGNATURE1;
        signature[1] = SIGNATURE2;
        algorithm = new KdbAlgorithmV1();
        version = VERSION;
        // masterSeed = changes every time, the db is saved
        // encryptionIV = changes every time, the db is saved
        numGroups = 0;
        numEntries = 0;
        // contentHash = no need to init
        // masterSeed2 = changes every time, the db is saved
        numKeyEncRounds = DEFAULT_NUMKEYENCROUNDS;
    }
    
    protected void reinitBeforeSave() {
        masterSeed = rand.nextBytes(16);
        encryptionIV = rand.nextBytes(16);
        masterSeed2 = rand.nextBytes(32);
    }
    
    protected void extractHeader(byte[] data) throws KeePassDatabaseException {
	if(data.length < HEADER_LENGTH) {
	    throw new KeePassDatabaseException("kdb file invalid: too short");
	}
	
	signature[0] = BinaryData.toInt(data, 0);
	signature[1] = BinaryData.toInt(data, 4);
	algorithm = new KdbAlgorithmV1(BinaryData.toInt(data, 8));
	version = BinaryData.toInt(data, 12);
	ByteArrays.fillCompletelyFrom(data, 16, masterSeed);
	ByteArrays.fillCompletelyFrom(data, 32, encryptionIV);
	numGroups = BinaryData.toInt(data, 48);
	numEntries = BinaryData.toInt(data, 52);
	ByteArrays.fillCompletelyFrom(data, 56, contentHash);
	ByteArrays.fillCompletelyFrom(data, 88, masterSeed2);
	numKeyEncRounds = BinaryData.toInt(data, 120);
    }

    protected boolean verifyHeader() throws KeePassDatabaseException {
	if(!isSignatureCorrect()) {
	    throw new KeePassDatabaseException("kdb file invalid: wrong signature");
	}
	if(!isVersionCorrect()) {
	    throw new KeePassDatabaseException("kdb file invalid: wrong version");
	}
	return true;
    }
    
    protected boolean verifyContent(byte[] contentHash) throws KeePassDatabaseException {
        if(!ByteArrays.equals(this.contentHash, contentHash)) {
            throw new KeePassDatabaseException("kdb file invalid: content hash invalid");
        }
        return true;
    }
    
    protected byte[] getHeader() {
        byte[] header = new byte[HEADER_LENGTH];
        BinaryData.fromInt(signature[0], header, 0);
        BinaryData.fromInt(signature[1], header, 4);
        BinaryData.fromInt(algorithm.toInt(), header, 8);
        BinaryData.fromInt(version, header, 12);
        ByteArrays.copyCompletelyTo(masterSeed, header, 16);
        ByteArrays.copyCompletelyTo(encryptionIV, header, 32);
        BinaryData.fromInt(numGroups, header, 48);
        BinaryData.fromInt(numEntries, header, 52);
        ByteArrays.copyCompletelyTo(contentHash, header, 56);
        ByteArrays.copyCompletelyTo(masterSeed2, header, 88);
        BinaryData.fromInt(numKeyEncRounds, header, 120);
        return header;
    }
    
    public String getMasterPassword() {
        if(usePasswordEncryption()) {
            return this.masterPasswordEncrypted != null ? new String(cipher.decrypt(passwordKey, this.masterPasswordEncrypted)).trim() : null;
        } else {
            return this.masterPasswordPlain;
        }
    }

    public void setMasterPassword(String masterPassword) {
        if(usePasswordEncryption()) {
            this.masterPasswordEncrypted = (masterPassword != null ? cipher.encrypt(passwordKey, masterPassword.getBytes()) : null);
        } else {
            this.masterPasswordPlain = masterPassword;
        }
        this.changed = true;
    }
    
    // for tests only
    byte[] getMasterPasswordEncrypted() {
        return masterPasswordEncrypted;
    }

    // for tests only
    String getMasterPasswordPlain() {
        return masterPasswordPlain;
    }
    
    public byte[] getKeyFile() {
        if(usePasswordEncryption()) {
            return this.keyFileEncrypted != null ? cipher.decrypt(passwordKey, this.keyFileEncrypted) : null;
        } else {
            return this.keyFilePlain;
        }
    }

    public boolean hasKeyFile() {
        return this.keyFileEncrypted != null || this.keyFilePlain != null;
    }
    
    public void removeKeyFile() {
        this.keyFileEncrypted = null;
        this.keyFilePlain = null;
        this.changed = true;
    }
    
    public void setKeyFile(byte[] keyFile) {
        if(usePasswordEncryption()) {
            this.keyFileEncrypted = (keyFile != null ? cipher.encrypt(passwordKey, keyFile) : null);
        } else {
            this.keyFilePlain = keyFile;
        }
        this.changed = true;
    }
    
    // for tests only
    byte[] getKeyFileEncrypted() {
        return keyFileEncrypted;
    }
    
    // for tests only
    byte[] getKeyFilePlain() {
        return keyFilePlain;
    }
    
    private boolean usePasswordEncryption() {
        return cipher != null && passwordKey != null;
    }
    
    protected byte[] getEncryptedContent(byte[] data) {
	byte[] encryptedContentData = new byte[data.length - HEADER_LENGTH];
	ByteArrays.fillCompletelyFrom(data, HEADER_LENGTH, encryptedContentData);
	return encryptedContentData;
    }
    
    protected void extractContent(byte[] plainContentData, ProgressMonitor pm) {
        if(pm != null) pm.nextStep(numGroups+numEntries, "pm_extract");
        
	int offset = 0;
	for (int i = 0; i < numGroups; i++) {
	    KdbGroupV1 group = new KdbGroupV1();
	    offset = group.extract(plainContentData, offset);
	    groups.addElement(group);
	    if(pm != null) {
                if(pm.isCanceled()) return;
                pm.tick();
            }
	}
	for (int i = 0; i < numEntries; i++) {
	    KdbEntryV1 entry = new KdbEntryV1();
	    offset = entry.extract(plainContentData, offset);
	    entries.addElement(entry);
	    if(pm != null) {
                if(pm.isCanceled()) return;
                pm.tick();
            }
	}
    }
    
    // forTest: can not test time values that are automatically set (lastAccessTime)
    protected byte[] getPlainContentData(ProgressMonitor pm, boolean forTest) {
        byte[] plainContentData = new byte[0];
        if(pm != null) pm.nextStep(groups.size() + entries.size(), "pm_extract");
        for(int i = 0; i < groups.size(); i++) {
            plainContentData = ByteArrays.append(plainContentData, ((KdbGroupV1)groups.elementAt(i)).getPlainContentData(forTest));
            if(pm != null) {
                if(pm.isCanceled()) return null;
                pm.tick();
            }
        }
        for (int i = 0; i < entries.size(); i++) {
            plainContentData = ByteArrays.append(plainContentData, ((KdbEntryV1)entries.elementAt(i)).getPlainContentData(forTest));
            if(pm != null) {
                if(pm.isCanceled()) return null;
                pm.tick();
            }
        }
        return plainContentData;
    }
    
    protected boolean isSignatureCorrect() {
	return signature[0] == SIGNATURE1 && signature[1] == SIGNATURE2;
    }
    
    protected KdbAlgorithmV1 getAlgorithm() {
        return algorithm;
    }
    
    protected boolean isVersionCorrect() {
        return version == VERSION;
    }
    
    protected byte[] getMasterSeed() {
	return masterSeed;
    }
    
    protected byte[] getEncryptionIV() {
	return encryptionIV;
    }

    public int getNumGroups() {
	return numGroups;
    }

    // only used for tests!
    protected void setNumGroups(int numGroups) {
	this.numGroups = numGroups;
    }
    
    public int getNumEntries() {
	return numEntries;
    }

    // only used for tests!
    protected void setNumEntries(int numEntries) {
	this.numEntries = numEntries;
    }
    
    protected byte[] getContentHash() {
	return contentHash;
    }

    protected void setContentHash(byte[] contentHash) {
        this.contentHash = contentHash;
    }
    
    protected byte[] getMasterSeed2() {
	return masterSeed2;
    }

    public int getNumKeyEncRounds() {
	return numKeyEncRounds;
    }
    
    public void setNumKeyEncRounds(int numKeyEncRounds) {
        this.numKeyEncRounds = numKeyEncRounds;
        changed = true;
    }
    
    protected void setPerformanceStatistics(PerformanceStatistics performanceStatistics) {
        this.performanceStatistics = performanceStatistics;
    }
    
    public PerformanceStatistics getPerformanceStatistics() {
        return performanceStatistics;
    }
    
    public Vector getGroups() {
	return groups;
    }
    
    public KdbGroup createGroup(KdbGroup parent) {
        int id = rand.nextInt();
        while(existsGroupWithId(id)) id = rand.nextInt();
        KdbGroupV1 group = new KdbGroupV1(id, parent);
        addGroup(group, parent);
        return group;
    }
    
    protected void addGroup(KdbGroup group, KdbGroup parent) {
        if(existsGroupWithId(group.getId())) {
            throw new IllegalStateException("group already exists in db");
        }
        
        if(parent == null) {
            ((KdbGroupV1)group).setTreeLevel(KeePassDatabase.ROOT_LEVEL);
            groups.addElement(group);
        } else {
            ((KdbGroupV1)group).setTreeLevel(parent.getTreeLevel() + 1);
            
            int insertAtIndex = 0;
            Vector childGroups = getChildGroups(parent);
            if(childGroups.size() == 0) insertAtIndex = groups.indexOf(parent) + 1;
            else insertAtIndex = groups.indexOf(childGroups.lastElement()) + 1;
            groups.insertElementAt(group, insertAtIndex);
        }
        this.numGroups++;
        this.changed = true;
    }
    
    public void removeGroup(KdbGroup group) {
        if(!isEmpty(group)) {
            throw new IllegalStateException("can not delete group with subgroups/entries");
        }
        if(isBackupGroup(group)) {
            throw new IllegalStateException("can not delete backup group");
        }
        
        groups.removeElement(group);
        this.numGroups--;
        this.changed = true;
    }
    
    private boolean existsGroupWithId(int id) {
        for(int i = 0; i < groups.size(); i++) {
            if(id == ((KdbGroup)groups.elementAt(i)).getId()) {
                return true;
            }
        }
        return false;
    }
    
    public Vector getEntries() {
	return entries;
    }
    
    public KdbEntry createEntry(KdbGroup parent) {
        if(parent == null) {
            throw new IllegalArgumentException("parent group null");
        }
        
        byte[] id = rand.nextBytes(16);
        while(existsEntryWithId(id)) id = rand.nextBytes(16);
        KdbEntryV1 entry = new KdbEntryV1(rand, cipher, id, parent);
        addEntry(entry, parent);
        return entry;
    }
    
    protected void addEntry(KdbEntry entry, KdbGroup parent) {
        if(existsEntryWithId(entry.getId())) {
            throw new IllegalStateException("entry already exists in db");
        }
        
        ((KdbEntryV1)entry).setGroupId(parent.getId());
	entries.addElement(entry);
	numEntries++;
	changed = true;
    }
    
    private boolean existsEntryWithId(byte[] id) {
        for(int i = 0; i < entries.size(); i++) {
            if(ByteArrays.equals(id,((KdbEntry)entries.elementAt(i)).getId())) {
                return true;
            }
        }
        return false;
    }
    
    public void removeEntry(KdbEntry entry) {
        if(!isBackupEntry(entry)) backup(entry);
        entries.removeElement(entry);
        numEntries--;
        changed = true;
    }
    
    public void setBackupGroup(KdbGroup group) {
        if(hasNewBackupFlag) {
            throw new IllegalStateException("backup group already exists");
        }
        ((KdbGroupV1)group).setInternalFlags(((KdbGroupV1)group).getInternalFlags() | 4096);
        hasNewBackupFlag = true;
    }
    
    protected void backup(KdbEntry entry) {
        KdbGroup backupGroup = getBackupGroup();
        if(backupGroup == null) return;
        KdbEntryV1 backupEntry = (KdbEntryV1) createEntry(backupGroup);
        backupEntry.copyValuesFrom((KdbEntryV1) entry);
    }

    public void close() {
        super.close();        
        this.masterPasswordEncrypted = null;
        this.masterPasswordPlain = null;
        this.keyFileEncrypted = null;
        this.keyFilePlain = null;
    }
}
