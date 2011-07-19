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
import org.sperle.keepass.kdb.KdbChangeEvent;
import org.sperle.keepass.kdb.KdbChangeListener;
import org.sperle.keepass.kdb.KdbDate;
import org.sperle.keepass.kdb.KdbEntry;
import org.sperle.keepass.kdb.KdbGroup;
import org.sperle.keepass.kdb.KeePassDatabase;
import org.sperle.keepass.util.BinaryData;
import org.sperle.keepass.util.ByteArrays;
import org.sperle.keepass.util.KeePassBinaryFields;
import org.sperle.keepass.util.Passwords;

/**
 * A KeePass database entry V1.
 */
public class KdbEntryV1 implements KdbEntry, org.sperle.keepass.util.Comparable {
    protected static final int FIELDTYPE_IGNORE = 0x0000;
    protected static final int FIELDTYPE_ID = 0x0001;
    protected static final int FIELDTYPE_GROUPID = 0x0002;
    protected static final int FIELDTYPE_ICONID = 0x0003;
    protected static final int FIELDTYPE_TITLE = 0x0004;
    protected static final int FIELDTYPE_URL = 0x0005;
    protected static final int FIELDTYPE_USERNAME = 0x0006;
    protected static final int FIELDTYPE_PASSWORD = 0x0007;
    protected static final int FIELDTYPE_NOTES = 0x0008;
    protected static final int FIELDTYPE_CREATIONTIME = 0x0009;
    protected static final int FIELDTYPE_LASTMODIFICATIONTIME = 0x000A;
    protected static final int FIELDTYPE_LASTACCESSTIME = 0x000B;
    protected static final int FIELDTYPE_EXPIRATIONTIME = 0x000C;
    protected static final int FIELDTYPE_BINARYDESCRIPTION = 0x000D;
    protected static final int FIELDTYPE_BINARYDATA = 0x000E;
    protected static final int FIELDTYPE_TERMINATOR = 0xFFFF;
    
    protected static final int FIELDTYPE_SIZE = 2;
    protected static final int FIELDSIZE_SIZE = 4;
    
    private byte id[]; // system
    private int groupId = -1; // system
    private int iconId = -1; // user
    private String title; // user
    private String url; // user
    private String username; // user
    private byte[] passwordEncrypted; // user (used, if passwordCipher != null)
    private byte[] passwordPlain; // user (used, if passwordCipher == null)
    private String notes; // user
    private KdbDate creationTime; // system
    private KdbDate lastModificationTime; // system
    private KdbDate lastAccessTime; // system
    private KdbDate expirationTime; // user
    private String binaryDescription; // user
    private byte[] binaryData; // user
    
    private transient Vector changeListeners = new Vector();
    
    private transient PasswordCipher passwordCipher;
    
    protected KdbEntryV1(PasswordCipher passwordCipher) {
        this.passwordCipher = passwordCipher;
    }
    
    protected KdbEntryV1(PasswordCipher passwordCipher, byte[] id, KdbGroup parent) {
        this(passwordCipher);
        
        this.id = id;
        this.groupId = parent.getId();
        this.iconId = KeePassDatabase.DEFAULT_ENTRY_ICON;
        this.title = null;
        this.url = null;
        this.username = null;
        this.passwordEncrypted = null;
        this.passwordPlain = null;
        this.notes = null;
        KdbDate now = KdbDate.now();
        this.creationTime = now;
        this.lastModificationTime = now;
        this.lastAccessTime = now;
        this.expirationTime = KdbDate.NEVER_EXPIRES;
        this.binaryDescription = null;
        this.binaryData = null;
    }
    
    // load
    protected int extract(byte[] plainContentData, int plainContentOffset) {
	int offset = plainContentOffset;
	while(getFieldType(plainContentData, offset) != FIELDTYPE_TERMINATOR) {
	    extractField(plainContentData, offset);
	    offset += getFieldSize(plainContentData, offset) + FIELDTYPE_SIZE + FIELDSIZE_SIZE;
	}
	// add terminator field
	offset += FIELDTYPE_SIZE + FIELDSIZE_SIZE;
	return offset;
    }
    
    private int getFieldType(byte[] fieldData, int offset) {
	return BinaryData.toUnsignedShort(fieldData, offset);
    }

    private int getFieldSize(byte[] fieldData, int offset) {
	return BinaryData.toInt(fieldData, offset + FIELDTYPE_SIZE);
    }
    
    // load
    private void extractField(byte[] fieldData, int offset) {
	int dataOffset = offset + FIELDTYPE_SIZE + FIELDSIZE_SIZE;
	switch (getFieldType(fieldData, offset)) {
	case FIELDTYPE_IGNORE:
	    break;
	case FIELDTYPE_ID:
	    id = new byte[16];
	    ByteArrays.fillCompletelyFrom(fieldData, dataOffset, id);
	    break;
	case FIELDTYPE_GROUPID:
	    this.groupId = BinaryData.toInt(fieldData, dataOffset);
	    break;
	case FIELDTYPE_ICONID:
	    this.iconId = BinaryData.toInt(fieldData, dataOffset);
	    break;
	case FIELDTYPE_TITLE:
	    this.title = BinaryData.toString(fieldData, dataOffset);
	    break;
	case FIELDTYPE_URL:
	    this.url = BinaryData.toString(fieldData, dataOffset);
	    break;
	case FIELDTYPE_USERNAME:
	    this.username = BinaryData.toString(fieldData, dataOffset);
	    break;
	case FIELDTYPE_PASSWORD:
	    setPassword(BinaryData.toPassword(fieldData, dataOffset));
	    break;
	case FIELDTYPE_NOTES:
	    this.notes = BinaryData.toString(fieldData, dataOffset);
	    break;
	case FIELDTYPE_CREATIONTIME:
	    this.creationTime = KdbDate.fromBinaryData(fieldData, dataOffset);
	    break;
	case FIELDTYPE_LASTMODIFICATIONTIME:
	    this.lastModificationTime = KdbDate.fromBinaryData(fieldData, dataOffset);
	    break;
	case FIELDTYPE_LASTACCESSTIME:
	    this.lastAccessTime = KdbDate.fromBinaryData(fieldData, dataOffset);
	    break;
	case FIELDTYPE_EXPIRATIONTIME:
	    this.expirationTime = KdbDate.fromBinaryData(fieldData, dataOffset);
	    break;
	case FIELDTYPE_BINARYDESCRIPTION:
	    this.binaryDescription = BinaryData.toString(fieldData, dataOffset);
	    break;
	case FIELDTYPE_BINARYDATA:
	    this.binaryData = new byte[getFieldSize(fieldData, offset)];
	    ByteArrays.fillCompletelyFrom(fieldData, dataOffset, this.binaryData);
	    break;
	}
    }

    // save
    protected byte[] getPlainContentData(boolean forTest) {
        byte[] plainContentData = new byte[0];
        if(this.id == null) {
            throw new IllegalStateException("group id not set");
        }
        plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromByteArray(FIELDTYPE_ID, this.id));
        if(this.groupId != -1) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromInt(FIELDTYPE_GROUPID, this.groupId));
        if(this.iconId != -1) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromInt(FIELDTYPE_ICONID, this.iconId));
        if(this.title != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromString(FIELDTYPE_TITLE, this.title));
        if(this.url != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromString(FIELDTYPE_URL, this.url));
        if(this.username != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromString(FIELDTYPE_USERNAME, this.username));
        if(getPassword() != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromPassword(FIELDTYPE_PASSWORD, getPassword()));
        if(this.notes != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromString(FIELDTYPE_NOTES, this.notes));
        if(this.creationTime != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromDate(FIELDTYPE_CREATIONTIME, this.creationTime));
        if(!forTest && this.lastModificationTime != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromDate(FIELDTYPE_LASTMODIFICATIONTIME, this.lastModificationTime));
        if(!forTest && this.lastAccessTime != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromDate(FIELDTYPE_LASTACCESSTIME, this.lastAccessTime));
        if(this.expirationTime != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromDate(FIELDTYPE_EXPIRATIONTIME, this.expirationTime));
        if(this.binaryDescription != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromString(FIELDTYPE_BINARYDESCRIPTION, this.binaryDescription));
        if(this.binaryData != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromByteArray(FIELDTYPE_BINARYDATA, this.binaryData));
        plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.entryTerminator());
        
        return plainContentData;
    }
    
    public int hashCode() {
	final int prime = 31;
	int result = 1;
	result = prime * result + ByteArrays.hashCode(this.id);
	return result;
    }

    public boolean equals(Object obj) {
	if (this == obj) return true;
	if (obj == null) return false;
	if (getClass() != obj.getClass()) return false;
	KdbEntryV1 other = (KdbEntryV1) obj;
	if (!ByteArrays.equals(this.id, other.id)) return false;
	return true;
    }

    public String toString() {
	return getTitle();
    }

    // only used for tests!
    protected void setId(byte[] id) {
        this.id = id;
    }
    
    public byte[] getId() {
	return this.id;
    }

    public void setGroupId(int groupId) {
        beforeChange();
	this.groupId = groupId;
	afterChange();
    }

    public int getGroupId() {
	return this.groupId;
    }

    public void setIconId(int iconId) {
        beforeChange();
	this.iconId = iconId;
	afterChange();
    }

    public int getIconId() {
	return this.iconId;
    }

    public void setTitle(String title) {
        beforeChange();
	this.title = title;
	afterChange();
    }

    public String getTitle() {
	return this.title;
    }

    public void setUrl(String url) {
        beforeChange();
	this.url = url;
	afterChange();
    }

    public String getUrl() {
	return this.url;
    }

    public void setUsername(String username) {
        beforeChange();
	this.username = username;
	afterChange();
    }

    public String getUsername() {
	return this.username;
    }

    public void setPassword(byte[] password) {
        beforeChange();
        if(usePasswordEncryption() && !Passwords.isEmpty(password)) {
// TODO remove DEBUG message
System.out.println("ENcrypting password: " + Passwords.toString(password));
            this.passwordEncrypted = password != null ? passwordCipher.encrypt(password) : null;
        } else {
            this.passwordPlain = ByteArrays.returnCopy(password);
        }
	afterChange();
    }

    public byte[] getPassword() {
        if(usePasswordEncryption() && !Passwords.isEmpty(this.passwordPlain)) {
            byte[] decryptedPassword = this.passwordEncrypted != null ? passwordCipher.decrypt(this.passwordEncrypted) : null;
// TODO remove DEBUG message
System.out.println("DEcrypting password: " + Passwords.toString(decryptedPassword));
            return decryptedPassword;
        } else {
            return ByteArrays.returnCopy(this.passwordPlain);
        }
    }

    // for tests only
    byte[] getPasswordEncrypted() {
        return this.passwordEncrypted;
    }

    // for tests only
    byte[] getPasswordPlain() {
        return this.passwordPlain;
    }
    
    private boolean usePasswordEncryption() {
        return this.passwordCipher != null;
    }
    
    public void setNotes(String notes) {
        beforeChange();
	this.notes = notes;
	afterChange();
    }

    public String getNotes() {
	return this.notes;
    }

    public KdbDate getCreationTime() {
	return this.creationTime;
    }

    public KdbDate getLastModificationTime() {
	return this.lastModificationTime;
    }

    public KdbDate getLastAccessTime() {
	return this.lastAccessTime;
    }

    public void access() {
        this.lastAccessTime = KdbDate.now();
    }
    
    public void setExpirationTime(KdbDate expirationTime) {
        beforeChange();
	this.expirationTime = expirationTime;
	afterChange();
    }

    public KdbDate getExpirationTime() {
	return this.expirationTime;
    }
    
    public String getBinaryDescription() {
	return this.binaryDescription;
    }
    
    public byte[] getBinaryData() {
        return this.binaryData;
    }
    
    public void addAttachment(String binaryDescription, byte[] binaryData) {
        beforeChange();
        this.binaryDescription = binaryDescription;
        this.binaryData = binaryData;
        afterChange();
    }
    
    public boolean hasAttachment() {
        return this.binaryData != null && this.binaryData.length > 0;
    }
    
    public void removeAttachment() {
        beforeChange();
        this.binaryDescription = null;
        this.binaryData = null;
        afterChange();
    }
    
    public boolean expired() {
        return this.expirationTime != null && !this.expirationTime.equals(KdbDate.NEVER_EXPIRES) && this.expirationTime.before(KdbDate.now());
    }
    
    private void beforeChange() {
        this.fireBeforeChange();
    }
    
    private void afterChange() {
        this.lastModificationTime = KdbDate.now();
        this.fireAfterChange();
    }
    
    public int compareTo(Object obj) {
        return (getTitle().compareTo(((KdbEntryV1)obj).getTitle()));
    }

    public boolean isInternal() {
        return "Meta-Info".equals(this.title) && "SYSTEM".equals(this.username) && "$".equals(this.url) && Passwords.isEmpty(getPassword());
    }

    public void addChangeListener(KdbChangeListener kdbChangeListener) {
        this.changeListeners.addElement(kdbChangeListener);
    }

    private void fireBeforeChange() {
        for (int i = 0; i < changeListeners.size(); i++) {
            ((KdbChangeListener)changeListeners.elementAt(i)).beforeChange(new KdbChangeEvent(this));
        }
    }
    
    private void fireAfterChange() {
        for (int i = 0; i < changeListeners.size(); i++) {
            ((KdbChangeListener)changeListeners.elementAt(i)).afterChange(new KdbChangeEvent(this));
        }
    }
    
    public void removeChangeListener(KdbChangeListener kdbChangeListener) {
        this.changeListeners.removeElement(kdbChangeListener);
    }

    public void close() {
        ByteArrays.fillCompletelyWith(this.passwordPlain, (byte)0);
        ByteArrays.fillCompletelyWith(this.passwordEncrypted, (byte)0);
    }
    
    protected void copyValuesFrom(KdbEntryV1 entry) {
        this.iconId = entry.iconId;
        this.title = entry.title;
        this.url = entry.url;
        this.username = entry.username;
        if(entry.passwordEncrypted != null) {
            this.passwordEncrypted = new byte[entry.passwordEncrypted.length];
            ByteArrays.copyCompletelyTo(entry.passwordEncrypted, this.passwordEncrypted, 0);
        } else {
            this.passwordEncrypted = null;
        }
        if(entry.passwordPlain != null) {
            this.passwordPlain = new byte[entry.passwordPlain.length];
            ByteArrays.copyCompletelyTo(entry.passwordPlain, this.passwordPlain, 0);
        } else {
            this.passwordPlain = null;
        }
        this.notes = entry.notes;
        this.expirationTime = entry.expirationTime;
        this.binaryDescription = entry.binaryDescription;
        if(entry.binaryData != null) {
            this.binaryData = new byte[entry.binaryData.length];
            ByteArrays.copyCompletelyTo(entry.binaryData, this.binaryData, 0);
        } else {
            this.binaryData = null;
        }
    }
}
