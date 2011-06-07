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

import org.sperle.keepass.kdb.KdbChangeEvent;
import org.sperle.keepass.kdb.KdbChangeListener;
import org.sperle.keepass.kdb.KdbDate;
import org.sperle.keepass.kdb.KdbGroup;
import org.sperle.keepass.kdb.KeePassDatabase;
import org.sperle.keepass.util.BinaryData;
import org.sperle.keepass.util.ByteArrays;
import org.sperle.keepass.util.KeePassBinaryFields;

/**
 * A KeePass database group V1.
 */
public class KdbGroupV1 implements KdbGroup, org.sperle.keepass.util.Comparable {
    protected static final int FIELDTYPE_IGNORE = 0x0000;
    protected static final int FIELDTYPE_ID = 0x0001;
    protected static final int FIELDTYPE_NAME = 0x0002;
    protected static final int FIELDTYPE_CREATIONTIME = 0x0003;
    protected static final int FIELDTYPE_LASTMODIFICATIONTIME = 0x0004;
    protected static final int FIELDTYPE_LASTACCESSTIME = 0x0005;
    protected static final int FIELDTYPE_EXPIRATIONTIME = 0x0006;
    protected static final int FIELDTYPE_ICONID = 0x0007;
    protected static final int FIELDTYPE_TREELEVEL = 0x0008;
    protected static final int FIELDTYPE_INTERNALFLAGS = 0x0009;
    protected static final int FIELDTYPE_TERMINATOR = 0xFFFF;
    
    protected static final int FIELDTYPE_SIZE = 2;
    protected static final int FIELDSIZE_SIZE = 4;
    
    private int id = -1; // system
    private String name; // user
    private KdbDate creationTime;  // system
    private KdbDate lastModificationTime; // system
    private KdbDate lastAccessTime; // system
    private KdbDate expirationTime;  // user
    private int iconId = -1;  // user
    private int treeLevel = -1;  // system
    private int internalFlags = -1; // system
    
    private transient Vector changeListeners = new Vector();
    
    // for loading and testing
    protected KdbGroupV1() {
    }
    
    // for creating
    protected KdbGroupV1(int id, KdbGroup parent) {
        this.id = id;
        this.name = null;
        KdbDate now = KdbDate.now();
        this.creationTime = now;
        this.lastModificationTime = now;
        this.lastAccessTime = now;
        this.expirationTime = KdbDate.NEVER_EXPIRES;
        this.iconId = KeePassDatabase.DEFAULT_GROUP_ICON;
        this.treeLevel = (parent == null ? KeePassDatabase.ROOT_LEVEL : parent.getTreeLevel() + 1);
        this.internalFlags = 0;
    }
    
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
    
    private void extractField(byte[] fieldData, int offset) {
	int dataOffset = offset + FIELDTYPE_SIZE + FIELDSIZE_SIZE;
	switch (getFieldType(fieldData, offset)) {
	case FIELDTYPE_IGNORE:
	    break;
	case FIELDTYPE_ID:
	    this.id = BinaryData.toInt(fieldData, dataOffset);
	    break;
	case FIELDTYPE_NAME:
	    this.name = BinaryData.toString(fieldData, dataOffset);
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
	case FIELDTYPE_ICONID:
	    this.iconId = BinaryData.toInt(fieldData, dataOffset);
	    break;
	case FIELDTYPE_TREELEVEL:
	    this.treeLevel = BinaryData.toUnsignedShort(fieldData, dataOffset);
	    break;
	case FIELDTYPE_INTERNALFLAGS:
	    this.internalFlags = BinaryData.toInt(fieldData, dataOffset);
	    break;
	}
    }
    
    protected byte[] getPlainContentData(boolean forTest) {
        byte[] plainContentData = new byte[0];
        if(this.id == -1) {
            throw new IllegalStateException("group id not set");
        }
        plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromInt(FIELDTYPE_ID, this.id));
        if(this.name != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromString(FIELDTYPE_NAME, this.name));
        if(this.creationTime != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromDate(FIELDTYPE_CREATIONTIME, this.creationTime));
        if(!forTest && this.lastModificationTime != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromDate(FIELDTYPE_LASTMODIFICATIONTIME, this.lastModificationTime));
        if(!forTest && this.lastAccessTime != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromDate(FIELDTYPE_LASTACCESSTIME, this.lastAccessTime));
        if(this.expirationTime != null) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromDate(FIELDTYPE_EXPIRATIONTIME, this.expirationTime));
        if(this.iconId != -1) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromInt(FIELDTYPE_ICONID, this.iconId));
        if(this.treeLevel != -1) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromUnsignedShort(FIELDTYPE_TREELEVEL, this.treeLevel));
        if(this.internalFlags != -1) plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.fromInt(FIELDTYPE_INTERNALFLAGS, this.internalFlags));
        plainContentData = ByteArrays.append(plainContentData, KeePassBinaryFields.groupTerminator());
        
        return plainContentData;
    }
    
    public int hashCode() {
	final int prime = 31;
	int result = 1;
	result = prime * result + this.id;
	return result;
    }

    public boolean equals(Object obj) {
	if (this == obj) return true;
	if (obj == null) return false;
	if (getClass() != obj.getClass()) return false;
	KdbGroupV1 other = (KdbGroupV1) obj;
	if (this.id != other.id) return false;
	return true;
    }

    public String toString() {
	return getName();
    }

    // only used in tests!
    protected void setId(int id) {
	this.id = id;
    }

    public int getId() {
	return id;
    }

    public void setName(String name) {
        beforeChange();
	this.name = name;
	afterChange();
    }

    public String getName() {
	return name;
    }

    public KdbDate getCreationTime() {
	return creationTime;
    }

    public KdbDate getLastModificationTime() {
	return lastModificationTime;
    }

    public KdbDate getLastAccessTime() {
	return lastAccessTime;
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
	return expirationTime;
    }

    public void setIconId(int iconId) {
        beforeChange();
	this.iconId = iconId;
	afterChange();
    }

    public int getIconId() {
	return iconId;
    }

    public void setTreeLevel(int treeLevel) {
        beforeChange();
	this.treeLevel = treeLevel;
	afterChange();
    }

    public int getTreeLevel() {
	return treeLevel;
    }

    public void setInternalFlags(int internalFlags) {
        beforeChange();
	this.internalFlags = internalFlags;
	afterChange();
    }

    public int getInternalFlags() {
	return internalFlags;
    }
    
    private void beforeChange() {
        this.fireBeforeChange();
    }
    
    private void afterChange() {
        this.lastModificationTime = KdbDate.now();
        this.fireAfterChange();
    }
    
    public boolean expired() {
        return expirationTime != null && !expirationTime.equals(KdbDate.NEVER_EXPIRES) && expirationTime.before(KdbDate.now());
    }
    
    public boolean isRoot() {
        return treeLevel == 0;
    }
    
    public int compareTo(Object obj) {
        return (getName().compareTo(((KdbGroupV1)obj).getName()));
    }
    
    public void addChangeListener(KdbChangeListener kdbChangeListener) {
        this.changeListeners.addElement(kdbChangeListener);
    }

    public void close() {
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
}
