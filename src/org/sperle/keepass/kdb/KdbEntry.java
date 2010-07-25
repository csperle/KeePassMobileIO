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
 * A KeePass database entry.
 */
public interface KdbEntry extends KdbItem {

    /**
     * The entry id.
     */
    byte[] getId();

    /**
     * The id of the group, this entry belongs to.
     */
    int getGroupId();

    /**
     * The entry title.
     */
    String getTitle();

    /**
     * The entry URL.
     */
    String getUrl();

    /**
     * The username of the entry.
     */
    String getUsername();

    /**
     * The password of the entry.
     */
    String getPassword();

    /**
     * The notes that belongs to this entry.
     */
    String getNotes();

    /**
     * The creation time of the entry.
     */
    KdbDate getCreationTime();

    /**
     * The last modification time of the entry.
     */
    KdbDate getLastModificationTime();

    /**
     * The last access time of the entry.
     */
    KdbDate getLastAccessTime();
    
    /**
     * Sets the time of last access to now.
     */
    void access();
    
    /**
     * The expiration time of the entry.
     */
    KdbDate getExpirationTime();

    /**
     * The description of the binary data field.
     */
    String getBinaryDescription();

    /**
     * Some binary data stored inside the entry.
     */
    byte[] getBinaryData();

    /**
     * Sets a new title of this entry.
     */
    void setTitle(String title);

    /**
     * Sets the entry URL.
     */
    void setUrl(String url);

    /**
     * Sets a new user name for this entry.
     */
    void setUsername(String username);

    /**
     * Sets a new password for this entry.
     */
    void setPassword(String password);

    /**
     * Sets the entry notes.
     */
    void setNotes(String notes);

    /**
     * Sets the expiration time of this entry.
     */
    void setExpirationTime(KdbDate expirationTime);
    
    /**
     * Returns true, if this entry is for internal use only and should not be shown to the user.
     */
    boolean isInternal();
    
    /**
     * Returns true, if this entry has expired.
     */
    boolean expired();
    
    /**
     * Adds an attachment to this entry.
     */
    void addAttachment(String binaryDescription, byte[] binaryData);
    
    /**
     * Returns true, if this entry has an attachment.
     */
    boolean hasAttachment();
    
    /**
     * Removes the attachment from this entry
     */
    void removeAttachment();
    
    /**
     * Adds a change listener to this entry.
     */
    void addChangeListener(KdbChangeListener kdbChangeListener);
    
    /**
     * Removes a change listener from this entry.
     */
    void removeChangeListener(KdbChangeListener kdbChangeListener);
}
