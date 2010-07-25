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
 * A KeePass database group.
 */
public interface KdbGroup extends KdbItem {

    /**
     * The group id.
     */
    int getId();

    /**
     * The group name.
     */
    String getName();

    /**
     * The creation time of the group.
     */
    KdbDate getCreationTime();

    /**
     * The last modification time of the group.
     */
    KdbDate getLastModificationTime();

    /**
     * The last access time of the group.
     */
    KdbDate getLastAccessTime();
    
    /**
     * Sets the time of last access to now.
     */
    void access();
    
    /**
     * The expiration time of the group.
     */
    KdbDate getExpirationTime();

    /**
     * The level of the tree this group belongs to.
     */
    int getTreeLevel();

    /**
     * Some internal flags stored within the group.
     */
    int getInternalFlags();
    
    /**
     * Sets a new name for this group.
     */
    void setName(String name);

    /**
     * Sets the expiration time of this group.
     */
    void setExpirationTime(KdbDate expirationTime);

    /**
     * Returns true, if group is a root group.
     */
    boolean isRoot();
    
    /**
     * Returns true if password group has expired.
     */
    boolean expired();
    
    /**
     * Adds a change listener to this group.
     */
    void addChangeListener(KdbChangeListener kdbChangeListener);
    
    /**
     * Removes a change listener from this group.
     */
    void removeChangeListener(KdbChangeListener kdbChangeListener);
}
