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

import java.util.Vector;

import org.sperle.keepass.monitor.ProgressMonitor;

/**
 * The KeePass database object.
 */
public interface KeePassDatabase {
    public static final int ROOT_LEVEL = 0;
    public static final int DEFAULT_ENTRY_ICON = 0;
    public static final int DEFAULT_GROUP_ICON = 48;
    
    public static final int BACKUP_GROUP_FLAG = 4096;
    
    /**
     * Returns true, if database content has changed since creation (loading).
     */
    boolean hasChanged();
    
    /**
     * Returns the file name of this database. Returns null if database was newly created. 
     */
    String getFileName();
    
    /**
     * Returns the name of this database. Returns null if database was newly created. 
     */
    String getDatabaseName();
    
    /**
     * Sets new master password for this database.
     */
    void setMasterPassword(String masterPassword);
    
    /**
     * Returns true, if database uses a key file for encryption.
     */
    boolean hasKeyFile();
    
    /**
     * Removes the file that is used as part of the master key.
     */
    void removeKeyFile();
    
    /**
     * Returns the number of groups in this database.
     */
    int getNumGroups();
    
    /**
     * Returns the number of password entries in this database.
     */    
    int getNumEntries();
    
    /**
     * Returns the number of key encryption rounds of the database.
     */
    int getNumKeyEncRounds();
    
    /**
     * Sets the number of key encryption rounds.
     */
    void setNumKeyEncRounds(int numKeyEncRounds);
    
    /**
     * Returns the performance statistics information object.
     */
    PerformanceStatistics getPerformanceStatistics();
    
    /**
     * Returns the all groups of this database.
     */
    Vector getGroups();
    
    /**
     * Creates and adds new a group to the given parent group.
     * If parent == null, the new group is created as root group.
     */
    KdbGroup createGroup(KdbGroup parent);
    
// TODO implement to move group
//    /**
//     * Moves a group to the specified new parent group.
//     */
//    void moveGroup(KdbGroup group, KdbGroup newParent);
    
    /**
     * Returns true, if group is empty (has no entries or subgroups in it).
     */
    boolean isEmpty(KdbGroup group);
    
    /**
     * Removes the specified _empty_ group. This method can not handle groups
     * that have subgroups/entries! 
     */
    void removeGroup(KdbGroup group);
    
    /**
     * Returns all entries of this database.
     */
    Vector getEntries();
    
    /**
     * Creates and adds a new entry to the given group.
     */
    KdbEntry createEntry(KdbGroup parent);

    /**
     * Moves an entry to a new group.
     */
    void moveEntry(KdbEntry entry, KdbGroup newParent);
    
    /**
     * Removes the specified entry from this database.
     */
    void removeEntry(KdbEntry entry);
    
    /**
     * Closes this database.
     */
    void close();
    
    /**
     * Returns the root groups.
     */
    Vector getRootGroups();
    
    /**
     * Returns the root group of the given entry.
     */
    KdbGroup getRootGroup(KdbEntry entry);
    
    /**
     * Returns the root group of the given group (returns group itself, if it is a root group).
     */
    KdbGroup getRootGroup(KdbGroup group);
    
    /**
     * Returns the child groups of the given group.
     */
    Vector getChildGroups(KdbGroup parent);
    
    /**
     * Returns the parent group the given group.
     */
    KdbGroup getParentGroup(KdbGroup group);
    
    /**
     * Returns the parent groups of the given group.
     */
    Vector getParentGroups(KdbGroup child);

    /**
     * Returns all groups on the same level as the group the given entry belongs to.
     */
    Vector getParentGroups(KdbEntry entry);
    
    /**
     * Returns the group the given entry belongs to.
     */
    KdbGroup getParentGroup(KdbEntry entry);
    
    /**
     * Returns all groups with the same level and parent as the given group.
     */
    Vector getSiblingGroups(KdbGroup group);
    
    /**
     * Returns the entries of the given group.
     */
    Vector getEntries(KdbGroup group);
    
    /**
     * Returns the path to the specified group (e.g "/root/group/subgroup").
     */
    String getGroupPath(KdbGroup group);
    
    /**
     * Returns the entries, that match the search text for the given search options.
     */
    Vector search(String searchText, SearchOptions options, ProgressMonitor pm);
    
    /**
     * Returns true, if the given item is the backup group or an entry inside the backup group.
     */
    boolean isBackupItem(KdbItem item);
    
    /**
     * Returns true, if given group is the backup group of the database.
     */
    boolean isBackupGroup(KdbGroup group);
    
    /**
     * Returns true, if the given entry is inside the backup group.
     */
    boolean isBackupEntry(KdbEntry entry);
    
    /**
     * Marks the given group in the database as backup group.
     */
    void setBackupGroup(KdbGroup group);
}
