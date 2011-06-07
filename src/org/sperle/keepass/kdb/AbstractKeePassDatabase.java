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

import org.sperle.keepass.kdb.v1.KdbEntryV1;
import org.sperle.keepass.monitor.ProgressMonitor;
import org.sperle.keepass.util.ByteArrays;

/**
 * Implements the logical access layer to the database. This algorithms have to be implementation independent.
 * TODO test this class
 */
public abstract class AbstractKeePassDatabase implements KeePassDatabase, KdbChangeListener {
    protected String fileName;
    
    protected boolean changed = false;
    protected boolean hasNewBackupFlag = false;
    
    public AbstractKeePassDatabase(String fileName) {
        this.fileName = fileName;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
    
    public String getDatabaseName() {
        if(fileName.indexOf('/') < 0) return fileName;
        else return fileName.substring(fileName.lastIndexOf('/') + 1);
    }
    
    /**
     * Activates automatic backup functionality of changed items.
     */
    public void initChangeEventSupport() {
        for (int i = 0; i < getGroups().size(); i++) {
            KdbGroup group = (KdbGroup) getGroups().elementAt(i);
            if(!isBackupGroup(group)) group.addChangeListener(this);
        }
        for (int i = 0; i < getEntries().size(); i++) {
            KdbEntry entry = (KdbEntry) getEntries().elementAt(i);
            if(!isBackupEntry(entry)) entry.addChangeListener(this);
        }
    }
    
    public void beforeChange(KdbChangeEvent e) {
        if(e.getSource() instanceof KdbEntry) {
            backup((KdbEntry)e.getSource());
        }
    }
    
    public void afterChange(KdbChangeEvent e) {
        changed = true;
    }
    
    public boolean hasChanged() {
        return changed;
    }
    
    public void resetChanged() {
        this.changed = false;
    }
    
    public boolean hasNewBackupFlag() {
        return hasNewBackupFlag;
    }
    
    public void close() {
        for(int i = 0; i < getEntries().size(); i++) {
            KdbEntry entry = (KdbEntry) getEntries().elementAt(i);
            entry.close();
        }
        getEntries().removeAllElements();
        for(int i = 0; i < getGroups().size(); i++) {
            KdbGroup group = (KdbGroup) getGroups().elementAt(i);
            group.close();
        }
        getGroups().removeAllElements();
    }
    
    public Vector getRootGroups() {
        Vector roots = new Vector();
        for(int i = 0; i < getGroups().size(); i++) {
            KdbGroup group = (KdbGroup) getGroups().elementAt(i);
            if (group.isRoot()) roots.addElement(group);
        }
        return roots;
    }
    
    public KdbGroup getRootGroup(KdbEntry entry) {
        KdbGroup parentGroup = getParentGroup(entry);
        if(parentGroup.isRoot()) return parentGroup;
        else return getRootGroup(parentGroup);
    }
    
    public KdbGroup getRootGroup(KdbGroup group) {
        if(group.isRoot()) return group;
        KdbGroup parentGroup = getParentGroup(group);
        if(parentGroup.isRoot()) return parentGroup;
        else return getRootGroup(parentGroup);
    }
    
    public Vector getChildGroups(KdbGroup parent) {
        int startIndex = getGroups().indexOf(parent);
        int childLevel = parent.getTreeLevel() + 1;
        
        Vector childs = new Vector();
        for(int i = startIndex + 1; i < getGroups().size(); i++) {
            KdbGroup child = (KdbGroup) getGroups().elementAt(i);
            if (child.getTreeLevel() == childLevel) childs.addElement(child);
            else if (child.getTreeLevel() < childLevel) break;
        }
        return childs;
    }
    
    public KdbGroup getParentGroup(KdbGroup group) {
        if(group.isRoot()) return null;
        
        for(int i = 0; i < getGroups().size(); i++) {
            KdbGroup parent = (KdbGroup) getGroups().elementAt(i);
            if (parent.getTreeLevel() == group.getTreeLevel() - 1 && getChildGroups(parent).contains(group)) return parent;
        }
        return null;
    }
    
    public Vector getParentGroups(KdbGroup child) {
        if(child.isRoot()) return new Vector(0);
        KdbGroup parentGroup = getParentGroup(child);
        return getSiblingGroups(parentGroup);
    }
    
    public KdbGroup getParentGroup(KdbEntry entry) {
        for(int i = 0; i < getGroups().size(); i++) {
            KdbGroup parent = (KdbGroup) getGroups().elementAt(i);
            if (parent.getId() == entry.getGroupId()) return parent;
        }
        return null;
    }
    
    public KdbGroup getGroup(int id) {
        for(int i = 0; i < getGroups().size(); i++) {
            KdbGroup group = (KdbGroup) getGroups().elementAt(i);
            if (id == group.getId()) return group;
        }
        return null;
    }
    
    public KdbEntry getEntry(byte[] id) {
        for(int i = 0; i < getEntries().size(); i++) {
            KdbEntry entry = (KdbEntry) getEntries().elementAt(i);
            if (ByteArrays.equals(id, entry.getId())) return entry;
        }
        return null;
    }
    
    public Vector getParentGroups(KdbEntry entry) {
        KdbGroup parentGroup = getParentGroup(entry);
        return getSiblingGroups(parentGroup);
    }
    
    public Vector getSiblingGroups(KdbGroup group) {
        if(group.isRoot()) return getRootGroups();
        
        Vector siblings = new Vector();
        for(int i = 0; i < getGroups().size(); i++) {
            KdbGroup sibling = (KdbGroup) getGroups().elementAt(i);
            if (sibling.getTreeLevel() == group.getTreeLevel() && 
                    getParentGroup(sibling).getId() == getParentGroup(group).getId()) {
                siblings.addElement(sibling);
            }
        }
        return siblings;
    }
    
    public boolean isEmpty(KdbGroup group) {
        if(getChildGroups(group).size() > 0 || getEntries(group).size() > 0) {
            return false;
        } else {
            return true;
        }
    }
    
    public Vector getEntries(KdbGroup group) {
        if(group == null) {
            return new Vector(0);
        }
        
        Vector ents = new Vector();
        for (int i = 0; i < getEntries().size(); i++) {
            KdbEntry ent = (KdbEntry) getEntries().elementAt(i);
            if (ent.getGroupId() == group.getId() && !ent.isInternal())
                ents.addElement(ent);
        }
        return ents;
    }
    
    public String getGroupPath(KdbGroup group) {
        if(group.isRoot()) return "/"+group.getName();
        else return getGroupPath(getParentGroup(group)) + "/"+group.getName();
    }
    
    public void moveEntry(KdbEntry entry, KdbGroup newParent) {
        ((KdbEntryV1)entry).setGroupId(newParent.getId());
        changed = true;
    }
    
    public Vector search(String searchText, SearchOptions options, ProgressMonitor pm) {
        Vector ents = new Vector();
        if(searchText != null && !"".equals(searchText)) {
            if(pm != null) pm.nextStep(getEntries().size(), "pm_search");
            for (int i = 0; i < getEntries().size(); i++) {
                KdbEntry ent = (KdbEntry) getEntries().elementAt(i);
                if(((options.searchTitle && ent.getTitle() != null && ent.getTitle().toLowerCase().indexOf(searchText.toLowerCase()) >= 0) ||
                   (options.searchUsername && ent.getUsername() != null && ent.getUsername().toLowerCase().indexOf(searchText.toLowerCase()) >= 0) ||
                   (options.searchUrl && ent.getUrl() != null && ent.getUrl().toLowerCase().indexOf(searchText.toLowerCase()) >= 0) ||
                   (options.searchNotes && ent.getNotes() != null && ent.getNotes().toLowerCase().indexOf(searchText.toLowerCase()) >= 0) ||
                   (options.searchBinaryDescription && ent.getBinaryDescription() != null && ent.getBinaryDescription().toLowerCase().indexOf(searchText.toLowerCase()) >= 0)) &&
                   !ent.isInternal() && (!isBackupEntry(ent) || options.searchBackupFolder)) {
                    ents.addElement(ent);
                    if(ents.size() >= options.searchResultsMax) return ents;
                    if(pm != null) pm.setStatusMessage("pm_searchresult", new Object[]{new Integer(ents.size())});
                }
                if(pm != null) {
                    if(pm.isCanceled()) return ents;
                    pm.tick();
                }
            }
        }
        return ents;
    }
    
    protected abstract void backup(KdbEntry entry);
    
    protected KdbGroup getBackupGroup() {
        for (int i = 0; i < getRootGroups().size(); i++) {
            KdbGroup group = (KdbGroup) getRootGroups().elementAt(i);
            if(isBackupGroup(group)) return group;
        }
        return null;
    }

    public boolean isBackupItem(KdbItem item) {
        if(item instanceof KdbGroup) {
            return isBackupGroup((KdbGroup)item);
        } else {
            return isBackupEntry((KdbEntry)item);
        }
    }
    
    /**
     * Returns true, if given folder is the backup folder of this database.
     * 
     * DEV: design flaw -> using group name to identify backup folder.
     * In different languages this method can return wrong results!
     * 
     * NEW IN V0.8: Dominik from KeePass reserved the 4096 bit of the
     * 'internal flag' group property for KeePassMobile to identify the
     * backup group
     */
    public boolean isBackupGroup(KdbGroup group) {
        return hasNewBackupFlag ? ((group.getInternalFlags() & BACKUP_GROUP_FLAG) > 0) : 
            (group.isRoot() && "Backup".equals(group.getName()));
    }
    
    public boolean isBackupEntry(KdbEntry entry) {
        return isBackupGroup(getRootGroup(entry));
    }
    
    public void checkNewBackupFlag() {
        for(int i = 0; i < getGroups().size(); i++) {
            KdbGroup group = (KdbGroup) getGroups().elementAt(i);
            if ((group.getInternalFlags() & BACKUP_GROUP_FLAG) > 0) {
                this.hasNewBackupFlag = true;
                return;
            }
        }
        this.hasNewBackupFlag = false;
    }
}
