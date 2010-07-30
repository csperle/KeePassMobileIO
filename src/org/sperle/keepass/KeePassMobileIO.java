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

package org.sperle.keepass;

import java.io.IOException;

import org.sperle.keepass.crypto.KeePassCryptoException;
import org.sperle.keepass.kdb.KdbEntry;
import org.sperle.keepass.kdb.KeePassDatabase;
import org.sperle.keepass.kdb.KeePassDatabaseException;
import org.sperle.keepass.kdb.KeePassDatabaseManager;
import org.sperle.keepass.monitor.ProgressMonitor;

/**
 * Facade class to access the KeePass IO functionality. Use the KeePassIOFactory
 * class to construct an instance of this class.
 */
public final class KeePassMobileIO {
    private KeePassDatabaseManager dbm;

    public KeePassMobileIO(KeePassDatabaseManager dbm) {
        this.dbm = dbm;
    }
    
    /**
     * Creates a new KeePass database.
     * 
     * @param name the name of the new database
     * @param masterPassword key for encryption
     * @param keyFileName path/name of key file for encryption
     * @throws IOException if key file can not be loaded
     */
    public KeePassDatabase create(String name, String masterPassword, String keyFileName) throws IOException {
        return dbm.create(name, masterPassword, keyFileName);
    }

    /**
     * Loads a KeePass database file.
     * @param filename path/name to the kdb file
     * @param masterPassword the master password to decrypt the database
     * @param keyFileName path/name of a key file to decrypt the database
     * @param pm the progress monitor to monitor loading process, can be null
     * @return the database instance to access it's content
     * @throws IOException if kdb file could not be loaded
     * @throws KeePassCryptoException if kdb file could not be decrypted
     * @throws KeePassDatabaseException if decrypted kdb content is not valid
     */
    public KeePassDatabase load(String filename, String masterPassword, String keyFileName, ProgressMonitor pm) throws IOException, KeePassCryptoException,
            KeePassDatabaseException {
        return dbm.load(filename, masterPassword, keyFileName, pm);
    }
    
    /**
     * Saves the attachment of the specified entry to a file.
     * @param entry the entry of the attachment 
     * @param foldername the path/name of the folder to save the file to (filename is specified in
     * the entry itself) 
     * @throws IOException if attachment could not be saved
     */
    public void saveAttachment(KdbEntry entry, String foldername) throws IOException {
        dbm.saveAttachment(entry, foldername);
    }
    
    /**
     * Adds a file as attachment to the specified entry.
     * @param entry the entry to add the attachment to 
     * @param filename the path/name of the file to add as attachment
     * @throws IOException if file could not be loaded
     */
    public void addAttachment(KdbEntry entry, String filename) throws IOException {
        dbm.addAttachment(entry, filename);
    }
    
    /**
     * Sets the file that is used as part of the master key.
     * @param filename the path/name of the key file
     * @throws IOException if key file could not be loaded
     * @throws KeePassDatabaseException if KeePass database is not supported
     */
    public void setKeyFile(KeePassDatabase kdb, String filename) throws IOException, KeePassDatabaseException {
        dbm.setKeyFile(kdb, filename);
    }
    
    /**
     * Saves a KeePass database to a file.
     * @param kdb KeePass database to save
     * @param filename path/name of the kdb file
     * @param pm the progress monitor to monitor saving process, can be null
     * @return true, if database was saved successfully - false, if user canceled
     * @throws IOException if kdb file could not be saved
     * @throws KeePassCryptoException if kdb file could not be encrypted
     * @throws KeePassDatabaseException if KeePass database is not supported
     */
    public boolean save(KeePassDatabase kdb, String filename, ProgressMonitor pm) throws IOException, KeePassCryptoException,
            KeePassDatabaseException {
        return dbm.save(kdb, filename, pm);
    }
}
