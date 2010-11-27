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

import java.io.IOException;

import org.sperle.keepass.crypto.KeePassCryptoException;
import org.sperle.keepass.monitor.ProgressMonitor;

/**
 * The KeePass database manager loads(+decrypts) and saves(+encrypts) KeePass databases.
 */
public interface KeePassDatabaseManager {
    
    /**
     * Creates a new KeePass database.
     * 
     * @param name the name of the new database
     * @param masterPassword key for encryption
     * @param keyFileName path/name of key file for encryption
     * @throws IOException if key file can not be loaded
     */
    KeePassDatabase create(String name, String masterPassword, String keyFileName) throws IOException;
    
    /**
     * Loads(+decrypts) a KeePass database.
     * @param fileName path/name of the database file
     * @param masterPassword key for decryption
     * @param keyFileName path/name of key file for decryption
     * @param pm the progress monitor to monitor loading process, can be null
     * @return KeePass database object
     * @throws IOException if file can not be loaded
     * @throws KeePassCryptoException if database can not be decrypted
     * @throws KeePassDatabaseException if database is invalid
     */
    KeePassDatabase load(String fileName, String masterPassword, String keyFileName, ProgressMonitor pm) throws IOException, KeePassCryptoException, KeePassDatabaseException;

    /**
     * Registers a crypto algorithm that knows how to encrypt/decrypt certain kind of KeePass databases.
     */
    void registerCryptoAlgorithm(KeePassDatabaseCryptoAlgorithm cryptoAlgorithm);
    
    /**
     * Saves(+encrypts) a KeePass database.
     * @param kdb the KeePass database to save
     * @param fileName path/name of the database file
     * @param pm the progress monitor to monitor saving process, can be null
     * @return true, if database was saved successfully - false, if user canceled
     * @throws IOException if file can not be saved
     * @throws KeePassCryptoException if database can not be encrypted
     * @throws KeePassDatabaseException if database is not supported
     */
    boolean save(KeePassDatabase kdb, String fileName, ProgressMonitor pm) throws IOException, KeePassCryptoException, KeePassDatabaseException;
    
    /**
     * Saves the attachment of the specified entry to a file.
     * @param entry the entry of the attachment 
     * @param foldername the path/name of the folder to save the file to (filename is specified in
     * the entry itself) 
     * @throws IOException if attachment could not be saved
     */
    void saveAttachment(KdbEntry entry, String foldername) throws IOException;

    /**
     * Adds a file as attachment to the specified entry.
     * @param entry the entry to add the attachment to 
     * @param filename the path/name of the file to add as attachment
     * @throws IOException if file could not be loaded
     */
    void addAttachment(KdbEntry entry, String filename) throws IOException;

    /**
     * Sets the file that is used as part of the master key.
     * @param filename the path/name of the key file
     * @throws IOException if key file could not be loaded
     * @throws KeePassDatabaseException if KeePass database is not supported
     */
    void setKeyFile(KeePassDatabase kdb, String filename) throws IOException, KeePassDatabaseException;

    /**
     * Closes the KeePass database.
     * @param kdb KeePass database to close
     */
    void close(KeePassDatabase kdb);
}
