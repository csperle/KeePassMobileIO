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

package org.sperle.keepass.io;

import java.io.IOException;

import org.sperle.keepass.monitor.ProgressMonitor;

/**
 * The IO manager does file IO.
 */
public interface IOManager {
    /**
     * Loads a binary file.
     * 
     * @param filename the path/name of the file
     * @param pm the progress monitor to monitor loading process, can be null
     * @return binary data
     * @throws IOException if an IO error occurs
     */
    byte[] loadBinary(String filename, ProgressMonitor pm) throws IOException;

    /**
     * Saves a binary file. The save process should be implemented very
     * defensively: first create a temporary file and save the contents into
     * that, then delete the original file and rename the temp file. This
     * guarantees, that there is a valid file left, even when the user cancels
     * or a exception occurs (no battery!).
     * 
     * @param filename the path/name of the file
     * @param binary binary data
     * @param pm the progress monitor to monitor saving process, can be null
     * @throws IOException if an IO error occurs
     */
    void saveBinary(String filename, byte[] binary, ProgressMonitor pm) throws IOException;
    
    /**
     * Deletes the file with the specified name.
     * 
     * @param filename name of file to delete
     * @throws IOException if an IO error occurs
     */
    void delete(String filename) throws IOException;
    
    /**
     * Returns the size of the file in bytes.
     * 
     * @param filename the path/name of the file
     * @return file size
     * @throws IOException if an IO error occurs
     */
    long getFileSize(String filename) throws IOException;

    /**
     * Returns true if file exists.
     */
    boolean exists(String filename) throws IOException;

    /**
     * Returns true if both files are binary equal.
     */
    boolean equals(String filename1, String filename2) throws IOException;

    /**
     * Generates a hash out of any file.
     * 
     * @param filename the path/name of the file
     * @param hash hash algorithm to use
     * @param packetSize size of the file package to use for calculation in bytes
     * @return hash result
     */
    byte[] generateHash(String filename, int packetSize) throws IOException;
}
