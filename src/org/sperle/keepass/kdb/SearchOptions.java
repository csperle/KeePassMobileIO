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
 * The search options control the search algorithm.
 */
public class SearchOptions {
    public final static int DEFAULT_SEARCH_RESULTS = 50;
    public final static int MAX_SEARCH_RESULTS = 200;
    
    public int searchResultsMax = 50;
    public boolean searchBackupFolder = true;
    
    public boolean searchUsername = true;
    public boolean searchTitle = true;
    public boolean searchUrl = true;
    public boolean searchNotes = true;
    public boolean searchBinaryDescription = false;
}
