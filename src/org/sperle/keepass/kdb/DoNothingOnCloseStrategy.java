package org.sperle.keepass.kdb;


/**
 * This close strategy does nothing else than closing the database.
 */
public class DoNothingOnCloseStrategy implements CloseStrategy {

    public void close(KeePassDatabase kdb) {
        kdb.close();
    }
}
