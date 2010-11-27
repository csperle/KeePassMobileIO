package org.sperle.keepass.kdb;

/**
 * A close strategy implements a algorithm that is called to close the KeePass database.
 */
public interface CloseStrategy {
    void close(KeePassDatabase kdb);
}
