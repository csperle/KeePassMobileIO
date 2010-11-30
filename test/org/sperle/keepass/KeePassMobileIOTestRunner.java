package org.sperle.keepass;

import jmunit.framework.cldc11.Test;
import jmunit.framework.cldc11.TestRunner;

/**
 * The TestRunner is a MIDLet that automatically starts the whole test suite and shuts the emulator
 * down afterward (not used at the moment).
 */
public class KeePassMobileIOTestRunner extends TestRunner {
    private Test nestedTest;

    public KeePassMobileIOTestRunner() {
        super(2000); // seconds to wait till automatic shutdown
        this.nestedTest = new KeePassMobileIOTestSuite();
    }

    protected Test getNestedTest() {
        return this.nestedTest;
    }
}