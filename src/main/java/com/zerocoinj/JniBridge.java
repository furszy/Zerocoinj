// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj;

import com.zerocoinj.utils.JniBridgeWrapper;


public class JniBridge implements JniBridgeWrapper {

    static {
        System.out.println(("***********************************************************************************"));
        System.out.println(("*** Native library initialization sequence beginning.  "));
        System.out.println(("*** java.library.path: " + System.getProperty("java.library.path")));
        System.out.println(("***"));

        // Load the JNI bridge
        System.out.println(("***"));
        System.out.println(("*** Loading JNI bridge library..."));
        try {
            System.loadLibrary("bridge");
        } catch (Error | Exception e) {
            System.out.println("***********************************************************************************");
            System.out.println("*** Failed to load JNI bridge library: " + e.getMessage());
            System.out.println("***********************************************************************************");
        }

        System.out.println(("***"));
        System.out.println(("*** Native library initialization sequence complete.  "));
        System.out.println(("***********************************************************************************"));
    }

    public JniBridge() {
    }

    // Compute seed
    public native byte[] compute1024seed(byte[] seed);

    //
    public native String computeVSeedAndVExpanded();
}
