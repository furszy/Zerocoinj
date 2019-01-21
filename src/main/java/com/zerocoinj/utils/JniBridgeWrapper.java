// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.utils;

public interface JniBridgeWrapper {

    // Compute seed
    byte[] compute1024seed(byte[] seed);

    //
    String computeVSeedAndVExpanded();

}
