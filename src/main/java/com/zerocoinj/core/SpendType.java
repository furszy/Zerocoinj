// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

public enum SpendType{
        SPEND, // Used for a typical spend transaction, zPIV should be unusable after
        STAKE, // Used for a spend that occurs as a stake
        MN_COLLATERAL, // Used when proving ownership of zPIV that will be used for masternodes (future)
        SIGN_MESSAGE // Used to sign messages that do not belong above (future)
};