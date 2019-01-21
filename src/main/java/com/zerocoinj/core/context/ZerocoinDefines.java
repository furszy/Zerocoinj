// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core.context;

public class ZerocoinDefines {

    public static final int ZEROCOIN_DEFAULT_SECURITYLEVEL          =       80;
    public static final int ZEROCOIN_MIN_SECURITY_LEVEL             =       80;
    public static final int ZEROCOIN_MAX_SECURITY_LEVEL             =       80;
    public static final int ACCPROOF_KPRIME                         =       160;
    public static final int ACCPROOF_KDPRIME                        =       128;
    public static final int MAX_COINMINT_ATTEMPTS                   =       10000;
    public static final int ZEROCOIN_MINT_PRIME_PARAM			    =       20;
    public static final String ZEROCOIN_VERSION_STRING              =       "0.11";
    public static final int ZEROCOIN_VERSION_INT				    =       11;
    public static final String ZEROCOIN_PROTOCOL_VERSION            =       "1";
    public static final int HASH_OUTPUT_BITS                        =       256;
    public static final String ZEROCOIN_COMMITMENT_EQUALITY_PROOF   =       "COMMITMENT_EQUALITY_PROOF";
    public static final String ZEROCOIN_ACCUMULATOR_PROOF           =       "ACCUMULATOR_PROOF";
    public static final String ZEROCOIN_SERIALNUMBER_PROOF          =       "SERIALNUMBER_PROOF";

    // Activate multithreaded mode for proof verification
    public static final int ZEROCOIN_THREADING  = 1;

    // Uses a fast technique for coin generation. Could be more vulnerable
    // to timing attacks. Turn off if an attacker can measure coin minting time.
    public static final int	ZEROCOIN_FAST_MINT = 1;

}
