// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core.accumulators;

import com.zerocoinj.core.CoinDenomination;
import com.zerocoinj.utils.ZUtils;
import org.pivxj.core.Sha256Hash;
import org.pivxj.core.Utils;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class Accumulators {

    public static long parseChecksum(String nChecksum, CoinDenomination denomination){
        byte[] data = Hex.decode(nChecksum);
        int pos = denomination.ordinal() - 1;
        // This is in bytes and not bits, that is why this is 4 and not 32
        return Utils.readUint32BE(data, 4 * pos);
    }

    public static long getChecksum(BigInteger bnValue) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ZUtils.serializeBigInteger(outputStream, bnValue);
            byte[] serializedBn = outputStream.toByteArray();
            outputStream.close();
            return Utils.readUint32(
                    Sha256Hash.twiceOf(serializedBn).getBytes(),
                    0
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
