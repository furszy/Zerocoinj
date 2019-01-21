// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj;

import com.zerocoinj.base.BaseZerocoinTest;
import com.zerocoinj.core.CoinDenomination;
import com.zerocoinj.core.Commitment;
import com.zerocoinj.core.ZeroCoin;
import com.zerocoinj.core.accumulators.Accumulators;
import org.junit.Assert;
import org.junit.Test;
import org.pivxj.core.*;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;

public class CoinSpendTransactionTest extends BaseZerocoinTest {

    private ZeroCoin loadUsedCoin(){
        ECKey ecKey = DumpedPrivateKey.fromBase58(params,"YQsiecvijvDhWKLZdCjrVDZFDLZ9h4vqHA41mCT5qVfsRNd65ame").getKey();

        BigInteger serial = new BigInteger("110472382934031650861109780437219935132951134920037147893700654158977699911958");
        long startTine = System.currentTimeMillis();
        ZeroCoin zeroCoin = new ZeroCoin(
                zerocoinContext,
                serial,
                new Commitment(
                        serial,
                        new BigInteger("22647209324847099310992131739994072293922818690615801467225369566946073129624"),
                        zerocoinContext.coinCommitmentGroup
                ),
                CoinDenomination.ZQ_ONE,
                ecKey
        );

        // tx data
        zeroCoin.setParentTxId(Sha256Hash.wrap("6ebb640608bc2e66a1f69d17805f6269af87cc8bf5a4a76d98b4bfeca4ff6df1"));
        zeroCoin.setHeight(1246075);

        if (ZeroCoin.extractVersionFromSerial(zeroCoin.getSerial()) != 2){
            throw new RuntimeException("Invalid serial");
        }
        System.out.println("Coin: " + zeroCoin);

        System.out.println("CommitmentValue HEX: " + zeroCoin.getCommitment().getCommitmentValue().toString(16));
        System.out.println("Serial HEX: " + zeroCoin.getSerial().toString(16));
        System.out.println("Randomness HEX: " + zeroCoin.getCommitment().getRandomness().toString(16));

        System.out.println(zeroCoin.toJsonString());
        return zeroCoin;
    }

    /**
     * TODO: Validate checksum with the accChecksum that is saved in the block header ---> Create 'parseChecksum' test..
     */
    @Test
    public void getChecksum(){
        BigInteger accumulatorValue = new BigInteger("3561600663402940732926043906364423161020342440624117570307091249060639206885130653863988878111310428748077228638352868732650158168092423962689079110324194403339356739684193064497664029797580227854526680598119493153506486861915117712084666457148723320456773331947568167765838929486198541587192008449043963542332768257345834745820618774265995860622095001311481803199614256817649809449639792171267561165839851563395985427353179021834999023255176416193723539458011239125983858692882261497427646089462797776980136519779279468532910388663095304534007710986799459485044817255525023687739904795167747777071707348910578166973");
        long accChecsum = Accumulators.getChecksum(accumulatorValue);
        Assert.assertEquals("AccChecksum is not valid", 1007276367, accChecsum);
    }

    @Test
    public void parseChecksum(){
        Accumulators.parseChecksum(
                "65f5f0b81ceaffcdaca31ccd76d2d59665563ca286ae8201392106930ab93376",
                CoinDenomination.ZQ_ONE
        );
    }

    @Test
    public void sign(){
        ECKey ecKey = DumpedPrivateKey.fromBase58(params,"YQsiecvijvDhWKLZdCjrVDZFDLZ9h4vqHA41mCT5qVfsRNd65ame").getKey();
        Sha256Hash dataToHash = Sha256Hash.wrap(
                Sha256Hash.wrap("4e7b723afb0f128c16f7ba027cdaf93fda3d3c030d7b90eff21c273fb22a25fd").getReversedBytes()
        );
        ECKey.ECDSASignature signature = ecKey.sign(dataToHash);
        System.out.println("Signature in DER: " + Hex.toHexString(signature.encodeToDER()));
    }

}
