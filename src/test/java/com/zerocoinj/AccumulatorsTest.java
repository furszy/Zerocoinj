// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj;

import com.zerocoinj.base.BaseZerocoinTest;
import com.zerocoinj.core.CoinDenomination;
import com.zerocoinj.core.Commitment;
import com.zerocoinj.core.ZeroCoin;
import com.zerocoinj.core.accumulators.Accumulator;
import com.zerocoinj.core.accumulators.AccumulatorWitness;
import com.zerocoinj.core.exceptions.InvalidSerialException;
import com.zerocoinj.utils.ZUtils;
import org.junit.Assert;
import org.junit.Test;
import org.pivxj.core.BloomFilter;
import org.pivxj.core.ECKey;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.List;

public class AccumulatorsTest extends BaseZerocoinTest {

    @Test
    public void accumulateAndGenerateWitness() {

        /********************************************************************/
        // What is it:      Accumulator computation
        // Who does it:     ZEROCOIN CLIENTS & TRANSACTION VERIFIERS
        // What it does:    Collects a number of PublicCoin values drawn from
        //                  the block chain and calculates an accumulator.
        //                  This accumulator is incrementally computable;
        //                  you can stop and serialize it at any point
        //                  then continue accumulating new transactions.
        //                  The accumulator is also order-independent, so
        //                  the same coins can be accumulated in any order
        //                  to give the same result.
        //                  WARNING: do not accumulate the same coin twice!
        /********************************************************************/


        System.out.println("Base params: " + zerocoinContext.getAccumulatorParams());

        int TESTS_COINS_TO_ACCUMULATE = 10;

        List<ZeroCoin> coinList = generateCoins(zerocoinContext, TESTS_COINS_TO_ACCUMULATE);

        // Create an empty accumulator object
        Accumulator accOne = new Accumulator(zerocoinContext.getAccumulatorParams(),CoinDenomination.ZQ_ONE);
        Accumulator accTwo = new Accumulator(zerocoinContext.getAccumulatorParams(),CoinDenomination.ZQ_ONE);
        Accumulator accThree = new Accumulator(zerocoinContext.getAccumulatorParams(),CoinDenomination.ZQ_ONE);
        Accumulator accFour = new Accumulator(zerocoinContext.getAccumulatorParams(),CoinDenomination.ZQ_ONE);
        AccumulatorWitness wThree = new AccumulatorWitness(accThree.copy(), coinList.get(0));

        // Now let's accumulate the coins
        for (int i = 0; i < TESTS_COINS_TO_ACCUMULATE; i++) {
            accOne.accumulate(coinList.get(i));
            accTwo.accumulate(coinList.get(TESTS_COINS_TO_ACCUMULATE - (i+1)));
            accThree.accumulate(coinList.get(i));
            wThree.addElement(coinList.get(i));
            if (i != 0){
                accFour.accumulate(coinList.get(i));
            }
        }

        // Compare the accumulated results
        boolean isAccOneNotEqualToAccTwo = !ZUtils.equals(accOne.getValue(), accTwo.getValue());
        boolean isAccOneNotEqualsToAccThree = !ZUtils.equals(accOne.getValue(), accThree.getValue());
        if (isAccOneNotEqualToAccTwo || isAccOneNotEqualsToAccThree) {
            throw new RuntimeException("Accumulators don't match");
        }

        if(! ZUtils.equals(accFour.getValue() , wThree.getValue() )) {
            throw new RuntimeException("Witness math not working");
        }

        // Verify that the witness is correct
        if (!wThree.verifyWitness(accThree, coinList.get(0)) ) {
            throw new RuntimeException("Witness not valid");
        }

        // TODO: add a test for the serialization/deserialization of this..
    }

    @Test
    public void genWitnessBloomFilter(){

        try {

            Accumulator fullAccumulator = new Accumulator(zerocoinContext.accumulatorParams, CoinDenomination.ZQ_ONE);

            List<ZeroCoin> mintedCoins = generateCoins(zerocoinContext, 10);
            mintedCoins.add(0, getFixedCoinToAccumulate());
            // Accumulate every coin to the full accumulator
            mintedCoins.forEach(fullAccumulator::accumulate);

            BloomFilter bloomFilter = new BloomFilter(1, 0.001, (long) (Math.random() * Long.MAX_VALUE));
            BigInteger value = mintedCoins.get(0).getCommitment().getCommitmentValue();
            bloomFilter.insert(ZUtils.serializeBigInteger(value));

            BigInteger valueNotInTheBloomFilter = mintedCoins.get(1).getCommitment().getCommitmentValue();
            BigInteger valueNotInTheBloomFilter2 = mintedCoins.get(2).getCommitment().getCommitmentValue();


            Assert.assertTrue("Value is not in the bloom filter", bloomFilter.contains(ZUtils.serializeBigInteger(value)));
            Assert.assertFalse("False positive", bloomFilter.contains(ZUtils.serializeBigInteger(valueNotInTheBloomFilter)));
            Assert.assertFalse("False positive", bloomFilter.contains(ZUtils.serializeBigInteger(valueNotInTheBloomFilter2)));

        } catch (InvalidSerialException e) {
            Assert.fail("Invalid serial in hardcoded coin creation");
        }
    }


    private static ZeroCoin getFixedCoinToAccumulate() throws InvalidSerialException {
        // Initial params
        ECKey ecKey = ECKey.fromPrivate(Hex.decode("05428f06cd1dd86c202f7f768460ceb8ca613b478c2b9a56da5904a6e01feafb"));
        BigInteger serial = ZeroCoin.generateSerial(ecKey);
        Commitment commitment = new Commitment(
                serial,
                new BigInteger("2390488417825796905446191797907317580555055449497400863046150136107332432991581508294308367332278340661601947647386625513081111368934764903805664136904530276483489343627033145949035591298498438742586050275211196398704380474365872315771383816553071498913573657323085265505218427064035696415904797386139981973"),
                new BigInteger("55847297248851286638767153313891635041639056443849327359544853196842740156050")
        );

        CoinDenomination denomination = CoinDenomination.ZQ_ONE;

        // Recreate the zeroCoin that we are going to redeem
        ZeroCoin mintedCoin = new ZeroCoin(
                zerocoinContext,
                serial,
                commitment,
                denomination,
                ecKey
        );
        System.out.println("Hardcoded Commitment value: " + commitment.getCommitmentValue());
        return mintedCoin;
    }

}
