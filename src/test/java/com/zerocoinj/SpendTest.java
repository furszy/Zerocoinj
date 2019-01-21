// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


package com.zerocoinj;

import com.google.common.collect.Lists;
import com.zerocoinj.base.BaseZerocoinTest;
import com.zerocoinj.core.*;
import com.zerocoinj.core.accumulators.Accumulator;
import com.zerocoinj.core.accumulators.AccumulatorWitness;
import com.zerocoinj.core.exceptions.InvalidSerialException;
import org.junit.Assert;
import org.junit.Test;
import org.pivxj.core.DumpedPrivateKey;
import org.pivxj.core.ECKey;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

public class SpendTest extends BaseZerocoinTest {

    @Test
    public void extractCoinSerialVersion(){

        ZeroCoin zeroCoin;

        while (true){
            try {
                zeroCoin = ZeroCoin.mintCoin(zerocoinContext, new ECKey(), CoinDenomination.ZQ_ONE);
                break;
            }catch (InvalidSerialException e){
            }
        }

        int version = ZeroCoin.extractVersionFromSerial(zeroCoin.getSerial());

        if (version != 2){
            Assert.fail("Invalid serial, version: " + version + ", " + zeroCoin.getSerial().toString(16));
        }else
            System.out.println("Valid serial, version: " + version + ", " + zeroCoin.getSerial().toString(16));

    }

    @Test
    public void mintAndSpendHardcoded() {

        // Mint and spend 5 times
        //for (int i = 0; i < 5; i++) {
            ECKey myKey = DumpedPrivateKey.fromBase58(params, "YNyCg4VwmWVHTTxyWGL6iQibTcZDs6K1ZFMzzNmfi31rmCLE6FQP").getKey();
            BigInteger mySerial = new BigInteger("111009496398446893607276187048990094508087714183805354000455438810437041952239");
            BigInteger myRandomness = new BigInteger("267649460127242815898575883083924440094914945403402767500310424593420110218");
            Commitment commitment = new Commitment(mySerial, myRandomness, zerocoinContext.getCoinCommitmentGroup());
            // Pub key --> 03091b56e476d643ca4954df39045dcbed5c6c6855d852b22b6d085067ece97b09
            ZeroCoin myCoin = new ZeroCoin(
                    zerocoinContext,
                    mySerial,
                    commitment,
                    CoinDenomination.ZQ_ONE,
                    myKey
            );

            ECKey key1 = DumpedPrivateKey.fromBase58(params,"YPkJLXeWbqSdfHkYXzNQ1ZMHcqxBryWF7raHb6cFBsr1jjMwg5VH").getKey();
            BigInteger serialCoin1 = new BigInteger("-3426450141185389544394515773681044325391463801641779838771205630415819980801");
            BigInteger randomnessCoin1 = new BigInteger("15259503457837854135433568039121272151791251817140985216137758469010177135810");
            Commitment commitmentCoin1 = new Commitment(serialCoin1, randomnessCoin1, zerocoinContext.getCoinCommitmentGroup());
            // pubkey --> 03541b87b84c1e6f810c5878129940fafe0795f0aad5f4b6411cdd3e7f3de2fef3
            // serial --> -3426450141185389544394515773681044325391463801641779838771205630415819980801
            ZeroCoin coin1 = new ZeroCoin(
                    zerocoinContext,
                    serialCoin1,
                    commitmentCoin1,
                    CoinDenomination.ZQ_ONE,
                    key1
            );

            ECKey key2 = DumpedPrivateKey.fromBase58(params,"YSz5sZxEFh4mV7S6FSpAiQuQRcmEc6QSLa8RhhATchtx6c5Zqh2j").getKey();
            BigInteger serialCoin2 = new BigInteger("2827963440474786774384693538447795721161954704748445280012090701255812078207");
            BigInteger randomnessCoin2 = new BigInteger("6238797081974602146901267375481108544838417762119067918155650661875803784910");
            Commitment commitmentCoin2 = new Commitment(serialCoin2, randomnessCoin2, zerocoinContext.getCoinCommitmentGroup());
            // pubkey --> 02e42793f1836038482cd19847fe833e6cc91ccc5008506e82a4663f650b4eabb7
            // serial --> 2827963440474786774384693538447795721161954704748445280012090701255812078207
            ZeroCoin coin2 = new ZeroCoin(
                    zerocoinContext,
                    serialCoin2,
                    commitmentCoin2,
                    CoinDenomination.ZQ_ONE,
                    key2
            );


            List<ZeroCoin> randomCoins = Lists.newArrayList(myCoin,coin1,coin2);
            //List<zeroCoin> randomCoins = generateCoins(zerocoinContext, 5); //Lists.newArrayList(myCoin, coin1, coin2 );

            //zeroCoin myCoin = randomCoins.get(0);

            // Accumulate the list of generated coins into a fresh accumulator.
            // The first one gets marked as accumulated for a witness, the
            // others just get accumulated normally.
            Accumulator acc = new Accumulator(
                    zerocoinContext.getAccumulatorParams(),
                    CoinDenomination.ZQ_ONE
            );

            AccumulatorWitness wAcc = new AccumulatorWitness(
                    acc,
                    myCoin
            );

            for (ZeroCoin coin : randomCoins) {
                acc.accumulate(coin);
                wAcc.addElement(coin);
            }

            SerialNumberSignatureOfKnowledge.RandomNumbers randomNumbers = null;

            // Now spend the coin
            CoinSpend spend = new CoinSpend(
                    zerocoinContext,
                    myCoin,
                    acc,
                    BigInteger.ZERO,
                    wAcc,
                    null,
                    SpendType.SPEND,
                    randomNumbers
            );

            // TODO: Update this old code..
//            byte[] accPoKBytes = readFile("mint_spend_test/serialized_accPoK.txt");
//            AccumulatorProofOfKnowledge accumulatorProofOfKnowledge = AccumulatorProofOfKnowledge.parse(params,zerocoinContext,accPoKBytes,0,true);
//
//            // First check that the accumulatorPoK is the same.
//            Assert.assertEquals(
//                    "AccumulatorPoK invalid",
//                    accumulatorProofOfKnowledge, spend.getAccumulatorPoK()
//            );


//            // TODO: Update this old code..
//            // Now check if the commitment is equal to c++
//            byte[] commitmentPoKBytes = readFile("mint_spend_test/serialized_commitmentPoK.txt");
//            CommitmentProofOfKnowledge commitmentPoK = CommitmentProofOfKnowledge.parse(
//                    params,
//                    zerocoinContext.getSerialNumberSoKCommitmentGroup(),
//                    zerocoinContext.getAccumulatorParams().getAccumulatorPoKCommitmentGroup(),
//                    commitmentPoKBytes,
//                    0,
//                    true
//            );
//
//            // First check that the accumulatorPoK is the same.
//            Assert.assertEquals(
//                    "commitmentPoKBytes invalid",
//                    commitmentPoK, spend.getCommitmentPoK()
//            );

            Assert.assertTrue("SpendCoin not valid" , spend.verify(acc));

        //}
    }

    @Test
    public void mintAndSpend(){

        List<ZeroCoin> randomCoins = generateCoins(zerocoinContext, 5); //Lists.newArrayList(myCoin, coin1, coin2 );
        ZeroCoin myCoin = randomCoins.get(0);

        // Accumulate the list of generated coins into a fresh accumulator.
        // The first one gets marked as accumulated for a witness, the
        // others just get accumulated normally.
        Accumulator acc = new Accumulator(
                zerocoinContext.getAccumulatorParams(),
                CoinDenomination.ZQ_ONE
        );

        AccumulatorWitness wAcc = new AccumulatorWitness(
                acc,
                myCoin
        );

        for (ZeroCoin coin : randomCoins) {
            acc.accumulate(coin);
            wAcc.addElement(coin);
        }

        // Now spend the coin
        CoinSpend spend = new CoinSpend(
                zerocoinContext,
                myCoin,
                acc,
                BigInteger.ZERO,
                wAcc,
                null,
                SpendType.SPEND,
                null
        );

        Assert.assertTrue("SpendCoin not valid" , spend.verify(acc));
    }

    private SerialNumberSignatureOfKnowledge.RandomNumbers loadRandomNumbersFromFile() {
        //
        File file = new File("mint_spend_test/serialNumberSoK_init.txt");//url.getPath());
        SerialNumberSignatureOfKnowledge.RandomNumbers randomNumbers = new SerialNumberSignatureOfKnowledge.RandomNumbers();
        if (!file.exists())
            throw new RuntimeException("Cannot read file, " + file.toPath());
        try {
            //File f = new File("src/com/mkyong/data.txt");

            BufferedReader b = new BufferedReader(new FileReader(file));
            String readLine = "";
            int i = 0;
            String s;
            while ((readLine = b.readLine()) != null) {
                switch (readLine.charAt(0) ){
                    case 'r':
                        s = readLine.substring(2);
                        randomNumbers.r[i] = new BigInteger(s);
                        break;
                    case 'v':
                        if (readLine.contains("v_seed")){
                            s = readLine.substring(7);
                            randomNumbers.v_seed[i] = new BigInteger(s);
                        }else {
                            s = readLine.substring(11);
                            randomNumbers.v_expanded[i] = new BigInteger(s);
                            i++;
                        }
                        break;
                }
            }

            return randomNumbers;

        } catch (IOException e) {
            throw new RuntimeException("Cannot read file, " + file.toPath());
        }
    }


}
