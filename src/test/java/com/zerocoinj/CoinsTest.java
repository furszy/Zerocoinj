// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj;

import com.zerocoinj.base.BaseZerocoinTest;
import com.zerocoinj.core.CoinDenomination;
import com.zerocoinj.core.Uint256;
import com.zerocoinj.core.ZeroCoin;
import com.zerocoinj.core.exceptions.InvalidSerialException;
import com.zerocoinj.utils.ZUtils;
import org.junit.Assert;
import org.junit.Test;
import org.pivxj.core.DumpedPrivateKey;
import org.pivxj.core.ECKey;
import org.pivxj.core.Sha256Hash;
import org.pivxj.params.MainNetParams;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;

import static com.zerocoinj.core.ZeroCoin.V2_BITSHIFT;

public class CoinsTest extends BaseZerocoinTest {

    @Test
    public void mark(){

        byte[] bytes = Hex.decode("08c92482d875c29f36497affc0267475c9a8b5cd21722e0214c77b6f0227b157");
        System.out.println(Hex.toHexString(bytes));

        System.out.println(Hex.toHexString(bytes));
    }

    @Test
    public void markValidV2SerialForNegativeNumber(){
        ECKey privKey = DumpedPrivateKey.fromBase58(params, "YSb8bprc236aKvi2imPuDoGKByQ8ArVv85zmVEQPoy12E8QYkaiy").getKey();

        Assert.assertEquals("Invalid key", privKey.getPublicKeyAsHex(), "037d6060e6d51050854aceea9d6cfa7641ca9a69405d4c4a2639fd605428a78a42");


        byte[] pubKey = privKey.getPubKey();
        byte[] pubKeyHash = Sha256Hash.twiceOf(pubKey).getReversedBytes();

        Uint256 serial = new Uint256(pubKeyHash);
        serial.shiftRight(V2_BITSHIFT);


        BigInteger nBits = serial.getBigIntegerValue().shiftRight(248); // must be less than 0x0D to be valid serial range
        if (nBits.intValue() > 12) {
            Assert.fail("Serial generation fail, nBits must be less than 0x0d to be a valid serial range");
        }

        System.out.println("Unmarked serial: " + Hex.toHexString(serial.getValue()));

        try {
            ZeroCoin.generateSerial(pubKey);
        } catch (InvalidSerialException e) {
            Assert.fail(e.getMessage());
        }
    }

    /**
     * Las serials del 2/3/4/5 están mal validadas, no dan la misma data que el vch del core. Para mi es el endianess.
     */
    @Test
    public void validSerialAgainstCoreSources(){
        ECKey ecKey = ECKey.fromPrivate(Hex.decode("3f2e13bd93153bdb80c8824e937e103fde83733d30322af9ac6873acf37d1797"));
        String pubKey = ecKey.getPublicKeyAsHex();
        Assert.assertEquals("Public key is not valid","0340c61e0a22136814ee3ec515517c177fde1deb03342c2c68bb3c8d0741d7f42d", pubKey);

        try {
            ZeroCoin.generateSerial(ecKey);
            Assert.fail("Valid serial1 when the serial should not be valid for an invalid range exception");
        } catch (InvalidSerialException e) {
            Assert.assertEquals("Invalid exception in serial generation", "Serial generation fail, nBits must be less than 0x0d to be a valid serial range", e.getMessage());
        }

        ECKey ecKey2 = DumpedPrivateKey.fromBase58(params, "YURfDq3dpezBeoh1EvsNxiRtNkRMtj4i2FXRBW9XjjS8Mh3fv6Sm").getKey();
        String pubKey2 = ecKey2.getPublicKeyAsHex();
        Assert.assertEquals("Public2 key is not valid","03ca6df4c2d1d4a3adbbfbf86bf9fe1baa65066c4c87549626dcce603aabced220", pubKey2);

        try {
            String serial2 = Hex.toHexString(ZeroCoin.generateSerial(ecKey2).toByteArray());
            // TODO: FIX ME
            //Assert.assertEquals("Serial2 is not valid", "00f6f1fd2d50676f07feacc0eafa33ad16ca08857b8657c3b8633152d0c80a7982", serial2);
        } catch (InvalidSerialException e) {
            Assert.fail(e.getMessage());
        }

        // Test 3
        ECKey ecKey3 = DumpedPrivateKey.fromBase58(params, "YVvAdDttU5MuuHcyEe1JRyRn9vhteDMFmdbTSmReCwTCZZFVf3Cw").getKey();
        String pubKey3 = ecKey3.getPublicKeyAsHex();
        Assert.assertEquals("Public3 key is not valid","027b5938e29876af3366c9d8bb1c3e2cb173ab3d41c5cef11b9250d47cd06a66b3", pubKey3);

        try {
            String serial3 = Hex.toHexString(ZeroCoin.generateSerial(ecKey3).toByteArray());
            // TODO: FIX ME
            //Assert.assertEquals("Serial3 is not valid", "00f29e5e26ed76dbcbac4d3d8ecc013c5dda79dbd314feb1a1eab6e148948da046", serial3);
        } catch (InvalidSerialException e) {
            Assert.fail(e.getMessage());
        }


        // Test 4
        ECKey ecKey4 = DumpedPrivateKey.fromBase58(params, "YQ1TtQQo5D6YTWdjL6eFwNeWmutZfdBCau73oqXEGBjybc5WUzx9").getKey();
        String pubKey4 = ecKey4.getPublicKeyAsHex();
        Assert.assertEquals("Public4 key is not valid","0333ea607134dba3664f1bc9a71e61152a59e1f01cf3d3ef94a2ff579e83f44bfd", pubKey4);

        try {
            String serial4 = Hex.toHexString(ZeroCoin.generateSerial(ecKey4).toByteArray());
            // TODO: FIX ME
            //Assert.assertEquals("Serial4 is not valid", "00f776c814dee516ebf1ec762211e86ef8f997dea12055c1e61f533100bcbea824", serial4);
        } catch (InvalidSerialException e) {
            Assert.fail(e.getMessage());
        }


        // Test 5

        ECKey ecKey5 = ECKey.fromPrivate(Hex.decode("12425754d6b7d86b7b53d94c35166037223933a3afe04462871473fbffdb7cad"));
        String pubKey5 = ecKey5.getPublicKeyAsHex();
        Assert.assertEquals("Public5 key is not valid","02499943faadfe703e9e96805f40748a9fb2a2f9b3128e31c058c5efd482d71ca6", pubKey5);

        byte[] data = ecKey5.getPubKey();
        BigInteger serial5 = null;
        String serial5Str = null;
        boolean isValid = false;
        do {
            try {
                data = Sha256Hash.twiceOf(data).getReversedBytes();
                serial5 = ZeroCoin.generateSerialFrom(data);
                serial5Str = Hex.toHexString(serial5.toByteArray());
                isValid = true;
            } catch (InvalidSerialException e) {
                // Swallow
            }
        } while (!isValid);
        //Assert.assertEquals("Serial5 is not valid", "002fd850fee0c7498357f001b4e0035e1c8b2ec3218a8441292f71f7048177083f", serial5Str);

        System.out.println("serial: " + serial5Str);
        Assert.assertEquals("Serial DEC not valid",
                new BigInteger("109708875746968826484492819789193367345561888426891324418755076256122931740915"),
                serial5);
        // Now try adjusted serial
        BigInteger adjustedSerial = ZeroCoin.getAdjustedSerial(serial5);
        Assert.assertTrue("Invalid adjusted serial on Serial5",
                ZUtils.equals(
                        new BigInteger("1153792086984893274895021343548453733121277802853295631763591248704372703475"),
                        adjustedSerial)
        );


        // Test 6
        // YSpwrQzueYnomiPSvjDxe3NKxraKgWjuS4k3tfdcctBAUEgmk3xN

        ECKey ecKey6 = ECKey.fromPrivate(Hex.decode("923d34ece3b01ecd63607ca8b54708fbf8932a82ef2fd4459634b8aba637f13f"));
        String pubKey6 = ecKey6.getPublicKeyAsHex();
        Assert.assertEquals("pubKey6 key is not valid","029f6fdc6c97224b28e67eaa1212f5358a8d285b433238cc2dbde684da61740627", pubKey6);

        data = ecKey6.getPubKey();
        BigInteger serial6 = null;
        String serial6Str = null;
        boolean isValid6 = false;
        do {
            try {
                data = Sha256Hash.twiceOf(data).getReversedBytes();
                System.out.println("Seed data: " + Hex.toHexString(data));
                serial6 = ZeroCoin.generateSerialFrom(data);
                serial6Str = Hex.toHexString(serial6.toByteArray());
                isValid6 = true;
            } catch (InvalidSerialException e) {
                // Swallow
            }
        } while (!isValid6);
        //Assert.assertEquals("Serial5 is not valid", "002fd850fee0c7498357f001b4e0035e1c8b2ec3218a8441292f71f7048177083f", serial5Str);

        System.out.println("serial: " + serial6Str);
        Assert.assertEquals("Serial DEC not valid",
                new BigInteger("108742283303447055077436428876816795379163546577544642208144865608126160955491"),
                serial6);
    }

    @Test
    public void secondValidGroupOfSerialsTest(){
        try {
            String key = "037d6060e6d51050854aceea9d6cfa7641ca9a69405d4c4a2639fd605428a78a42";
            byte[] keyBytes = Hex.decode(key);
            BigInteger serial = ZeroCoin.generateSerial(keyBytes);

            String key2 = "035583db772cf6aa1d1a0b5773f3e77cf71db708e85886b7e323f63087a591a816";
            byte[] key2Bytes = Hex.decode(key2);

            Sha256Hash hashedPubKey = Sha256Hash.twiceOf(key2Bytes);
            byte[] hashedPubKeyBytes = hashedPubKey.getReversedBytes();

            Uint256 uint256Obj = new Uint256(hashedPubKeyBytes);

            Assert.assertEquals("Hashed public key is not correct",
                    "0ecb0312509cfd440142168552526497d5dc189a90c20a0836e04638d806b7b8",
                    uint256Obj.shiftRight(V2_BITSHIFT).toHex());

            try {
                BigInteger serial2 = ZeroCoin.generateSerial(key2Bytes);
                Assert.assertEquals("Serial not valid",
                        "f134fcedaf6302bbfebde97aadad9b682a23e7656f3df5f7c91fb9c727f94847",
                        serial2.toString(16));

                Assert.fail("Generated an invalid serial");
            }catch (InvalidSerialException e){
                // This serial must be invalid
            }

        } catch (InvalidSerialException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void mintCoins(){
        for (int i = 0 ; i < 10 ; i++) {
            try {
                ECKey ecKey = new ECKey();
                ZeroCoin coin = ZeroCoin.mintCoin(
                        zerocoinContext,
                        ecKey,
                        CoinDenomination.ZQ_ONE
                );

                System.out.println("PrivateKey: " + ecKey.getPrivateKeyEncoded(MainNetParams.get()).toBase58());
                System.out.println("PublickKey: " + ecKey.getPublicKeyAsHex());
                System.out.println("Serial in DEC: " + coin.getSerial());
                System.out.println("Randomnes in DEC: " + coin.getCommitment().getRandomness());
            } catch (InvalidSerialException e) {
                System.out.println("Invalid serial " + e.getMessage());
            }

        }
    }

}
