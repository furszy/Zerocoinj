// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj;

import com.zerocoinj.base.BaseZerocoinTest;
import com.zerocoinj.core.ZeroCoin;
import com.zerocoinj.core.exceptions.InvalidSerialException;
import org.junit.Test;
import org.pivxj.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

public class NetworkTest extends BaseZerocoinTest {

    private static final Logger log = LoggerFactory.getLogger(NetworkTest.class);

    String json;

    {

        // TODO: el serial de acá está mal.. quizás le pifié y el 'r' es el serial..
        json = "{" +
                "    \"d\": 1," +
                "    \"p\": \"4694785a45813eb2610e5ece629628aab4be1ae6e00bc04e8209c0d321b33041afebded8e90961a61330d236ac4a7b7de993c1826698d9d03dedb7f543abffa466bf8b995eac71eb043fbdb143b78092b016c7c8ff8e1a31d1d0529bd012c4ce59962b75d1300e79a8cb27b06473ebee47fc130f672aeee2fab425c29ac9fdcb\"," +
                "    \"s\": \"348a52b4200ec991bf2b53b503d9654eb8af3dd8599c83ffc70dced1adf776ea\"," +
                "    \"r\": \"f629e615f57871d6fb4f365c0d7314a0044fcfa8bae05693b06f5bc6b552aa9a\"," +
                "    \"t\": \"dd2239f510f55a5eac4835c79d952a6c4df8631e73af7f42d03fb72be8d559a6\"," +
                "    \"h\": 1245475," +
                "    \"u\": false," +
                "    \"v\": 2," +
                "    \"k\": \"YPYy7sKemafRVQczxrgj4wFUfFEH6oiMqUSUi3veS2hmHdqPhqHR\"" +
                "  }";

    }

    @Test
    public void adjustedSerial(){
        try {
            ECKey ecKey = DumpedPrivateKey.fromBase58(params, "YRxcRrbqGZuB7rABPPTFEUs88JVBBwNYYtVe9p7XT6We7ifh75ZP").getKey();
            BigInteger serial = ZeroCoin.generateSerial(ecKey);
            BigInteger adjustedSerial = ZeroCoin.getAdjustedSerial(serial);
        } catch (InvalidSerialException e) {
            throw new RuntimeException(e);
        }
    }

}
