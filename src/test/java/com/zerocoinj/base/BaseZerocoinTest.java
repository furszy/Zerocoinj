// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.base;

import com.zerocoinj.JniBridge;
import com.zerocoinj.core.CoinDenomination;
import com.zerocoinj.core.ZeroCoin;
import com.zerocoinj.core.context.ZerocoinContext;
import com.zerocoinj.core.exceptions.InvalidSerialException;
import org.junit.Assert;
import org.pivxj.core.Context;
import org.pivxj.core.ECKey;
import org.pivxj.core.NetworkParameters;
import org.pivxj.params.MainNetParams;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class BaseZerocoinTest {

    protected static ZerocoinContext zerocoinContext = new ZerocoinContext(new JniBridge());

    protected static NetworkParameters params = MainNetParams.get();

    {
        Context.getOrCreate(params);
    }


    protected static List<ZeroCoin> generateCoins(ZerocoinContext zerocoinContext, int number){
        List<ZeroCoin> list = new ArrayList<>();

        for (int i = 0; i < number; i++) {
            try {
                ECKey ecKey = new ECKey();
                ZeroCoin zeroCoin = ZeroCoin.mintCoin(zerocoinContext, ecKey, CoinDenomination.ZQ_ONE);
                System.out.println(
                        String.format(
                                "Minted coin number %d: \n keypair: %s \n commitment %s ",
                                i, ecKey.toStringWithPrivate(params), zeroCoin
                        )
                );
                list.add(zeroCoin);
            } catch (InvalidSerialException e) {
                // PubKey doesn't have the size that we are looking for..
                i--;
                continue;
            }
        }
        return list;
    }

    protected byte[] readFile(String path){
        File file = new File(path);//url.getPath());
        if (!file.exists())
            Assert.fail("File not exists, " + path);
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new RuntimeException("Cannot read file, " + path);
        }
    }

}
