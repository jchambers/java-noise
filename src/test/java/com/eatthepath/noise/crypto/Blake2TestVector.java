package com.eatthepath.noise.crypto;

import com.eatthepath.noise.util.HexDeserializer;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

record Blake2TestVector(String hash,

                        @JsonProperty("in")
                        @JsonDeserialize(using = HexDeserializer.class)
                        byte[] inputBytes,

                        @JsonDeserialize(using = HexDeserializer.class)
                        byte[] key,

                        @JsonProperty("out")
                        @JsonDeserialize(using = HexDeserializer.class)
                        byte[] expectedHash) {
}
