package com.eatthepath.noise.crypto;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class Blake2bMessageDigestSpiTest {

  @ParameterizedTest
  @MethodSource("blake2bTestVectors")
  void engineUpdateByteArrayDigest(final byte[] bytes, final byte[] key, final byte[] expectedHash) {
    final Blake2bMessageDigestSpi blake2bMessageDigestSpi = new Blake2bMessageDigestSpi(64, key);
    blake2bMessageDigestSpi.engineUpdate(bytes, 0, bytes.length);

    assertArrayEquals(expectedHash, blake2bMessageDigestSpi.engineDigest());
  }

  @ParameterizedTest
  @MethodSource("blake2bTestVectors")
  void engineUpdateSingleByteDigest(final byte[] bytes, final byte[] key, final byte[] expectedHash) {
    final Blake2bMessageDigestSpi blake2bMessageDigestSpi = new Blake2bMessageDigestSpi(64, key);

    for (final byte b : bytes) {
      blake2bMessageDigestSpi.engineUpdate(b);
    }

    assertArrayEquals(expectedHash, blake2bMessageDigestSpi.engineDigest());
  }

  private static Stream<Arguments> blake2bTestVectors() throws IOException {
    return Blake2TestUtil.loadBlake2TestVectorsForHash("blake2b")
        .map(blake2bTestVector ->
            Arguments.of(blake2bTestVector.inputBytes(), blake2bTestVector.key(), blake2bTestVector.expectedHash()));
  }
}