package com.eatthepath.noise.crypto;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class Blake2sMessageDigestSpiTest {

  @ParameterizedTest
  @MethodSource("blake2sTestVectors")
  void engineUpdateByteArrayDigest(final byte[] bytes, final byte[] key, final byte[] expectedHash) {
    final Blake2sMessageDigestSpi blake2sMessageDigestSpi = new Blake2sMessageDigestSpi(32, key);
    blake2sMessageDigestSpi.engineUpdate(bytes, 0, bytes.length);

    assertArrayEquals(expectedHash, blake2sMessageDigestSpi.engineDigest());
  }

  @ParameterizedTest
  @MethodSource("blake2sTestVectors")
  void engineUpdateSingleByteDigest(final byte[] bytes, final byte[] key, final byte[] expectedHash) {
    final Blake2sMessageDigestSpi blake2sMessageDigestSpi = new Blake2sMessageDigestSpi(32, key);

    for (final byte b : bytes) {
      blake2sMessageDigestSpi.engineUpdate(b);
    }

    assertArrayEquals(expectedHash, blake2sMessageDigestSpi.engineDigest());
  }

  private static Stream<Arguments> blake2sTestVectors() throws IOException {
    return Blake2TestUtil.loadBlake2TestVectorsForHash("blake2s")
        .map(blake2sTestVector ->
            Arguments.of(blake2sTestVector.inputBytes(), blake2sTestVector.key(), blake2sTestVector.expectedHash()));
  }
}