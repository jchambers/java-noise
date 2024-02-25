package com.eatthepath.noise.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.DigestException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Blake2s256MessageDigestTest {

  @Test
  void getDigestLength() {
    assertEquals(32, new Blake2s256MessageDigest().getDigestLength());
  }

  @ParameterizedTest
  @MethodSource("blake2sTestVectors")
  void digest(final byte[] bytes, final byte[] expectedDigest) {
    assertArrayEquals(expectedDigest, new Blake2s256MessageDigest().digest(bytes));
  }

  @ParameterizedTest
  @MethodSource("blake2sTestVectors")
  void digestOffsetLength(final byte[] bytes, final byte[] expectedDigest) throws DigestException {
    final Blake2s256MessageDigest messageDigest = new Blake2s256MessageDigest();
    messageDigest.update(bytes);

    final byte[] digest = new byte[messageDigest.getDigestLength()];
    messageDigest.digest(digest, 0, messageDigest.getDigestLength());

    assertArrayEquals(expectedDigest, digest);
  }

  private static Stream<Arguments> blake2sTestVectors() throws IOException {
    return Blake2TestUtil.loadBlake2TestVectorsForHash("blake2s")
        .filter(blake2TestVector -> blake2TestVector.key() == null || blake2TestVector.key().length == 0)
        .map(blake2sTestVector ->
            Arguments.of(blake2sTestVector.inputBytes(), blake2sTestVector.expectedHash()));
  }
}
