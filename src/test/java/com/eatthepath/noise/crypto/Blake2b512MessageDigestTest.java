package com.eatthepath.noise.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.DigestException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class Blake2b512MessageDigestTest {

  @Test
  void getDigestLength() {
    assertEquals(64, new Blake2b512MessageDigest().getDigestLength());
  }

  @ParameterizedTest
  @MethodSource("blake2bTestVectors")
  void digest(final byte[] bytes, final byte[] expectedDigest) {
    assertArrayEquals(expectedDigest, new Blake2b512MessageDigest().digest(bytes));
  }

  @ParameterizedTest
  @MethodSource("blake2bTestVectors")
  void digestOffsetLength(final byte[] bytes, final byte[] expectedDigest) throws DigestException {
    final Blake2b512MessageDigest messageDigest = new Blake2b512MessageDigest();
    messageDigest.update(bytes);

    final byte[] digest = new byte[messageDigest.getDigestLength()];
    messageDigest.digest(digest, 0, messageDigest.getDigestLength());

    assertArrayEquals(expectedDigest, digest);
  }

  private static Stream<Arguments> blake2bTestVectors() throws IOException {
    return Blake2TestUtil.loadBlake2TestVectorsForHash("blake2b")
        .filter(blake2TestVector -> blake2TestVector.key() == null || blake2TestVector.key().length == 0)
        .map(blake2bTestVector ->
            Arguments.of(blake2bTestVector.inputBytes(), blake2bTestVector.expectedHash()));
  }
}
