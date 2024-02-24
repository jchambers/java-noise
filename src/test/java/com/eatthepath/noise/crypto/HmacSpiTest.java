package com.eatthepath.noise.crypto;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.TestAbortedException;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class HmacSpiTest {

  private static class HmacMd5Spi extends HmacSpi {

    public HmacMd5Spi() throws NoSuchAlgorithmException {
      super(MessageDigest.getInstance("MD5"), 64);
    }

    @Override
    protected int engineGetMacLength() {
      return 16;
    }
  }

  @ParameterizedTest
  @MethodSource
  void hmacMd5(final Key key, final byte[] input, final byte[] expectedDigest)
      throws InvalidAlgorithmParameterException, InvalidKeyException {

    final HmacMd5Spi hmacMd5;

    try {
      hmacMd5 = new HmacMd5Spi();
    } catch (final NoSuchAlgorithmException e) {
      throw new TestAbortedException("MD5 not supported");
    }

    hmacMd5.engineInit(key, null);
    hmacMd5.engineUpdate(input, 0, input.length);

    assertArrayEquals(expectedDigest, hmacMd5.engineDoFinal());
  }

  private static List<Arguments> hmacMd5() {
    // Test vectors via https://www.ietf.org/rfc/rfc2104.txt
    return List.of(
        Arguments.of(
            new SecretKeySpec(HexFormat.of().parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), "RAW"),
            "Hi There".getBytes(StandardCharsets.UTF_8),
            HexFormat.of().parseHex("9294727a3638bb1c13f48ef8158bfc9d")),

        Arguments.of(
            new SecretKeySpec("Jefe".getBytes(StandardCharsets.UTF_8), "RAW"),
            "what do ya want for nothing?".getBytes(StandardCharsets.UTF_8),
            HexFormat.of().parseHex("750c783e6ab0b503eaa86e310a5db738")),

        Arguments.of(
            new SecretKeySpec(HexFormat.of().parseHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "RAW"),
            HexFormat.of().parseHex("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"),
            HexFormat.of().parseHex("56be34521d144c88dbb8c733f0e8b3f6"))
    );
  }
}
