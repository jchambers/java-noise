package com.eatthepath.noise.component;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

abstract class AbstractNoiseHashTest {

  protected abstract NoiseHash getHash();

  @Test
  void getName() {
    assertNotNull(getHash().getName());
  }

  @ParameterizedTest
  @MethodSource
  void messageDigest(final byte[] input) {
    final MessageDigest messageDigest = getHash().getMessageDigest();

    assertArrayEquals(messageDigest.digest(input), messageDigest.digest(input),
        "Calls to `digest` should reset the message digest");

    assertEquals(getHash().getHashLength(), messageDigest.digest(input).length);
  }

  private static List<byte[]> messageDigest() {
    final byte[] shortInput = new byte[4];
    final byte[] longInput = new byte[1024];

    ThreadLocalRandom.current().nextBytes(shortInput);
    ThreadLocalRandom.current().nextBytes(longInput);

    return List.of(shortInput, longInput);
  }

  @ParameterizedTest
  @MethodSource
  void hmac(final Key key, final byte[] input) throws InvalidKeyException {
    final Mac hmac = getHash().getHmac();

    hmac.init(key);
    final byte[] firstDigest = hmac.doFinal(input);

    hmac.init(key);
    final byte[] secondDigest = hmac.doFinal(input);

    assertArrayEquals(firstDigest, secondDigest);
    assertEquals(getHash().getHashLength(), firstDigest.length);
  }

  private static List<Arguments> hmac() {
    final byte[] shortKey = new byte[16];
    final byte[] longKey = new byte[256];
    final byte[] shortInput = new byte[4];
    final byte[] longInput = new byte[1024];

    ThreadLocalRandom.current().nextBytes(shortKey);
    ThreadLocalRandom.current().nextBytes(longKey);
    ThreadLocalRandom.current().nextBytes(shortInput);
    ThreadLocalRandom.current().nextBytes(longInput);

    return List.of(
        Arguments.of(new SecretKeySpec(shortKey, "RAW"), shortInput),
        Arguments.of(new SecretKeySpec(shortKey, "RAW"), longInput),
        Arguments.of(new SecretKeySpec(longKey, "RAW"), shortInput),
        Arguments.of(new SecretKeySpec(longKey, "RAW"), longInput));
  }
}