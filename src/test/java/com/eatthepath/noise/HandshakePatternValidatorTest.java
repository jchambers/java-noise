package com.eatthepath.noise;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class HandshakePatternValidatorTest {

  @ParameterizedTest
  @ValueSource(strings = {
      "N",
      "K",
      "X",
      "NN",
      "KN",
      "NK",
      "KK",
      "NX",
      "KX",
      "XN",
      "IN",
      "XK",
      "IK",
      "XX",
      "IX",
      "NK1",
      "NX1",
      "X1N",
      "X1K",
      "XK1",
      "X1K1",
      "X1X",
      "XX1",
      "X1X1",
      "K1N",
      "K1K",
      "KK1",
      "K1K1",
      "K1X",
      "KX1",
      "K1X1",
      "I1N",
      "I1K",
      "IK1",
      "I1K1",
      "I1X",
      "IX1",
      "I1X1",
      "Npsk0",
      "Kpsk0",
      "Xpsk1",
      "NNpsk0",
      "NNpsk2",
      "NKpsk0",
      "NKpsk2",
      "NXpsk2",
      "XNpsk3",
      "XKpsk3",
      "XXpsk3",
      "KNpsk0",
      "KNpsk2",
      "KKpsk0",
      "KKpsk2",
      "KXpsk2",
      "INpsk1",
      "INpsk2",
      "IKpsk1",
      "IKpsk2",
      "IXpsk2"
  })
  void validateKnownPatterns(final String patternName) {
    assertDoesNotThrow(() -> HandshakePatternValidator.validate(HandshakePattern.getInstance(patternName)));
  }
}
