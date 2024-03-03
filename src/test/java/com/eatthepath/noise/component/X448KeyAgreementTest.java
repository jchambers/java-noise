package com.eatthepath.noise.component;

import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class X448KeyAgreementTest extends AbstractNoiseKeyAgreementTest {

  @Override
  protected AbstractXECKeyAgreement getKeyAgreement() throws NoSuchAlgorithmException {
    return new X448KeyAgreement();
  }

  @Test
  void getPublicKeyLength() throws NoSuchAlgorithmException {
    assertEquals(448 / 8, getKeyAgreement().getPublicKeyLength());
  }

  @Test
  void checkPublicKeyMismatched() {
    assertThrows(InvalidKeyException.class, () ->
        getKeyAgreement().checkPublicKey(KeyPairGenerator.getInstance("X25519").generateKeyPair().getPublic()));
  }

  @Test
  void checkKeyPairMismatched() {
    assertThrows(InvalidKeyException.class, () ->
        getKeyAgreement().checkKeyPair(KeyPairGenerator.getInstance("X25519").generateKeyPair()));
  }
}