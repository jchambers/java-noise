package com.eatthepath.noise.component;

import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class X25519KeyAgreementTest extends AbstractNoiseKeyAgreementTest {

  @Override
  protected AbstractXECKeyAgreement getKeyAgreement() throws NoSuchAlgorithmException {
    return new X25519KeyAgreement();
  }

  @Test
  void getPublicKeyLength() throws NoSuchAlgorithmException {
    assertEquals(32, getKeyAgreement().getPublicKeyLength());
  }

  @Test
  void checkPublicKeyMismatched() {
    assertThrows(InvalidKeyException.class, () ->
        getKeyAgreement().checkPublicKey(KeyPairGenerator.getInstance("X448").generateKeyPair().getPublic()));
  }

  @Test
  void checkKeyPairMismatched() {
    assertThrows(InvalidKeyException.class, () ->
        getKeyAgreement().checkKeyPair(KeyPairGenerator.getInstance("X448").generateKeyPair()));
  }
}