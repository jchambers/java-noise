package com.eatthepath.noise.component;

import org.junit.jupiter.api.Test;

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
}