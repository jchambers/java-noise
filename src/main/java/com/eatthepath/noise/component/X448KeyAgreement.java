package com.eatthepath.noise.component;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.HexFormat;

class X448KeyAgreement extends AbstractXECKeyAgreement {

  private static final String ALGORITHM = "X448";
  private static final byte[] X509_PREFIX = HexFormat.of().parseHex("3042300506032b656f033900");

  public X448KeyAgreement() throws NoSuchAlgorithmException {
    super(KeyAgreement.getInstance(ALGORITHM), KeyPairGenerator.getInstance(ALGORITHM), KeyFactory.getInstance(ALGORITHM));
  }

  @Override
  public String getName() {
    return "448";
  }

  @Override
  public int getPublicKeyLength() {
    return 56;
  }

  @Override
  protected byte[] getX509Prefix() {
    return X509_PREFIX;
  }
}
