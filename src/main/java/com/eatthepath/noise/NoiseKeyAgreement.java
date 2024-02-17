package com.eatthepath.noise;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public interface NoiseKeyAgreement {

  String getName();

  KeyPair generateKeyPair();

  byte[] generateSecret(PrivateKey privateKey, PublicKey publicKey) throws InvalidKeyException;

  int getPublicKeyLength();

  byte[] serializePublicKey(PublicKey publicKey);

  PublicKey deserializePublicKey(byte[] publicKeyBytes) throws InvalidKeySpecException;
}
