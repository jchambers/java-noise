package com.eatthepath.noise.component;

import java.security.NoSuchAlgorithmException;

public interface ProtocolNameResolver {

  NoiseKeyAgreement getKeyAgreement(String name) throws NoSuchAlgorithmException;

  NoiseCipher getCipher(String name) throws NoSuchAlgorithmException;

  NoiseHash getHash(String name) throws NoSuchAlgorithmException;
}
