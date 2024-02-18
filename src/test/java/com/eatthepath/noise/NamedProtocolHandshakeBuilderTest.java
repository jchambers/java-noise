package com.eatthepath.noise;

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class NamedProtocolHandshakeBuilderTest {

  @Test
  void build() throws NoSuchAlgorithmException, NoSuchPatternException {
    final String noiseProtocolName = "Noise_NN_25519_AESGCM_SHA256";

    final NoiseHandshake noiseHandshake =
        new NamedProtocolHandshakeBuilder(noiseProtocolName, NoiseHandshake.Role.INITIATOR).build();

    assertEquals(noiseProtocolName, noiseHandshake.getNoiseProtocolName());
  }

  @Test
  void buildMissingRemoteStaticKey() throws NoSuchAlgorithmException, NoSuchPatternException {
    final String noiseProtocolName = "Noise_KN_25519_AESGCM_SHA256";

    final NamedProtocolHandshakeBuilder builder =
        new NamedProtocolHandshakeBuilder(noiseProtocolName, NoiseHandshake.Role.RESPONDER);

    assertThrows(IllegalStateException.class, builder::build);

    builder.setRemoteStaticPublicKey(KeyPairGenerator.getInstance("X25519").generateKeyPair().getPublic());

    assertEquals(noiseProtocolName, builder.build().getNoiseProtocolName());
  }

  @Test
  void buildMissingLocalKeyPair() throws NoSuchAlgorithmException, NoSuchPatternException {
    final String noiseProtocolName = "Noise_NX_25519_AESGCM_SHA256";

    final NamedProtocolHandshakeBuilder builder =
        new NamedProtocolHandshakeBuilder(noiseProtocolName, NoiseHandshake.Role.RESPONDER);

    assertThrows(IllegalStateException.class, builder::build);

    builder.setLocalStaticKeyPair(KeyPairGenerator.getInstance("X25519").generateKeyPair());

    assertEquals(noiseProtocolName, builder.build().getNoiseProtocolName());
  }
}