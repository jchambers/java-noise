package com.eatthepath.noise;

import javax.annotation.Nullable;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class NamedProtocolHandshakeBuilder {

  private final HandshakePattern handshakePattern;
  private final NoiseKeyAgreement keyAgreement;
  private final NoiseCipher cipher;
  private final NoiseHash hash;

  private final NoiseHandshake.Role role;

  @Nullable private KeyPair localEphemeralKeyPair;
  @Nullable private KeyPair localStaticKeyPair;
  @Nullable private PublicKey remoteEphemeralPublicKey;
  @Nullable private PublicKey remoteStaticPublicKey;

  @Nullable private byte[] prologue;

  public NamedProtocolHandshakeBuilder(final String noiseProtocolName, final NoiseHandshake.Role role) throws NoSuchAlgorithmException, NoSuchPatternException {
    this(noiseProtocolName, role, new DefaultProtocolNameResolver());
  }

  public NamedProtocolHandshakeBuilder(final String noiseProtocolName, final NoiseHandshake.Role role, final ProtocolNameResolver protocolNameResolver) throws NoSuchAlgorithmException, NoSuchPatternException {
    final String[] components = noiseProtocolName.split("_");

    if (components.length != 5) {
      throw new IllegalArgumentException("Invalid Noise protocol name; did not contain five sections");
    }

    if (!"Noise".equals(components[0])) {
      throw new IllegalArgumentException("Noise protocol names must begin with \"Noise_\"");
    }

    this.handshakePattern = HandshakePattern.getInstance(components[1]);
    this.keyAgreement = protocolNameResolver.getKeyAgreement(components[2]);
    this.cipher = protocolNameResolver.getCipher(components[3]);
    this.hash = protocolNameResolver.getHash(components[4]);

    this.role = role;
  }

  public NamedProtocolHandshakeBuilder setLocalEphemeralKeyPair(@Nullable final KeyPair localEphemeralKeyPair) {
    this.localEphemeralKeyPair = localEphemeralKeyPair;
    return this;
  }

  public NamedProtocolHandshakeBuilder setLocalStaticKeyPair(@Nullable final KeyPair localStaticKeyPair) {
    this.localStaticKeyPair = localStaticKeyPair;
    return this;
  }

  public NamedProtocolHandshakeBuilder setRemoteEphemeralPublicKey(@Nullable final PublicKey remoteEphemeralPublicKey) {
    this.remoteEphemeralPublicKey = remoteEphemeralPublicKey;
    return this;
  }

  public NamedProtocolHandshakeBuilder setRemoteStaticPublicKey(@Nullable final PublicKey remoteStaticPublicKey) {
    this.remoteStaticPublicKey = remoteStaticPublicKey;
    return this;
  }

  public NamedProtocolHandshakeBuilder setPrologue(@Nullable final byte[] prologue) {
    this.prologue = prologue;
    return this;
  }

  public NoiseHandshake build() {
    if (handshakePattern.requiresRemoteStaticPublicKey(role) && remoteStaticPublicKey == null) {
      throw new IllegalStateException(handshakePattern.name() + " handshake pattern requires a remote static public key for the " + role + " role");
    }

    if (handshakePattern.requiresLocalStaticKeyPair(role) && localStaticKeyPair == null) {
      throw new IllegalStateException(handshakePattern.name() + " handshake pattern requires a local static key pair for the " + role + " role");
    }

    // TODO Check key compatibility if applicable

    return new NoiseHandshake(handshakePattern,
        role,
        cipher,
        hash,
        keyAgreement,
        prologue,
        localStaticKeyPair,
        localEphemeralKeyPair,
        remoteStaticPublicKey,
        remoteEphemeralPublicKey);
  }
}
