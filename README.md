# java-noise

java-noise is a Java implementation of the [Noise Protocol Framework](https://noiseprotocol.org/), which describes itself as:

> …a framework for building crypto protocols. Noise protocols support mutual and optional authentication, identity hiding, forward secrecy, zero round-trip encryption, and other advanced features.

java-noise supports all handshake patterns, handshake pattern modifiers, and cryptographic algorithms enumerated in revision 34 of the [Noise Protocol Framework specification](https://noiseprotocol.org/noise.html). Some cryptographic algorithms depend on the presence of a security provider that provides an implementation of the named algorithm. In particular:

- The "25519" key agreement algorithm requires that the JVM have a security provider that supports the "X25519" `KeyAgreement` and `KeyPairGenerator` algorithms
- The "448" key agreement algorithm requires that the JVM have a security provider that supports the "X448" `KeyAgreement` and `KeyPairGenerator` algorithms
- The "ChaChaPoly" cipher algorithm requires that the JVM have a security provider that supports the "ChaCha20-Poly1305" `Cipher` algorithm
- The "SHA512" hash algorithm requires that the JVM have a security provider that supports the "SHA-512" `MessageDigest` algorithm and the "HmacSHA512" `Mac` algorithm

All other algorithms named in the Noise Protocol Framework specification are supported unconditionally.

## Reference

- [java-noise API documentation (Javadoc)](https://jchambers.github.io/java-noise/apidocs/latest/)
- [The Noise Protocol Framework specification](https://noiseprotocol.org/noise.html)

## Handshakes

A Noise protocol begins with a handshake in which two parties (an initiator and a responder) exchange handshake messages that contain key material and optional payloads to negotiate a shared secret key and establish an ongoing session for Noise transport messages. Noise handshakes are described by ["handshake patterns"](https://noiseprotocol.org/noise.html#handshake-patterns), which prescribe the handshake messages exchanged between the initiator and responder. In java-noise, Noise handshakes are managed by NoiseHandshake instances.

NoiseHandshake instances can be constructed using either a NoiseHandshakeBuilder, which provides static initializers for common Noise handshake patterns, or a NamedProtocolHandshakeBuilder, which allows for arbitrary handshake pattern names, but only offers runtime checks (as opposed to compile-time checks) that appropriate key material has been provided before building a NoiseHandshake instance.

### Interactive patterns

In the most common case, Noise handshakes implement a interactive pattern in which both parties will send and receive messages to one another once the handshake is complete. As an example, the NN interactive handshake pattern is defined as:

```
NN:
  -> e
  <- e, ee
```

The parties in an NN handshake exchange messages until all required messages have been exchanged, then the handshake instances yield interactive transport instances:

```java
final NoiseHandshake initiatorHandshake = NoiseHandshakeBuilder.forNNInitiator()
    .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
    .build();

final NoiseHandshake responderHandshake = NoiseHandshakeBuilder.forNNResponder()
    .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
    .build();

// -> e (with an empty payload)
final byte[] initiatorEMessage = initiatorHandshake.writeMessage((byte[]) null);
responderHandshake.readMessage(initiatorEMessage);

// <- e, ee (with an empty payload)
final byte[] responderEEeMessage = responderHandshake.writeMessage((byte[]) null);
initiatorHandshake.readMessage(responderEEeMessage);

assert initiatorHandshake.isDone();
assert responderHandshake.isDone();

final NoiseTransport initiatorTransport = initiatorHandshake.toTransport();
final NoiseTransport responderTransport = responderHandshake.toTransport();
```

### One-way patterns

Noise handshakes may also use one-way patterns. As the Noise Protocol Framework specification notes:

> These patterns could be used to encrypt files, database records, or other non-interactive data streams.

One-way handshakes exchange handshake messages in the same way as interactive handshakes, but instead of producing interactive NoiseTransport instances, one-way handshakes produce a one-way NoiseTransportWriter for initiators or NoiseTransportReader for responders. As an example, the N handshake pattern is defined as:

```
N:
  <- s
  ...
  -> e, es
```

The parties in an N handshake exchange messages as usual, then the handshake instances yield one-way transport instances:

```java
final NoiseHandshake initiatorHandshake = NoiseHandshakeBuilder.forNInitiator(responderStaticPublicKey)
    .setComponentsFromProtocolName("Noise_N_25519_AESGCM_SHA256")
    .build();

final NoiseHandshake responderHandshake = NoiseHandshakeBuilder.forNResponder(responderStaticKeyPair)
    .setComponentsFromProtocolName("Noise_N_25519_AESGCM_SHA256")
    .build();

// -> e, es (with an empty payload)
final byte[] initiatorEphemeralKeyMessage = initiatorHandshake.writeMessage((byte[]) null);
responderHandshake.readMessage(initiatorEphemeralKeyMessage);

assert initiatorHandshake.isDone();
assert responderHandshake.isDone();

final NoiseTransportWriter transportWriter = initiatorHandshake.toTransportWriter();
final NoiseTransportReader transportReader = responderHandshake.toTransportReader();
```

### Fallback patterns

Noise handshakes can "fall back" to another pattern to handle certain kinds of errors. As an example, the [Noise Pipes](https://noiseprotocol.org/noise.html#noise-pipes) compound protocol expects that initiators will usually have the responder's static public key available from a previous "full" (XX) handshake, and can use an abbreviated (IK) handshake pattern with that static key set via a pre-handshake message. If the responder can't decrypt a message from the initiator, though, it might conclude that the initiator has a stale copy of its public key and can fall back to a "full" (XXfallback) handshake.

The IK handshake pattern is defined as:

```
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

…and the XXfallback pattern is defined as:

```
XXfallback:
  -> e
  ...
  <- e, ee, s, es
  -> s, se
```

As an example, consider a scenario where the initiator of an IK handshake has a "stale" static key for the responder:

```java
final NoiseHandshake ikInitiatorHandshake =
    NoiseHandshakeBuilder.forIKInitiator(initiatorStaticKeyPair, staleRemoteStaticPublicKey)
        .setComponentsFromProtocolName("Noise_IK_25519_AESGCM_SHA256")
        .build();

final NoiseHandshake ikResponderHandshake =
    NoiseHandshakeBuilder.forIKResponder(currentResponderStaticKeyPair)
        .setComponentsFromProtocolName("Noise_IK_25519_AESGCM_SHA256")
        .build();
```

The initiator sends its first message to the responder, which won't be able to decrypt the message due to the static key disagreement:

```java
// -> e, es, s, ss (with an empty payload)
final byte[] initiatorStaticKeyMessage = ikInitiatorHandshake.writeMessage((byte[]) null);

// Throws an AEADBadTagException because the initiator has a stale static key for the responder
ikResponderHandshake.readMessage(initiatorStaticKeyMessage);
```

Rather than simply failing the handshake (assuming both the initiator and responder are expecting that a fallback may happen), the responder can fall back to the XXfallback pattern, reusing the ephemeral key it already received from the initiator as a pre-handshake message, and write a message to continue the XXfallback pattern:

```java
final NoiseHandshake xxFallbackResponderHandshake =
    ikResponderHandshake.fallbackTo("XXfallback");

// <- e, ee, s, es (with an empty payload)
final byte[] responderStaticKeyMessage = xxFallbackResponderHandshake.writeMessage((byte[]) null);
```

The initiator will fail to decrypt the message from the responder:

```java
// Throws an AEADBadTagException
ikInitiatorHandshake.readMessage(responderStaticKeyMessage);
```

Like the responder, the initiator can take the decryption failure as a cue to fall back to the XXfallback pattern, then read the message and finish the handshake:

```java
final NoiseHandshake xxFallbackInitiatorHandshake =
    ikInitiatorHandshake.fallbackTo("XXfallback");

xxFallbackInitiatorHandshake.readMessage(responderStaticKeyMessage);

final byte[] initiatorFallbackStaticKeyMessage =
    xxFallbackInitiatorHandshake.writeMessage((byte[]) null);

xxFallbackResponderHandshake.readMessage(initiatorFallbackStaticKeyMessage);

assert xxFallbackInitiatorHandshake.isDone();
assert xxFallbackResponderHandshake.isDone();
```

Once the handshake is finished, the transition to the transport phase of the protocol continues as usual.

## Transports

Once the handshake phase of a Noise protocol has finished, NoiseHandshake instances may be transformed or "split" (in the terminology of the Noise Protocol Framework specification) into Noise transport objects. Depending on the nature of the handshake and the role of the party in the handshake, a NoiseHandshake instance may be transformed into exactly one of:

- A NoiseTransportWriter if the handshake is a one-way handshake for the handshake initiator
- A NoiseTransportReader if the handshake is a one-way handshake for the handshake responder
- A NoiseTransport if the handshake is interactive

Once a handshake has been split, a Noise transport instance can be used to exchange transport messages as needed. Note that unlike handshake messages, transport messages contain only payload ciphertexts (i.e. they do not contain key material, and their content is always encrypted). As an example starting from a finished interactive handshake:

```java
final NoiseTransport initiatorTransport = initiatorHandshake.toTransport();
final NoiseTransport responderTransport = responderHandshake.toTransport();

final byte[] originalPlaintextBytes = "Hello, Bob!".getBytes(StandardCharsets.UTF_8);

final byte[] aliceToBobCiphertext =
    initiatorTransport.writeMessage(originalPlaintextBytes);

assert !Arrays.equals(aliceToBobCiphertext, originalPlaintextBytes);

final byte[] aliceToBobPlaintext = responderTransport.readMessage(aliceToBobCiphertext);

assert Arrays.equals(aliceToBobPlaintext, originalPlaintextBytes);
```

## Limitations and cut corners

java-noise strives to be well-behaved, but its implementation makes a few minor deviations from pedantic correctness. In particular:

- [IETF RFC 7693 ("The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)")](https://datatracker.ietf.org/doc/html/rfc7693), [section 2.1](https://datatracker.ietf.org/doc/html/rfc7693#section-2.1) specifies that BLAKE2b must support up to $2^{128}$ bytes of input data. The implementation included in java-noise only supports up to $2^{64}$. To put that limitation into perspective, though, BLAKE2b can hash about 1GiB/sec of input data on modern hardware. At that rate, it would take nearly 300 years of continuous work on a single input stream to encounter that limit. On top of that, the [Noise Protocol Framework specification, section 3](https://noiseprotocol.org/noise.html#message-format) specifies that Noise messages may not be more than 64KiB, and so this limitation is very unlikely to matter in any practical scenario.
- Similarly, the [Noise Protocol Framework specification, section 5](https://noiseprotocol.org/noise.html#processing-rules) specifies that `CipherState` objects (practically exposed as `NoiseHandshake` and the `NoiseTransport` family of interfaces in java-noise) must fail and self-delete in the event of nonce rollover. java-noise does _not_ implement this check because the nonce is a 64-bit value, and assuming a transfer rate of 1,000,000 messages per second, encountering this limit would take nearly 300,000 years on modern hardware.
- In the interest of avoiding "nuisance" exceptions (for example, declaring that `NoiseTransport#writeMessage` might throw a `NoSuchAlgorithmException`), java-noise assumes that if an implementation of a cryptographic algorithm can be instantiated once, it can be re-instantiated again later. In theory, this assumption may not always hold; an implementation of a cryptographic algorithm may be provided by a Java security `Provider` that is later removed. This situation is unlikely in practice (and callers operating in an environment where they do not control their security infrastructure likely have bigger problems), but if a previously-available algorithm becomes unavailable, various components of java-noise may throw an unchecked `AssertionError` instead of a `NoSuchAlgorithmException`.

## Test vectors

Test vectors for this project come from several sources:

1. java-noise uses the test vectors from the [cacophony](https://github.com/haskell-cryptography/cacophony) project without significant modification
2. java-noise uses parts of the "fallback" test vectors from the [noise-c](https://github.com/rweather/noise-c) project, but without the PSK-related fallback tests, since noise-c's PSK implementation appears to adhere to an earlier version of the Noise specification
3. Test vectors for the BLAKE2 algorithms come from the [BLAKE2](https://www.blake2.net/) project

The general idea behind Noise test vecors is [explained on the Noise wiki](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors), though most publicly available test vectors seem to deviate from the format described on the wiki to some degree.
