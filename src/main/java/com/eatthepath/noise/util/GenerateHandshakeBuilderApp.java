package com.eatthepath.noise.util;

import com.eatthepath.noise.HandshakePattern;
import com.eatthepath.noise.NoiseHandshake;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

class GenerateHandshakeBuilderApp {

  private static final String HANDSHAKE_PATTERN_FILE = "/com/eatthepath/noise/handshake-patterns.txt";

  private static final String NO_KEY_INITIALIZER_TEMPLATE = """
      public static NoiseHandshakeBuilder for%METHOD_SAFE_PATTERN_NAME%%METHOD_SAFE_ROLE_NAME%() {
        try {
          return new NoiseHandshakeBuilder(NoiseHandshake.Role.%ROLE_ENUM_KEY%,
              HandshakePattern.getInstance("%PATTERN_NAME%"),
              null,
              null);
        } catch (final NoSuchPatternException e) {
          throw new AssertionError("Statically-generated handshake pattern not found", e);
        }
      }
      """;

  private static final String LOCAL_STATIC_KEY_INITIALIZER_TEMPLATE = """
      public static NoiseHandshakeBuilder for%METHOD_SAFE_PATTERN_NAME%%METHOD_SAFE_ROLE_NAME%(final KeyPair localStaticKeyPair) {
        try {
          return new NoiseHandshakeBuilder(NoiseHandshake.Role.%ROLE_ENUM_KEY%,
              HandshakePattern.getInstance("%PATTERN_NAME%"),
              localStaticKeyPair,
              null);
        } catch (final NoSuchPatternException e) {
          throw new AssertionError("Statically-generated handshake pattern not found", e);
        }
      }
      """;

  private static final String REMOTE_STATIC_KEY_INITIALIZER_TEMPLATE = """
      public static NoiseHandshakeBuilder for%METHOD_SAFE_PATTERN_NAME%%METHOD_SAFE_ROLE_NAME%(final PublicKey remoteStaticPublicKey) {
        try {
          return new NoiseHandshakeBuilder(NoiseHandshake.Role.%ROLE_ENUM_KEY%,
              HandshakePattern.getInstance("%PATTERN_NAME%"),
              null,
              remoteStaticPublicKey);
        } catch (final NoSuchPatternException e) {
          throw new AssertionError("Statically-generated handshake pattern not found", e);
        }
      }
      """;

  private static final String LOCAL_AND_REMOTE_STATIC_KEY_INITIALIZER_TEMPLATE = """
      public static NoiseHandshakeBuilder for%METHOD_SAFE_PATTERN_NAME%%METHOD_SAFE_ROLE_NAME%(final KeyPair localStaticKeyPair, final PublicKey remoteStaticPublicKey) {
        try {
          return new NoiseHandshakeBuilder(NoiseHandshake.Role.%ROLE_ENUM_KEY%,
              HandshakePattern.getInstance("%PATTERN_NAME%"),
              localStaticKeyPair,
              remoteStaticPublicKey);
        } catch (final NoSuchPatternException e) {
          throw new AssertionError("Statically-generated handshake pattern not found", e);
        }
      }
      """;

  private static final String HANDSHAKE_BUILDER_TEMPLATE_FILE = "NoiseHandshakeBuilder.java.template";

  private static final String INITIALIZER_TEMPLATE_PLACEHOLDER = "// ----- AUTOGENERATED INITIALIZERS HERE -----";

  public static void main(final String... args) throws IOException {
    final StringBuilder initializerBuilder = new StringBuilder();

    for (final HandshakePattern handshakePattern : loadAllPatterns()) {
      for (final NoiseHandshake.Role role : NoiseHandshake.Role.values()) {
        final boolean needsLocalStaticKeyPair = handshakePattern.requiresLocalStaticKeyPair(role);
        final boolean needsRemoteStaticPublicKey = handshakePattern.requiresRemoteStaticPublicKey(role);

        final String template;

        if (needsLocalStaticKeyPair && needsRemoteStaticPublicKey) {
          template = LOCAL_AND_REMOTE_STATIC_KEY_INITIALIZER_TEMPLATE;
        } else if (needsLocalStaticKeyPair) {
          template = LOCAL_STATIC_KEY_INITIALIZER_TEMPLATE;
        } else if (needsRemoteStaticPublicKey) {
          template = REMOTE_STATIC_KEY_INITIALIZER_TEMPLATE;
        } else {
          template = NO_KEY_INITIALIZER_TEMPLATE;
        }

        initializerBuilder.append(renderTemplate(template, buildTemplateModel(handshakePattern, role))
            .lines()
            .map(line -> "  " + line)
            .collect(Collectors.joining("\n")));

        initializerBuilder.append("\n\n");
      }
    }

    try (final InputStream templateInputStream = GenerateHandshakeBuilderApp.class.getResourceAsStream(HANDSHAKE_BUILDER_TEMPLATE_FILE)) {
      if (templateInputStream == null) {
        throw new IOException("Could not read template file");
      }

      final String templateString = new String(templateInputStream.readAllBytes(), StandardCharsets.UTF_8);

      System.out.println(templateString.replace(INITIALIZER_TEMPLATE_PLACEHOLDER, initializerBuilder.toString()));
    }
  }

  private static Map<String, String> buildTemplateModel(final HandshakePattern handshakePattern, final NoiseHandshake.Role role) {
    final String methodSafeRoleName = switch (role) {
      case INITIATOR -> "Initiator";
      case RESPONDER -> "Responder";
    };

    return Map.of(
        // TODO Turn "weird" pattern names into method-safe names
        "%METHOD_SAFE_PATTERN_NAME%", handshakePattern.name(),
        "%METHOD_SAFE_ROLE_NAME%", methodSafeRoleName,
        "%ROLE_ENUM_KEY%", role.name(),
        "%PATTERN_NAME%", handshakePattern.name()
    );
  }

  private static String renderTemplate(final String template, final Map<String, String> model) {
    String renderedTemplate = template;

    for (final Map.Entry<String, String> entry : model.entrySet()) {
      renderedTemplate = renderedTemplate.replace(entry.getKey(), entry.getValue());
    }

    return renderedTemplate;
  }

  private static List<HandshakePattern> loadAllPatterns() throws IOException {
    try (final InputStream inputStream = GenerateHandshakeBuilderApp.class.getResourceAsStream(HANDSHAKE_PATTERN_FILE)) {
      if (inputStream == null) {
        throw new IOException("Could not read handshake pattern file");
      }

      return Arrays.stream(new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).split("\n\n"))
          .filter(chunk -> !chunk.isBlank())
          .map(HandshakePattern::fromString)
          .toList();
    }
  }
}
