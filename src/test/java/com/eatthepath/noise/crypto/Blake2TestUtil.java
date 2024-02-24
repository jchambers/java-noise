package com.eatthepath.noise.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

import java.io.IOException;
import java.io.InputStream;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

class Blake2TestUtil {

  static Stream<Blake2TestVector> loadBlake2TestVectorsForHash(final String hash) throws IOException {
    return loadBlake2TestVectors()
        .filter(testVector -> hash.equals(testVector.hash()));
  }

  static Stream<Blake2TestVector> loadBlake2TestVectors() throws IOException {
    final InputStream testVectorInputStream = Blake2TestUtil.class.getResourceAsStream("blake2-test-vectors.json");

    if (testVectorInputStream == null) {
      throw new IOException("Test vector file not found");
    }

    final ObjectReader objectReader = new ObjectMapper()
        .reader()
        .forType(Blake2TestVector.class);

    return StreamSupport.stream(Spliterators.spliterator(objectReader.readValues(testVectorInputStream), 1,
                Spliterator.IMMUTABLE | Spliterator.NONNULL | Spliterator.ORDERED), false);
  }
}
