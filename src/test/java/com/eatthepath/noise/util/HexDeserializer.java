package com.eatthepath.noise.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.HexFormat;

public class HexDeserializer extends JsonDeserializer<byte[]> {

  @Override
  public byte[] deserialize(final JsonParser jsonParser, final DeserializationContext deserializationContext) throws IOException {
    return HexFormat.of().parseHex(jsonParser.getValueAsString());
  }
}
