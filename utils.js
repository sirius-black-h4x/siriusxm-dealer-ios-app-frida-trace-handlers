function op2str(op) {
  return {0: "kCCEncrypt", 1: "kCCDecrypt"}[op.toInt32()];
}

function alg2str(alg) {
  return {
    0: "kCCAlgorithmAES",
    1: "kCCAlgorithmDES",
    2: "kCCAlgorithm3DES",
    3: "kCCAlgorithmCAST",
    4: "kCCAlgorithmRC4",
    5: "kCCAlgorithmRC2",
    6: "kCCAlgorithmBlowfish"
  }[alg.toInt32()];
}

function opts2str(opt) {
  const optVal = opt.toInt32();
  if (optVal === 0) {
    return "(none)";
  }
  var opts = [];
  for (var i = 0; i < 32; ++i) {
    if ((optVal >>> i) & 1) {
      opts.push({
        0: "kCCOptionPKCS7Padding",
        1: "kCCOptionECBMode"
      }[i]);
    }
  }
  return "[" + opts.join(", ") + "]";
}

function nibble2hexstr(nibble) {
  if (nibble >= 0 && nibble < 10) {
    return "0" + nibble;
  } else if (nibble < 16) {
    return String.fromCharCode("A".charCodeAt(0) + nibble);
  } else {
    throw new Error(`nibble: ${nibble} out of range`);
  }
}

function byte2hexstr(byte) {
  if (byte >= 0 && byte < 256) {
    return nibble2hexstr((byte >>> 4) & 0x0F) + nibble2hexstr(byte & 0x0F);
  } else {
    throw new Error(`byte: ${byte} out of range`);
  }
}

function uint8array2hexstr(arr) {
  var hexstr = "";
  for (var i = 0; i < arr.length; ++i) {
    hexstr += byte2hexstr(i);
  }
  return hexstr;
}

function iv2str(iv) {
  if (iv.isNull()) {
    return "NULL";
  } else {
    return uint8array2hexstr(new Uint8Array(ArrayBuffer.wrap(iv, 16)));
  }
}
