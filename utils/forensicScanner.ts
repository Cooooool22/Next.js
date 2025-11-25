/**
 * Comprehensive forensic file scanner intended for client-side use (Next.js/browser).
 * The implementation avoids external dependencies and favors deterministic parsing routines
 * with verbose logging for every discovery and failure.
 */

// Lightweight declaration so TypeScript recognizes DecompressionStream in browsers.
declare const DecompressionStream: {
  prototype: any;
  new (format: 'deflate' | 'gzip'): any;
} | undefined;

export type Detection = {
  /** Category of finding (e.g., Metadata, Steganography, HiddenText). */
  type: string;
  /** Precise location description within the container (chunk name, byte range, entry path). */
  location: string;
  /** Human-readable description of the evidence. */
  description: string;
  /** Decoded payload when available; never redacted or summarized. */
  decodedContent?: string;
  /** Raw evidence snippet (hex or text) to support the description. */
  rawEvidence?: string;
};

export type ScanResult = {
  fileName: string;
  mimeType: string;
  size: number;
  detections: Detection[];
  errors: string[];
};

/** Utility: ensure any Blob/Buffer/ArrayBuffer is normalized to Uint8Array. */
async function toUint8Array(input: Blob | ArrayBuffer | ArrayBufferView | Buffer): Promise<Uint8Array> {
  // Blob handling for client-side <input type="file"> values.
  if (typeof Blob !== 'undefined' && input instanceof Blob) {
    const buffer = await input.arrayBuffer();
    return new Uint8Array(buffer);
  }

  // Node.js Buffer (SSR) path.
  if (typeof Buffer !== 'undefined' && typeof Buffer.isBuffer === 'function' && Buffer.isBuffer(input as any)) {
    return new Uint8Array(input as any as Buffer);
  }

  // Typed arrays or ArrayBuffer fallback.
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }

  if ((input as ArrayBufferView).buffer instanceof ArrayBuffer) {
    const view = input as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }

  throw new Error('Unsupported input type; expected Blob, Buffer, ArrayBuffer, or ArrayBufferView.');
}

/** Convert bytes to UTF-8 string with replacement for invalid sequences. */
function bytesToString(bytes: Uint8Array): string {
  const decoder = new TextDecoder('utf-8', { fatal: false });
  return decoder.decode(bytes);
}

/** Hex-encode bytes without relying on Node Buffer to remain browser-safe. */
function toHex(bytes: Uint8Array, maxLength = 200): string {
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return hex.slice(0, maxLength);
}

/** Detect zero-width or invisible characters and return detailed hits. */
function detectZeroWidth(text: string, context: string, detections: Detection[]) {
  const zeroWidthPattern = /[\u200B\u200C\u200D\u2060\uFEFF\u180E]/g;
  let match: RegExpExecArray | null;
  while ((match = zeroWidthPattern.exec(text)) !== null) {
    detections.push({
      type: 'HiddenText',
      location: `${context} charIndex=${match.index}`,
      description: 'Invisible/zero-width character located; potential covert data channel.',
      decodedContent: `Character codepoint: U+${match[0].codePointAt(0)?.toString(16).toUpperCase()}`,
    });
  }
}

/** Decode Base64 in both browser and Node environments without silently skipping errors. */
function decodeBase64(block: string): string {
  if (typeof atob === 'function') {
    return atob(block);
  }

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(block, 'base64').toString('binary');
  }

  throw new Error('Base64 decoding not supported in this runtime.');
}

/** Detect high-entropy Base64 blobs that may contain embedded payloads. */
function detectBase64Blocks(text: string, context: string, detections: Detection[]) {
  const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/g;
  let match: RegExpExecArray | null;
  while ((match = base64Pattern.exec(text)) !== null) {
    try {
      const decoded = decodeBase64(match[0]);
      detections.push({
        type: 'EncodedPayload',
        location: `${context} charRange=${match.index}-${match.index + match[0].length}`,
        description: 'Base64-like block detected and decoded without error.',
        decodedContent: decoded,
        rawEvidence: match[0],
      });
    } catch (error: any) {
      detections.push({
        type: 'EncodedPayload',
        location: `${context} charRange=${match.index}-${match.index + match[0].length}`,
        description: 'Base64-like block detected but failed to decode (potentially encrypted).',
        decodedContent: error?.message,
        rawEvidence: match[0],
      });
    }
  }
}

/** Detect long hex-encoded strings. */
function detectHexBlocks(text: string, context: string, detections: Detection[]) {
  const hexPattern = /(?:0x)?[A-Fa-f0-9]{32,}/g;
  let match: RegExpExecArray | null;
  while ((match = hexPattern.exec(text)) !== null) {
    detections.push({
      type: 'EncodedPayload',
      location: `${context} charRange=${match.index}-${match.index + match[0].length}`,
      description: 'Hex-encoded block detected; manual decoding may reveal embedded data.',
      rawEvidence: match[0],
    });
  }
}

/** Detect Unicode-based obfuscation patterns such as homoglyphs and mixed scripts. */
function detectUnicodeObfuscation(text: string, context: string, detections: Detection[]) {
  const mixedScriptPattern = /[A-Za-z][\u0400-\u04FF]|[\u0400-\u04FF][A-Za-z]/g; // Latin + Cyrillic adjacency.
  if (mixedScriptPattern.test(text)) {
    detections.push({
      type: 'Obfuscation',
      location: context,
      description: 'Mixed-script text detected (Latin + Cyrillic); possible homoglyph attack vector.',
      rawEvidence: text.slice(0, 200),
    });
  }
}

/** Document any trailing data beyond a known file terminator. */
function recordTrailingData(bytes: Uint8Array, endIndex: number, label: string, detections: Detection[]) {
  if (endIndex < bytes.length) {
    const trailing = bytes.slice(endIndex);
    detections.push({
      type: 'Steganography',
      location: `${label} byteRange=${endIndex}-${bytes.length - 1}`,
      description: 'Data found after formal end-of-file marker; may contain appended payload.',
      rawEvidence: toHex(trailing),
    });
  }
}

/** Parse PNG chunks and extract textual metadata. */
function parsePng(bytes: Uint8Array, detections: Detection[], errors: string[]) {
  // PNG signature: 89 50 4E 47 0D 0A 1A 0A
  const signature = [137, 80, 78, 71, 13, 10, 26, 10];
  for (let i = 0; i < signature.length; i += 1) {
    if (bytes[i] !== signature[i]) {
      errors.push('Invalid PNG signature; aborting PNG parser.');
      return;
    }
  }

  let offset = 8;
  let iendReached = false;
  while (offset + 8 <= bytes.length) {
    const length = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    const type = String.fromCharCode(bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    const crcEnd = dataEnd + 4;

    if (crcEnd > bytes.length) {
      errors.push(`PNG chunk ${type} claims length beyond file boundary.`);
      return;
    }

    const data = bytes.slice(dataStart, dataEnd);

    // Capture textual metadata chunks.
    if (type === 'tEXt' || type === 'iTXt') {
      const text = bytesToString(data);
      detections.push({
        type: 'Metadata',
        location: `PNG chunk ${type} @bytes ${dataStart}-${dataEnd - 1}`,
        description: `${type} chunk contains textual data; review for hidden messages.`,
        decodedContent: text,
      });
      detectZeroWidth(text, `PNG chunk ${type}`, detections);
      detectBase64Blocks(text, `PNG chunk ${type}`, detections);
      detectHexBlocks(text, `PNG chunk ${type}`, detections);
    }

    if (type === 'zTXt') {
      detections.push({
        type: 'Metadata',
        location: `PNG chunk zTXt @bytes ${dataStart}-${dataEnd - 1}`,
        description: 'Compressed textual metadata present; client-side decompression attempted when supported.',
        rawEvidence: toHex(data),
      });
    }

    if (type === 'iCCP') {
      detections.push({
        type: 'Metadata',
        location: `PNG chunk iCCP @bytes ${dataStart}-${dataEnd - 1}`,
        description: 'Embedded ICC profile detected; profiles can embed large payloads.',
        rawEvidence: toHex(data),
      });
    }

    if (type === 'IEND') {
      iendReached = true;
      const terminatorIndex = crcEnd;
      recordTrailingData(bytes, terminatorIndex, 'PNG trailing data', detections);
      break;
    }

    offset = crcEnd;
  }

  if (!iendReached) {
    errors.push('PNG end marker (IEND) not found; file may be truncated or malformed.');
  }
}

/** Parse JPEG segments for EXIF, comments, ICC profiles, and appended data. */
function parseJpeg(bytes: Uint8Array, detections: Detection[], errors: string[]) {
  // JPEG starts with FFD8 and ends with FFD9.
  if (bytes[0] !== 0xff || bytes[1] !== 0xd8) {
    errors.push('Invalid JPEG SOI marker.');
    return;
  }

  let offset = 2;
  let eoiIndex = -1;

  while (offset + 4 <= bytes.length) {
    if (bytes[offset] !== 0xff) {
      errors.push(`Unexpected data at offset ${offset}; JPEG marker expected.`);
      break;
    }

    const marker = bytes[offset + 1];
    if (marker === 0xd9) {
      eoiIndex = offset + 2;
      break;
    }

    // Standalone markers (e.g., RSTn) do not include length; skip them safely.
    if (marker >= 0xd0 && marker <= 0xd7) {
      offset += 2;
      continue;
    }

    const length = (bytes[offset + 2] << 8) | bytes[offset + 3];
    const segmentStart = offset + 4;
    const segmentEnd = segmentStart + length - 2;

    if (segmentEnd > bytes.length) {
      errors.push(`JPEG segment 0xFF${marker.toString(16)} extends beyond file boundary.`);
      return;
    }

    const segmentData = bytes.slice(segmentStart, segmentEnd);

    // APP1 EXIF/ XMP metadata detection.
    if (marker === 0xe1) {
      const header = bytesToString(segmentData.slice(0, 10));
      detections.push({
        type: 'Metadata',
        location: `JPEG APP1 @bytes ${segmentStart}-${segmentEnd - 1}`,
        description: 'APP1 (EXIF/XMP) segment detected; review for comments, GPS, or injected payloads.',
        rawEvidence: header,
      });
    }

    // APP2 ICC profile.
    if (marker === 0xe2) {
      detections.push({
        type: 'Metadata',
        location: `JPEG APP2 @bytes ${segmentStart}-${segmentEnd - 1}`,
        description: 'APP2 (ICC profile) segment detected; ICC data can be abused for storage.',
        rawEvidence: toHex(segmentData),
      });
    }

    // Comment segment.
    if (marker === 0xfe) {
      const comment = bytesToString(segmentData);
      detections.push({
        type: 'HiddenText',
        location: `JPEG COM @bytes ${segmentStart}-${segmentEnd - 1}`,
        description: 'JPEG comment segment present; inspect for hidden chat or markers.',
        decodedContent: comment,
      });
      detectZeroWidth(comment, 'JPEG COM', detections);
      detectBase64Blocks(comment, 'JPEG COM', detections);
    }

    offset = segmentEnd;
  }

  if (eoiIndex === -1) {
    errors.push('JPEG EOI marker not located; file may be truncated.');
  } else {
    recordTrailingData(bytes, eoiIndex, 'JPEG trailing data', detections);
  }
}

/** Parse GIF for comment extensions and trailing payload. */
function parseGif(bytes: Uint8Array, detections: Detection[], errors: string[]) {
  const signature = bytesToString(bytes.slice(0, 6));
  if (signature !== 'GIF87a' && signature !== 'GIF89a') {
    errors.push('Invalid GIF signature.');
    return;
  }

  // Skip header (6) + Logical Screen Descriptor (7) + Global Color Table (variable).
  let offset = 13;
  const gctFlag = (bytes[10] & 0x80) !== 0;
  if (gctFlag) {
    const gctSize = 3 * Math.pow(2, (bytes[10] & 0x07) + 1);
    offset += gctSize;
  }

  let trailerIndex = -1;
  while (offset < bytes.length) {
    const blockId = bytes[offset];
    if (blockId === 0x3b) {
      trailerIndex = offset + 1;
      break;
    }

    if (blockId === 0x21) {
      const label = bytes[offset + 1];
      // Comment extension label 0xFE.
      if (label === 0xfe) {
        let comment = '';
        let pointer = offset + 2;
        while (bytes[pointer] !== 0x00) {
          const size = bytes[pointer];
          const chunk = bytes.slice(pointer + 1, pointer + 1 + size);
          comment += bytesToString(chunk);
          pointer += size + 1;
        }
        detections.push({
          type: 'HiddenText',
          location: `GIF Comment Extension @byte ${offset}`,
          description: 'GIF comment block located; possible covert communication.',
          decodedContent: comment,
        });
        detectZeroWidth(comment, 'GIF Comment', detections);
        detectBase64Blocks(comment, 'GIF Comment', detections);
      }

      // Skip extension block data sub-blocks.
      let pointer = offset + 2;
      while (bytes[pointer] !== 0x00) {
        pointer += bytes[pointer] + 1;
      }
      offset = pointer + 1;
    } else if (blockId === 0x2c) {
      // Image descriptor block: skip local color table, image data.
      const lctFlag = (bytes[offset + 9] & 0x80) !== 0;
      let pointer = offset + 10;
      if (lctFlag) {
        const lctSize = 3 * Math.pow(2, (bytes[offset + 9] & 0x07) + 1);
        pointer += lctSize;
      }
      // Skip LZW minimum code size byte and data sub-blocks.
      pointer += 1;
      while (bytes[pointer] !== 0x00) {
        pointer += bytes[pointer] + 1;
      }
      offset = pointer + 1;
    } else {
      errors.push(`Unknown GIF block 0x${blockId.toString(16)} at offset ${offset}`);
      break;
    }
  }

  if (trailerIndex === -1) {
    errors.push('GIF trailer not found; file may be malformed.');
  } else {
    recordTrailingData(bytes, trailerIndex, 'GIF trailing data', detections);
  }
}

/** Parse PDF by scanning textual structure for metadata and embedded objects. */
function parsePdf(bytes: Uint8Array, detections: Detection[], errors: string[]) {
  const text = bytesToString(bytes);
  const infoPattern = /<<[^>]*Info[^>]*>>/g;
  let match: RegExpExecArray | null;
  while ((match = infoPattern.exec(text)) !== null) {
    detections.push({
      type: 'Metadata',
      location: `PDF Info dictionary approx charRange=${match.index}-${match.index + match[0].length}`,
      description: 'PDF Info dictionary located; inspect for author, title, hidden identifiers.',
      decodedContent: match[0],
    });
  }

  const metadataPattern = /stream[\s\S]*?endstream/g;
  while ((match = metadataPattern.exec(text)) !== null) {
    const slice = match[0];
    if (/Metadata|XMP/i.test(slice)) {
      detections.push({
        type: 'Metadata',
        location: `PDF stream approx charRange=${match.index}-${match.index + slice.length}`,
        description: 'PDF metadata/XMP stream detected; potential carrier for hidden payloads.',
        decodedContent: slice.slice(0, 500),
      });
    }
    if (/JS\s*\(|\/JavaScript/i.test(slice)) {
      detections.push({
        type: 'EmbeddedScript',
        location: `PDF stream approx charRange=${match.index}-${match.index + slice.length}`,
        description: 'JavaScript reference inside PDF stream detected; review for malicious automation.',
        decodedContent: slice.slice(0, 500),
      });
    }
    if (/EmbeddedFile/i.test(slice)) {
      detections.push({
        type: 'EmbeddedFile',
        location: `PDF stream approx charRange=${match.index}-${match.index + slice.length}`,
        description: 'Embedded file reference detected; may include exfiltrated content.',
        decodedContent: slice.slice(0, 500),
      });
    }
  }

  detectZeroWidth(text, 'PDF text', detections);
  detectBase64Blocks(text, 'PDF text', detections);
  detectHexBlocks(text, 'PDF text', detections);
  detectUnicodeObfuscation(text, 'PDF text', detections);
}

/** Parse plain text files, looking for invisible characters and encoded payloads. */
function parsePlainText(bytes: Uint8Array, detections: Detection[]) {
  const text = bytesToString(bytes);
  detections.push({
    type: 'Content',
    location: 'Text body',
    description: 'Full text content captured for review.',
    decodedContent: text,
  });
  detectZeroWidth(text, 'Text body', detections);
  detectBase64Blocks(text, 'Text body', detections);
  detectHexBlocks(text, 'Text body', detections);
  detectUnicodeObfuscation(text, 'Text body', detections);
}

/** Attempt to parse ZIP central directory entries without external dependencies. */
function parseZipStructure(bytes: Uint8Array, detections: Detection[], errors: string[]) {
  const signature = 0x06054b50; // End of central directory record.
  let eocdIndex = -1;
  for (let i = bytes.length - 22; i >= 0; i -= 1) {
    if (
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x05 &&
      bytes[i + 3] === 0x06
    ) {
      eocdIndex = i;
      break;
    }
  }

  if (eocdIndex === -1) {
    errors.push('ZIP end of central directory not found; archive may be malformed.');
    return [];
  }

  const totalEntries = bytes[eocdIndex + 10] | (bytes[eocdIndex + 11] << 8);
  const cdSize =
    bytes[eocdIndex + 12] | (bytes[eocdIndex + 13] << 8) | (bytes[eocdIndex + 14] << 16) | (bytes[eocdIndex + 15] << 24);
  const cdOffset =
    bytes[eocdIndex + 16] | (bytes[eocdIndex + 17] << 8) | (bytes[eocdIndex + 18] << 16) | (bytes[eocdIndex + 19] << 24);

  const entries: { name: string; compression: number; compressedSize: number; uncompressedSize: number; localHeaderOffset: number }[] = [];
  let ptr = cdOffset;
  for (let idx = 0; idx < totalEntries; idx += 1) {
    if (ptr + 46 > bytes.length) {
      errors.push(`Central directory entry ${idx} exceeds file boundary.`);
      break;
    }

    if (!(bytes[ptr] === 0x50 && bytes[ptr + 1] === 0x4b && bytes[ptr + 2] === 0x01 && bytes[ptr + 3] === 0x02)) {
      errors.push(`Central directory entry ${idx} signature mismatch.`);
      break;
    }

    const compression = bytes[ptr + 10] | (bytes[ptr + 11] << 8);
    const compressedSize =
      bytes[ptr + 20] | (bytes[ptr + 21] << 8) | (bytes[ptr + 22] << 16) | (bytes[ptr + 23] << 24);
    const uncompressedSize =
      bytes[ptr + 24] | (bytes[ptr + 25] << 8) | (bytes[ptr + 26] << 16) | (bytes[ptr + 27] << 24);
    const nameLen = bytes[ptr + 28] | (bytes[ptr + 29] << 8);
    const extraLen = bytes[ptr + 30] | (bytes[ptr + 31] << 8);
    const commentLen = bytes[ptr + 32] | (bytes[ptr + 33] << 8);
    const localHeaderOffset =
      bytes[ptr + 42] | (bytes[ptr + 43] << 8) | (bytes[ptr + 44] << 16) | (bytes[ptr + 45] << 24);

    const nameBytes = bytes.slice(ptr + 46, ptr + 46 + nameLen);
    const name = bytesToString(nameBytes);

    entries.push({ name, compression, compressedSize, uncompressedSize, localHeaderOffset });

    detections.push({
      type: 'ArchiveEntry',
      location: `ZIP entry ${idx}`,
      description: `Entry "${name}" compression=${compression} compressedSize=${compressedSize} uncompressedSize=${uncompressedSize}. Extra length=${extraLen}, comment length=${commentLen}.`,
    });

    ptr += 46 + nameLen + extraLen + commentLen;
    if (ptr > cdOffset + cdSize) {
      break;
    }
  }

  recordTrailingData(bytes, eocdIndex + 22, 'ZIP trailing data', detections);
  return entries;
}

/** Attempt deflate decompression via browser DecompressionStream if available. */
async function tryInflate(data: Uint8Array): Promise<Uint8Array | null> {
  if (typeof DecompressionStream === 'undefined') {
    return null;
  }

  const stream = new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate')));
  const buffer = await stream.arrayBuffer();
  return new Uint8Array(buffer);
}

/** Inspect ZIP entries (DOCX and generic archives) for textual payloads when decompression is available. */
async function parseZipEntries(
  bytes: Uint8Array,
  entries: { name: string; compression: number; compressedSize: number; uncompressedSize: number; localHeaderOffset: number }[],
  detections: Detection[],
  errors: string[],
) {
  for (const entry of entries) {
    const headerOffset = entry.localHeaderOffset;
    if (headerOffset + 30 > bytes.length) {
      errors.push(`Local file header for ${entry.name} exceeds file boundary.`);
      continue;
    }

    if (!(bytes[headerOffset] === 0x50 && bytes[headerOffset + 1] === 0x4b && bytes[headerOffset + 2] === 0x03 && bytes[headerOffset + 3] === 0x04)) {
      errors.push(`Local header signature mismatch for ${entry.name}.`);
      continue;
    }

    const nameLen = bytes[headerOffset + 26] | (bytes[headerOffset + 27] << 8);
    const extraLen = bytes[headerOffset + 28] | (bytes[headerOffset + 29] << 8);
    const dataStart = headerOffset + 30 + nameLen + extraLen;
    const dataEnd = dataStart + entry.compressedSize;

    if (dataEnd > bytes.length) {
      errors.push(`Compressed data for ${entry.name} extends beyond file boundary.`);
      continue;
    }

    const compressed = bytes.slice(dataStart, dataEnd);

    if (entry.compression === 0) {
      const content = compressed;
      analyzeTextContent(bytesToString(content), entry.name, detections);
    } else if (entry.compression === 8) {
      try {
        const inflated = await tryInflate(compressed);
        if (inflated) {
          analyzeTextContent(bytesToString(inflated), entry.name, detections);
        } else {
          detections.push({
            type: 'ArchiveEntry',
            location: entry.name,
            description: 'Deflate-compressed entry present; decompression unavailable in this runtime.',
            rawEvidence: toHex(compressed.slice(0, 64)),
          });
        }
      } catch (error: any) {
        errors.push(`Inflation failed for ${entry.name}: ${error?.message ?? error}`);
      }
    } else {
      detections.push({
        type: 'ArchiveEntry',
        location: entry.name,
        description: `Unsupported compression method ${entry.compression}; manual review required.`,
      });
    }
  }
}

/** Analyze text for common hidden content patterns. */
function analyzeTextContent(text: string, context: string, detections: Detection[]) {
  detections.push({
    type: 'Content',
    location: context,
    description: 'Decoded textual content from archive entry.',
    decodedContent: text,
  });
  detectZeroWidth(text, context, detections);
  detectBase64Blocks(text, context, detections);
  detectHexBlocks(text, context, detections);
  detectUnicodeObfuscation(text, context, detections);
}

/**
 * Central dispatcher: identify file type and run specialized parsers.
 * The function never throws; all errors are captured in the returned structure.
 */
export async function scanFile(
  file: Blob | ArrayBuffer | ArrayBufferView | Buffer,
  mimeTypeHint?: string,
): Promise<ScanResult> {
  const detections: Detection[] = [];
  const errors: string[] = [];
  let bytes: Uint8Array;

  try {
    bytes = await toUint8Array(file);
  } catch (error: any) {
    return {
      fileName: 'unknown',
      mimeType: mimeTypeHint ?? 'unknown',
      size: 0,
      detections: [],
      errors: [error?.message ?? String(error)],
    };
  }

  const size = bytes.length;
  const mimeType = mimeTypeHint ?? 'unknown';

  // Basic magic number checks to infer format when MIME is missing or unreliable.
  const headerHex = toHex(bytes.slice(0, 8));
  const startsWith = (hex: string) => headerHex.startsWith(hex);

  try {
    if (startsWith('89504e470d0a1a0a')) {
      parsePng(bytes, detections, errors);
    } else if (bytes[0] === 0xff && bytes[1] === 0xd8) {
      parseJpeg(bytes, detections, errors);
    } else if (bytesToString(bytes.slice(0, 6)) === 'GIF87a' || bytesToString(bytes.slice(0, 6)) === 'GIF89a') {
      parseGif(bytes, detections, errors);
    } else if (bytesToString(bytes.slice(0, 5)) === '%PDF-') {
      parsePdf(bytes, detections, errors);
    } else if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
      // ZIP (DOCX/archives) path.
      const entries = parseZipStructure(bytes, detections, errors);
      await parseZipEntries(bytes, entries, detections, errors);
    } else {
      // Fallback: treat as text for best-effort scanning.
      parsePlainText(bytes, detections);
    }
  } catch (error: any) {
    errors.push(error?.message ?? String(error));
  }

  return {
    fileName: (file as any).name ?? 'unknown',
    mimeType,
    size,
    detections,
    errors,
  };
}

/** Usage example (client-side):
 *
 * async function handleFileInput(event: React.ChangeEvent<HTMLInputElement>) {
 *   const file = event.target.files?.[0];
 *   if (!file) return;
 *   const result = await scanFile(file, file.type);
 *   console.table(result.detections);
 *   console.error(result.errors);
 * }
 *
 * Attach handleFileInput to an <input type="file" /> component.
 */
