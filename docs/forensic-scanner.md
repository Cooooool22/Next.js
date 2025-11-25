# Forensic file scanner

This document describes the client-side forensic scanning utilities provided in `utils/forensicScanner.ts`.

## Capabilities
- Binary-aware parsing of PNG, JPEG, GIF, PDF, and ZIP/DOCX containers.
- Detection of hidden channels including trailing bytes beyond file terminators, zero-width characters, mixed-script obfuscation, and embedded Base64/hex blobs.
- Metadata inspection for EXIF/XMP, ICC profiles, PNG text chunks, GIF comments, PDF streams, and ZIP central directory entries.
- Best-effort decompression of deflate-compressed ZIP entries using the browser`s `DecompressionStream` API when available, with transparent logging when decompression is not possible.
- All findings are returned verbatim without summarization, including decoded content and raw evidence snippets where applicable.

## Usage
```tsx
import { scanFile } from '../utils/forensicScanner';

async function handleFile(file: File) {
  const result = await scanFile(file, file.type);
  // Each detection contains type, location, description, and optional decodedContent/rawEvidence.
  console.table(result.detections);
  if (result.errors.length) {
    console.error('Scan errors', result.errors);
  }
}
```

### Output structure
- `fileName`, `mimeType`, and `size` describe the scanned file.
- `detections` is an array of logged findings. No entry is filtered or obfuscated.
- `errors` collects every parsing or decoding failure; the scanner never throws.

### Edge cases
- Corrupted files (e.g., truncated PNG/JPEG/GIF) are reported with explicit errors.
- ZIP/DOCX parsing lists every entry found in the central directory. If decompression is unsupported in the runtime, the scanner records that limitation alongside the hex preview of compressed data.
- Unknown formats are treated as plain text so zero-width characters and encoded payloads still surface.
