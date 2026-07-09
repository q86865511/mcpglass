// Walk a GIF's block structure and (a) insert a NETSCAPE2.0 infinite-loop
// extension after the global color table, (b) insert a Graphic Control
// Extension with the given frame delay before every image descriptor.
// GifBitmapEncoder emits neither, so without this the GIF neither loops nor paces.
// Usage: node patch-gif.mjs <in.gif> <out.gif> <delayCs>
import { readFileSync, writeFileSync } from "node:fs";
const [inFile, outFile, delayCsStr] = process.argv.slice(2);
const delayCs = Number(delayCsStr);
const buf = readFileSync(inFile);
const lo = delayCs & 0xff, hi = (delayCs >> 8) & 0xff;

let pos = 13; // header (6) + logical screen descriptor (7)
const packed = buf[10];
if (packed & 0x80) pos += 3 * 2 ** ((packed & 7) + 1); // global color table

const parts = [buf.subarray(0, pos)];
parts.push(Buffer.from([0x21, 0xff, 0x0b, ...Buffer.from("NETSCAPE2.0", "ascii"), 0x03, 0x01, 0x00, 0x00, 0x00]));

const skipSubBlocks = () => { while (buf[pos] !== 0) pos += buf[pos] + 1; pos++; };
let frames = 0;
while (pos < buf.length) {
  const b = buf[pos];
  if (b === 0x3b) { parts.push(buf.subarray(pos, pos + 1)); break; } // trailer
  if (b === 0x21) { // extension: 0x21 <label> <sub-blocks...> 0x00
    const start = pos;
    pos += 2;
    skipSubBlocks();
    parts.push(buf.subarray(start, pos));
  } else if (b === 0x2c) { // image descriptor
    parts.push(Buffer.from([0x21, 0xf9, 0x04, 0x04, lo, hi, 0x00, 0x00])); // GCE, disposal=1
    const start = pos;
    const ipacked = buf[pos + 9];
    pos += 10;
    if (ipacked & 0x80) pos += 3 * 2 ** ((ipacked & 7) + 1); // local color table
    pos++; // LZW min code size
    skipSubBlocks();
    parts.push(buf.subarray(start, pos));
    frames++;
  } else {
    throw new Error(`unexpected block 0x${b.toString(16)} at ${pos}`);
  }
}
writeFileSync(outFile, Buffer.concat(parts));
console.log(`frames=${frames} delay=${delayCs}cs size=${Math.round(Buffer.concat(parts).length / 1024)}KB -> ${outFile}`);
