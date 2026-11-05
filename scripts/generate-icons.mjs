// Generates the MyVault application icons without any external dependency.
// Output: src-tauri/icons/{32x32,128x128,128x128@2x,icon}.png and icon.ico
import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "src-tauri", "icons");
mkdirSync(outDir, { recursive: true });

/* ---------- PNG encoding ---------- */

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function encodePng(width, height, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/* ---------- drawing ---------- */

const clamp01 = (v) => (v < 0 ? 0 : v > 1 ? 1 : v);
const mix = (a, b, t) => a + (b - a) * t;

function roundedRectSdf(x, y, cx, cy, halfW, halfH, radius) {
  const dx = Math.abs(x - cx) - (halfW - radius);
  const dy = Math.abs(y - cy) - (halfH - radius);
  const ax = Math.max(dx, 0);
  const ay = Math.max(dy, 0);
  return Math.hypot(ax, ay) + Math.min(Math.max(dx, dy), 0) - radius;
}

// Returns [r,g,b,a] for a sample in unit space.
function shade(x, y) {
  // background: rounded square with a vertical gradient
  const bg = roundedRectSdf(x, y, 0.5, 0.5, 0.5, 0.5, 0.225);
  if (bg > 0) return [0, 0, 0, 0];
  const t = clamp01(y);
  let r = mix(15, 30, t);
  let g = mix(23, 41, t);
  let b = mix(42, 59, t);

  const accent = [56, 189, 248];
  // shackle: half ring
  const dx = x - 0.5;
  const dy = y - 0.4;
  const dist = Math.hypot(dx, dy);
  const ring = Math.abs(dist - 0.155) - 0.0375;
  if (dy <= 0.02 && ring <= 0) {
    r = accent[0];
    g = accent[1];
    b = accent[2];
  }
  // lock body
  const body = roundedRectSdf(x, y, 0.5, 0.615, 0.185, 0.165, 0.045);
  if (body <= 0) {
    const sheen = clamp01((0.62 - y) * 3);
    r = mix(accent[0], 224, sheen * 0.35);
    g = mix(accent[1], 242, sheen * 0.35);
    b = mix(accent[2], 254, sheen * 0.35);
  }
  // keyhole
  const hole = Math.hypot(x - 0.5, y - 0.6) - 0.028;
  if (hole <= 0) {
    r = 15;
    g = 23;
    b = 42;
  }
  return [r, g, b, 255];
}

function render(size, samples = 4) {
  const buf = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < samples; sy++) {
        for (let sx = 0; sx < samples; sx++) {
          const x = (px + (sx + 0.5) / samples) / size;
          const y = (py + (sy + 0.5) / samples) / size;
          const [sr, sg, sb, sa] = shade(x, y);
          const w = sa / 255;
          r += sr * w;
          g += sg * w;
          b += sb * w;
          a += sa;
        }
      }
      const n = samples * samples;
      const alpha = a / n;
      const norm = alpha > 0 ? alpha / 255 : 1;
      const i = (py * size + px) * 4;
      buf[i] = Math.round(r / n / norm);
      buf[i + 1] = Math.round(g / n / norm);
      buf[i + 2] = Math.round(b / n / norm);
      buf[i + 3] = Math.round(alpha);
    }
  }
  return buf;
}

function pngFor(size, samples) {
  return encodePng(size, size, render(size, samples));
}

/* ---------- ICO ---------- */

function buildIco(entries) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);
  let offset = 6 + entries.length * 16;
  const dir = [];
  for (const { size, data } of entries) {
    const e = Buffer.alloc(16);
    e[0] = size >= 256 ? 0 : size;
    e[1] = size >= 256 ? 0 : size;
    e[2] = 0;
    e[3] = 0;
    e.writeUInt16LE(1, 4);
    e.writeUInt16LE(32, 6);
    e.writeUInt32LE(data.length, 8);
    e.writeUInt32LE(offset, 12);
    dir.push(e);
    offset += data.length;
  }
  return Buffer.concat([header, ...dir, ...entries.map((e) => e.data)]);
}

const files = [
  [16, "16x16.png"],
  [32, "32x32.png"],
  [48, "48x48.png"],
  [128, "128x128.png"],
  [256, "128x128@2x.png"],
  [512, "icon.png"],
];

const generated = new Map();
for (const [size, name] of files) {
  const data = pngFor(size, size <= 48 ? 8 : 4);
  generated.set(size, data);
  writeFileSync(join(outDir, name), data);
}

writeFileSync(
  join(outDir, "icon.ico"),
  buildIco([16, 32, 48, 256].map((size) => ({ size, data: generated.get(size) }))),
);
writeFileSync(
  join(outDir, "StoreLogo.png"),
  pngFor(50, 4),
);

console.log("icons written to", outDir);
