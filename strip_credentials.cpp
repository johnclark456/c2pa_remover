// strip_credentials.cpp
//
// Bulk-remove Content Credentials (C2PA) from PSD / PSB / JPEG files.
//
//   JPEG  C2PA manifests live in APP11 (FFEB) JUMBF segments ("JP", box instance En, sequence Z).
//         Every APP11 segment belonging to a JUMBF box whose description box carries the C2PA
//         UUID is cut out. JPEG has no global length field, so nothing else needs patching.
//   PSD   Removes global tagged blocks keyed "CAI " (or --key), plus any global block whose
//   PSB   payload starts with the C2PA JUMBF signature. Only the Layer-and-Mask section length
//         field is patched; every other byte is copied as-is.
//
// Format is detected from magic bytes (not the extension) for named files; directory scans
// pick up .psd .psb .jpg .jpeg .jpe .jfif.
//
// Build:  g++ -std=c++17 -O2 -Wall -Wextra -o strip-credentials strip_credentials.cpp
//         cl /std:c++17 /O2 /EHsc strip_credentials.cpp
//
// PSD layout relied on (Adobe Photoshop File Formats spec):
//   Header(26) | ColorModeData(4+n) | ImageResources(4+n) |
//   LayerAndMask( len[4|8] | LayerInfo(len[4|8]+n) | GlobalMaskInfo(4+n) | tagged blocks... ) |
//   ImageData
//   tagged block = sig('8BIM'|'8B64') key(4) len[4|8] data pad

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

struct ParseError : std::runtime_error { using std::runtime_error::runtime_error; };

// ------------------------------------------------------------------ file access

class File {
public:
    explicit File(const fs::path& p) : f_(p, std::ios::binary) {
        if (!f_) throw std::runtime_error("cannot open for reading");
        f_.seekg(0, std::ios::end);
        size_ = static_cast<uint64_t>(f_.tellg());
    }
    uint64_t size() const { return size_; }

    void read(uint64_t off, void* buf, size_t n) {
        if (off > size_ || n > size_ - off) throw ParseError("read past end of file");
        f_.clear();
        f_.seekg(static_cast<std::streamoff>(off));
        f_.read(static_cast<char*>(buf), static_cast<std::streamsize>(n));
        if (!f_) throw std::runtime_error("read error");
    }
    uint64_t be(uint64_t off, int n) {
        uint8_t b[8] = {0};
        read(off, b, static_cast<size_t>(n));
        uint64_t v = 0;
        for (int i = 0; i < n; ++i) v = (v << 8) | b[i];
        return v;
    }
    std::string tag(uint64_t off) {
        char s[4];
        read(off, s, 4);
        return std::string(s, 4);
    }
    void copy_to(std::ostream& out, uint64_t from, uint64_t to) {
        std::vector<char> buf(1u << 20);
        while (from < to) {
            size_t n = static_cast<size_t>(std::min<uint64_t>(buf.size(), to - from));
            read(from, buf.data(), n);
            out.write(buf.data(), static_cast<std::streamsize>(n));
            if (!out) throw std::runtime_error("write error (disk full?)");
            from += n;
        }
    }

private:
    std::ifstream f_;
    uint64_t size_ = 0;
};

// off + len, checked against the file size
static uint64_t advance(const File& f, uint64_t off, uint64_t len) {
    if (off > f.size() || len > f.size() - off) throw ParseError("structure overruns file");
    return off + len;
}

// ------------------------------------------------------------------ shared types

struct Options {
    bool recursive = false, dryRun = false, list = false, backup = false, keepMtime = false, sniff = true;
    std::set<std::string> keys = {"CAI "};   // PSD/PSB only
};

// What to remove from one file, independent of format.
struct Plan {
    std::string format;                                  // "PSD", "PSB", "JPEG"
    std::string unit;                                    // what one cut is: "block" / "APP11 segment"
    std::vector<std::pair<uint64_t, uint64_t>> cuts;     // [start,end), sorted, disjoint
    uint64_t itemCount = 0;                              // blocks / JUMBF segments seen (for verification)
    bool patchLen = false;                               // PSD: Layer-and-Mask length field must shrink
    uint64_t lenOff = 0, lenValue = 0, lenNew = 0;
    int lenSize = 0;
    std::vector<std::string> listing, notes;
};

// C2PA JUMBF description-box UUID: "c2pa" 0011-0010-8000-00AA00389B71
static const uint8_t kC2paUuid[16] = {0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10,
                                      0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71};

static bool has_c2pa_uuid(File& f, uint64_t off, uint64_t len) {
    uint64_t n = std::min<uint64_t>(len, 256);
    if (n < sizeof kC2paUuid) return false;
    std::vector<uint8_t> b(static_cast<size_t>(n));
    f.read(off, b.data(), b.size());
    return std::search(b.begin(), b.end(), kC2paUuid, kC2paUuid + sizeof kC2paUuid) != b.end();
}

static std::string printable(const std::string& k) {
    std::string s;
    for (unsigned char c : k) s += std::isprint(c) ? static_cast<char>(c) : '?';
    return s;
}

// ------------------------------------------------------------------ PSD / PSB

struct Block {
    uint64_t start = 0;      // offset of the '8BIM' signature
    uint64_t end = 0;        // one past the padding
    uint64_t dataStart = 0;
    uint64_t dataLen = 0;
    std::string sig, key;
    bool hit = false;
    std::string why;
};

struct Layout {
    bool psb = false;
    uint64_t imgResStart = 0, imgResEnd = 0;
    uint64_t lmFieldOff = 0;  // offset of the Layer-and-Mask length field
    int lmFieldSize = 4;      // 4 (PSD) or 8 (PSB)
    uint64_t lmLen = 0;
    uint64_t lmEnd = 0;
    int pad = 4;              // padding multiple that parsed cleanly
    std::vector<Block> blocks;
};

// Keys whose length field is 8 bytes in PSB (spec list + keys seen in real PSB files).
static const std::set<std::string> kLongKeys = {
    "LMsk", "Lr16", "Lr32", "Layr", "Mt16", "Mt32", "Mtrn", "Alph", "FMsk",
    "lnk2", "lnk3", "lnkD", "lnkE", "FEid", "FXid", "PxSD", "cinf"};

// Parse the chain [start,end) as tagged blocks. Succeeds only if the chain tiles the range
// exactly and every block starts with a valid signature -- that is what makes the padding
// guess (4/2/1) self-validating rather than assumed.
static std::optional<std::vector<Block>> parse_blocks(File& f, uint64_t start, uint64_t end,
                                                      bool psb, int pad, bool clampLast) {
    std::vector<Block> out;
    uint64_t off = start;
    while (off < end) {
        if (end - off < 12) return std::nullopt;
        Block b;
        b.start = off;
        b.sig = f.tag(off);
        b.key = f.tag(off + 4);
        if (b.sig != "8BIM" && b.sig != "8B64") return std::nullopt;
        const int ls = (psb && kLongKeys.count(b.key)) ? 8 : 4;
        if (end - off < 8u + static_cast<unsigned>(ls)) return std::nullopt;
        b.dataLen = f.be(off + 8, ls);
        b.dataStart = off + 8 + static_cast<uint64_t>(ls);
        if (b.dataLen > end - b.dataStart) return std::nullopt;
        const uint64_t p = static_cast<uint64_t>(pad);
        uint64_t blockEnd = b.dataStart + (b.dataLen + p - 1) / p * p;
        if (blockEnd > end) {
            if (!clampLast) return std::nullopt;
            blockEnd = end;  // final block with its trailing pad omitted
        }
        b.end = blockEnd;
        out.push_back(b);
        off = blockEnd;
    }
    return out;
}

static Layout read_layout(File& f) {
    uint8_t h[26];
    f.read(0, h, sizeof h);
    if (std::memcmp(h, "8BPS", 4) != 0) throw ParseError("not a PSD/PSB (bad signature)");
    const unsigned ver = (static_cast<unsigned>(h[4]) << 8) | h[5];
    if (ver != 1 && ver != 2) throw ParseError("unknown PSD version");

    Layout L;
    L.psb = (ver == 2);
    L.lmFieldSize = L.psb ? 8 : 4;

    uint64_t off = advance(f, 26, 4 + f.be(26, 4));            // colour mode data
    L.imgResStart = off + 4;
    L.imgResEnd = advance(f, off, 4 + f.be(off, 4));           // image resources
    L.lmFieldOff = L.imgResEnd;
    L.lmLen = f.be(L.lmFieldOff, L.lmFieldSize);
    const uint64_t lmStart = advance(f, L.lmFieldOff, static_cast<uint64_t>(L.lmFieldSize));
    L.lmEnd = advance(f, lmStart, L.lmLen);
    if (L.lmLen == 0) return L;

    if (L.lmLen < static_cast<uint64_t>(L.lmFieldSize)) throw ParseError("layer-and-mask section too short");
    const uint64_t liLen = f.be(lmStart, L.lmFieldSize);
    if (liLen > L.lmLen - static_cast<uint64_t>(L.lmFieldSize)) throw ParseError("layer info overruns its section");
    uint64_t p = lmStart + static_cast<uint64_t>(L.lmFieldSize) + liLen;
    if (p == L.lmEnd) return L;
    if (L.lmEnd - p < 4) throw ParseError("truncated global layer mask info");
    const uint64_t gm = f.be(p, 4);
    if (gm > L.lmEnd - p - 4) throw ParseError("global layer mask info overruns its section");
    p += 4 + gm;

    for (bool clamp : {false, true})
        for (int pad : {4, 2, 1})
            if (auto r = parse_blocks(f, p, L.lmEnd, L.psb, pad, clamp)) {
                L.blocks = std::move(*r);
                L.pad = pad;
                return L;
            }
    throw ParseError("global tagged blocks do not tile the section (unexpected layout)");
}

// Read-only look at image resources for credential traces we deliberately do NOT remove.
static std::vector<std::string> scan_resources(File& f, const Layout& L) {
    std::vector<std::string> warn;
    try {
        uint64_t off = L.imgResStart;
        while (off <= L.imgResEnd && L.imgResEnd - off >= 12) {
            const std::string sig = f.tag(off);
            if (sig != "8BIM" && sig != "MeSa" && sig != "PHUT" && sig != "AgHg" && sig != "DCSR") break;
            const unsigned id = static_cast<unsigned>(f.be(off + 4, 2));
            uint8_t nl = 0;
            f.read(off + 6, &nl, 1);
            const uint64_t namePad = ((1u + nl) % 2) ? (2u + nl) : (1u + nl);
            const uint64_t lenOff = off + 6 + namePad;
            if (L.imgResEnd - lenOff < 4) break;
            const uint64_t len = f.be(lenOff, 4);
            const uint64_t data = lenOff + 4;
            if (len > L.imgResEnd - data) break;

            if (has_c2pa_uuid(f, data, len))
                warn.push_back("image resource " + std::to_string(id) + " carries a C2PA payload (not removed)");
            if (id == 1060 && len <= (8u << 20)) {
                std::string xmp(static_cast<size_t>(len), '\0');
                f.read(data, xmp.data(), xmp.size());
                if (xmp.find("dcterms:provenance") != std::string::npos)
                    warn.push_back("XMP contains dcterms:provenance (remote manifest link; XMP left untouched)");
            }
            off = data + len + (len & 1);
        }
    } catch (const std::exception&) {
        // best-effort diagnostics only
    }
    return warn;
}

static Plan analyze_psd(File& f, const Options& o) {
    Layout L = read_layout(f);
    Plan P;
    P.format = L.psb ? "PSB" : "PSD";
    P.unit = "block";
    P.itemCount = L.blocks.size();
    P.listing.push_back("  " + P.format + ", global blocks padded to " + std::to_string(L.pad));

    uint64_t removed = 0;
    for (auto& b : L.blocks) {
        if (o.keys.count(b.key)) { b.hit = true; b.why = "key"; }
        else if (o.sniff && has_c2pa_uuid(f, b.dataStart, b.dataLen)) {
            b.hit = true;
            b.why = "C2PA JUMBF signature in payload";
        }
        P.listing.push_back("    " + b.sig + ' ' + printable(b.key) + "  " + std::to_string(b.dataLen) + " bytes" +
                            (b.hit ? "   <-- would remove (" + b.why + ")" : ""));
        if (b.hit) { P.cuts.emplace_back(b.start, b.end); removed += b.end - b.start; }
    }
    P.notes = scan_resources(f, L);
    P.patchLen = true;
    P.lenOff = L.lmFieldOff;
    P.lenSize = L.lmFieldSize;
    P.lenValue = L.lmLen;
    P.lenNew = L.lmLen - removed;
    return P;
}

// ------------------------------------------------------------------ JPEG

static uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

// Walk the marker structure of the first image (SOI .. EOI), including every scan of a progressive
// file. Bytes after EOI (trailers, MPF images, ...) are never touched.
static Plan analyze_jpeg(File& f, const Options&) {
    if (f.size() > (1ull << 31)) throw ParseError("JPEG larger than 2 GiB; refusing to buffer it");
    std::vector<uint8_t> d(static_cast<size_t>(f.size()));
    f.read(0, d.data(), d.size());
    const size_t n = d.size();
    if (n < 4 || d[0] != 0xFF || d[1] != 0xD8) throw ParseError("not a JPEG (no SOI)");

    struct Seg { size_t start, end; uint16_t en; uint32_t z; size_t plen; bool c2pa; };
    std::vector<Seg> segs;
    bool xmpProvenance = false;

    size_t p = 2;
    while (p < n) {
        if (d[p] != 0xFF) throw ParseError("expected a marker at offset " + std::to_string(p));
        while (p < n && d[p] == 0xFF) ++p;                       // fill bytes
        if (p >= n) break;
        const size_t mpos = p;
        const uint8_t m = d[p++];
        if (m == 0x00) throw ParseError("invalid marker FF00 at offset " + std::to_string(mpos - 1));
        if (m == 0xD9) break;                                    // EOI
        if (m == 0x01 || (m >= 0xD0 && m <= 0xD8)) continue;    // markers without a length field

        if (n - p < 2) throw ParseError("truncated segment header");
        const size_t len = rd16(&d[p]);
        if (len < 2 || len > n - p) throw ParseError("segment length overruns file");
        const uint8_t* pay = &d[p + 2];
        const size_t plen = len - 2;

        if (m == 0xEB && plen >= 8 && pay[0] == 'J' && pay[1] == 'P') {
            // JUMBF in JPEG: "JP", En (box instance, 2 bytes), Z (packet sequence, 4 bytes), then box data.
            // The UUID sits in the first segment's description box, within the first few dozen bytes.
            const size_t w = std::min<size_t>(plen, 96);
            const bool c2pa = std::search(pay, pay + w, kC2paUuid, kC2paUuid + sizeof kC2paUuid) != pay + w;
            segs.push_back({mpos - 1, p + len, rd16(pay + 2), rd32(pay + 4), plen, c2pa});
        } else if (m == 0xE1 && !xmpProvenance) {
            static const char key[] = "dcterms:provenance";
            xmpProvenance = std::search(pay, pay + plen, key, key + sizeof key - 1) != pay + plen;
        }
        p += len;

        if (m == 0xDA) {                                         // SOS: skip entropy-coded data
            for (;;) {
                const void* q = (p < n) ? std::memchr(&d[p], 0xFF, n - p) : nullptr;
                if (!q) { p = n; break; }
                const size_t i = static_cast<size_t>(static_cast<const uint8_t*>(q) - d.data());
                size_t j = i + 1;
                while (j < n && d[j] == 0xFF) ++j;
                if (j >= n) { p = n; break; }
                if (d[j] == 0x00 || (d[j] >= 0xD0 && d[j] <= 0xD7)) { p = j + 1; continue; }  // stuffed / RSTn
                p = j - 1;                                       // the FF just before the next marker
                break;
            }
        }
    }

    std::set<uint16_t> c2paInstances;
    for (const auto& s : segs) if (s.c2pa) c2paInstances.insert(s.en);

    Plan P;
    P.format = "JPEG";
    P.unit = "APP11 segment";
    P.itemCount = segs.size();
    for (const auto& s : segs) {
        const bool hit = c2paInstances.count(s.en) != 0;
        P.listing.push_back("    APP11 JUMBF En=" + std::to_string(s.en) + " Z=" + std::to_string(s.z) + "  " +
                            std::to_string(s.plen) + " bytes" + (hit ? "   <-- would remove (C2PA manifest store)" : ""));
        if (hit) P.cuts.emplace_back(s.start, s.end);
    }
    if (segs.empty()) P.listing.push_back("    no APP11 JUMBF segments");
    if (xmpProvenance)
        P.notes.push_back("XMP contains dcterms:provenance (remote manifest link; XMP left untouched)");
    return P;
}

// ------------------------------------------------------------------ dispatch + processing

static Plan analyze(File& f, const Options& o) {
    uint8_t m[4] = {0};
    if (f.size() < 4) throw ParseError("file too small");
    f.read(0, m, 4);
    if (std::memcmp(m, "8BPS", 4) == 0) return analyze_psd(f, o);
    if (m[0] == 0xFF && m[1] == 0xD8 && m[2] == 0xFF) return analyze_jpeg(f, o);
    throw ParseError("unrecognized format (not PSD/PSB/JPEG)");
}

enum class Kind { Clean, Stripped, WouldStrip, Listed, Error };

struct Result {
    Kind kind = Kind::Clean;
    size_t items = 0;
    uint64_t bytes = 0;
    std::string unit, msg;
};

static void put_be(std::ostream& o, uint64_t v, int n) {
    char b[8];
    for (int i = n - 1; i >= 0; --i) { b[i] = static_cast<char>(v & 0xFF); v >>= 8; }
    o.write(b, n);
}

static Result process(const fs::path& given, const Options& o) {
    Result r;
    // A symlink is stripped through to its target; renaming a temp file over the link itself
    // would swap the link for a regular file and leave the target's credentials in place.
    fs::path path = given;
    {
        std::error_code ec;
        if (fs::is_symlink(given, ec)) {
            fs::path real = fs::canonical(given, ec);
            if (!ec) path = real;
        }
    }
    fs::path tmp = path;
    tmp += ".cai-strip.tmp";
    bool tmpCreated = false;
    try {
        Plan P;
        uint64_t origSize = 0;
        uint64_t removed = 0;
        {
            File in(path);
            P = analyze(in, o);
            origSize = in.size();
            r.unit = P.unit;

            if (o.list) {
                for (const auto& l : P.listing) std::cout << l << "\n";
                for (const auto& w : P.notes) std::cout << "    [note] " << w << "\n";
                r.kind = Kind::Listed;
                return r;
            }
            for (const auto& w : P.notes) std::cout << "  [note] " << w << "\n";
            if (P.cuts.empty()) { r.msg = "no matching " + P.format + " " + P.unit + "s"; return r; }

            for (const auto& c : P.cuts) removed += c.second - c.first;
            r.items = P.cuts.size();
            r.bytes = removed;
            if (o.dryRun) { r.kind = Kind::WouldStrip; return r; }

            const fs::file_time_type mtime = fs::last_write_time(path);
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) throw std::runtime_error("cannot create temp file");
            tmpCreated = true;

            uint64_t cur = 0;
            if (P.patchLen) {                                   // PSD: the only edited field
                in.copy_to(out, 0, P.lenOff);
                put_be(out, P.lenNew, P.lenSize);
                cur = P.lenOff + static_cast<uint64_t>(P.lenSize);
            }
            for (const auto& c : P.cuts) { in.copy_to(out, cur, c.first); cur = c.second; }
            in.copy_to(out, cur, in.size());
            out.flush();
            if (!out) throw std::runtime_error("write error (disk full?)");
            out.close();

            std::error_code ec;
            fs::permissions(tmp, fs::status(path).permissions(), ec);
            if (o.keepMtime) fs::last_write_time(tmp, mtime, ec);
        }

        // Re-parse the output with the same analyzer before it can replace anything.
        {
            File chk(tmp);
            if (chk.size() != origSize - removed) throw std::runtime_error("verify: unexpected output size");
            Plan V = analyze(chk, o);
            if (V.format != P.format) throw std::runtime_error("verify: format changed");
            if (!V.cuts.empty()) throw std::runtime_error("verify: matching data still present");
            if (V.itemCount != P.itemCount - P.cuts.size()) throw std::runtime_error("verify: item count mismatch");
            if (P.patchLen && V.lenValue != P.lenNew) throw std::runtime_error("verify: section length mismatch");
        }

        if (o.backup) {
            fs::path bak = path;
            bak += ".bak";
            if (fs::exists(bak)) throw std::runtime_error("backup already exists: " + bak.string());
            fs::rename(path, bak);
            try { fs::rename(tmp, path); }
            catch (...) { std::error_code ec; fs::rename(bak, path, ec); throw; }
        } else {
            fs::rename(tmp, path);
        }
        tmpCreated = false;
        r.kind = Kind::Stripped;
    } catch (const std::exception& e) {
        r.kind = Kind::Error;
        r.msg = e.what();
    }
    if (tmpCreated) { std::error_code ec; fs::remove(tmp, ec); }
    return r;
}

// ------------------------------------------------------------------ CLI

static void usage(const char* argv0) {
    std::cerr <<
        "Usage: " << argv0 << " [options] <file-or-directory>...\n"
        "Removes C2PA Content Credentials from PSD, PSB and JPEG files.\n"
        "  -r, --recursive   descend into subdirectories\n"
        "  -n, --dry-run     report what would be removed; modify nothing\n"
        "  -l, --list        list what was found per file; modify nothing\n"
        "      --backup      keep each original as <name>.bak\n"
        "      --keep-mtime  preserve the modification time\n"
        "PSD/PSB only:\n"
        "      --key KEY     also remove this tagged-block key (4 chars, 3 chars = pad with space,\n"
        "                    or 8 hex digits). Repeatable.\n"
        "      --no-sniff    only match by key; skip the C2PA-signature payload check\n"
        "  -h, --help\n";
}

static bool parse_key(const std::string& a, std::string& out) {
    if (a.size() == 4) { out = a; return true; }
    if (a.size() == 3) { out = a + ' '; return true; }
    if (a.size() == 8 && std::all_of(a.begin(), a.end(), [](unsigned char c) { return std::isxdigit(c); })) {
        out.clear();
        for (size_t i = 0; i < 8; i += 2) out += static_cast<char>(std::stoi(a.substr(i, 2), nullptr, 16));
        return true;
    }
    return false;
}

static bool is_supported_ext(const fs::path& p) {
    std::string e = p.extension().string();
    std::transform(e.begin(), e.end(), e.begin(), [](unsigned char c) { return std::tolower(c); });
    return e == ".psd" || e == ".psb" || e == ".jpg" || e == ".jpeg" || e == ".jpe" || e == ".jfif";
}

int run(int argc, char** argv) {
    Options o;
    std::vector<fs::path> inputs;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-r" || a == "--recursive") o.recursive = true;
        else if (a == "-n" || a == "--dry-run") o.dryRun = true;
        else if (a == "-l" || a == "--list") o.list = true;
        else if (a == "--backup") o.backup = true;
        else if (a == "--keep-mtime") o.keepMtime = true;
        else if (a == "--no-sniff") o.sniff = false;
        else if (a == "--key") {
            std::string k;
            if (i + 1 >= argc || !parse_key(argv[++i], k)) { std::cerr << "bad --key\n"; return 2; }
            o.keys.insert(k);
        } else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else if (!a.empty() && a[0] == '-') { std::cerr << "unknown option: " << a << "\n"; usage(argv[0]); return 2; }
        else inputs.emplace_back(a);
    }
    if (inputs.empty()) { usage(argv[0]); return 2; }

    // Collect first: we rename files while processing, which must not disturb a live directory iterator.
    std::set<fs::path> files;
    int errors = 0;
    for (const auto& in : inputs) {
        std::error_code ec;
        if (fs::is_regular_file(in, ec)) { files.insert(in); continue; }
        if (!fs::is_directory(in, ec)) { std::cerr << "[error] " << in.string() << ": not a file or directory\n"; ++errors; continue; }
        auto take = [&](const fs::path& p, bool reg) { if (reg && is_supported_ext(p)) files.insert(p); };
        std::error_code e2;
        if (o.recursive) {
            for (fs::recursive_directory_iterator it(in, fs::directory_options::skip_permission_denied, e2), end;
                 !e2 && it != end; it.increment(e2))
                take(it->path(), it->is_regular_file(e2));
        } else {
            for (fs::directory_iterator it(in, fs::directory_options::skip_permission_denied, e2), end;
                 !e2 && it != end; it.increment(e2))
                take(it->path(), it->is_regular_file(e2));
        }
        if (e2) { std::cerr << "[error] " << in.string() << ": " << e2.message() << "\n"; ++errors; }
    }

    int stripped = 0, clean = 0, would = 0;
    uint64_t bytes = 0;
    for (const auto& p : files) {
        if (o.list) std::cout << p.string() << "\n";
        Result r = process(p, o);
        switch (r.kind) {
            case Kind::Stripped:
                std::cout << "[stripped] " << p.string() << ": " << r.items << ' ' << r.unit << "(s), " << r.bytes << " bytes\n";
                ++stripped; bytes += r.bytes; break;
            case Kind::WouldStrip:
                std::cout << "[would strip] " << p.string() << ": " << r.items << ' ' << r.unit << "(s), " << r.bytes << " bytes\n";
                ++would; bytes += r.bytes; break;
            case Kind::Clean:
                std::cout << "[unchanged] " << p.string() << ": " << r.msg << "\n";
                ++clean; break;
            case Kind::Listed: break;
            case Kind::Error:
                std::cerr << "[error] " << p.string() << ": " << r.msg << "\n";
                ++errors; break;
        }
    }
    if (!o.list) {
        std::cout << "\n" << files.size() << " file(s): " << stripped << " stripped, " << would << " would strip, "
                  << clean << " unchanged, " << errors << " error(s); " << bytes << " bytes "
                  << (o.dryRun ? "removable" : "removed") << "\n";
        if (stripped + would == 0 && clean > 0)
            std::cout << "Nothing matched. Run with --list on a file you know carries credentials to see what it contains.\n";
    }
    return errors ? 1 : 0;
}

#ifndef STRIP_CREDENTIALS_NO_MAIN   // the unit tests include this file and supply their own main()
int main(int argc, char** argv) { return run(argc, argv); }
#endif
