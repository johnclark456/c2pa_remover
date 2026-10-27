// test_strip_credentials.cpp -- unit + property tests for strip_credentials.cpp
//
//   bazel test //:strip_credentials_test                     build and run
//   bazel test --config=asan //:strip_credentials_test       same, under AddressSanitizer + UBSan
//   bazel test //:strip_credentials_test --test_arg=jpeg     only tests whose name contains "jpeg"
//
// No external framework. The tests #include the tool's source directly so they can reach its
// internals (analyze, process, run, ...). Test files are built from scratch by the builders
// below -- not with the tool's own parser -- so "expected output" is independent of the code
// under test: expected = the same file rebuilt without the credential bytes.

#define STRIP_CREDENTIALS_NO_MAIN
#include "strip_credentials.cpp"

#include <chrono>
#include <cstdlib>
#include <random>
#include <sstream>

using Bytes = std::vector<uint8_t>;

// ============================================================ mini framework

struct TestAbort {};
static int g_checks = 0, g_failures = 0;
static std::string g_current;

struct Registered { std::string name; void (*fn)(); };
static std::vector<Registered>& registry() { static std::vector<Registered> r; return r; }
struct Registrar { Registrar(const char* n, void (*f)()) { registry().push_back({n, f}); } };

#define TEST(name) static void name(); static Registrar reg_##name(#name, name); static void name()

#define CHECK_MSG(cond, msg)                                                                          \
    do {                                                                                              \
        ++g_checks;                                                                                   \
        if (!(cond)) {                                                                                \
            ++g_failures;                                                                             \
            std::cerr << "  FAIL " << g_current << " @ line " << __LINE__ << ": " << msg << "\n";      \
        }                                                                                             \
    } while (0)
#define CHECK(cond) CHECK_MSG(cond, #cond)
#define REQUIRE(cond)                                                                                 \
    do {                                                                                              \
        ++g_checks;                                                                                   \
        if (!(cond)) {                                                                                \
            ++g_failures;                                                                             \
            std::cerr << "  FAIL(fatal) " << g_current << " @ line " << __LINE__ << ": " #cond "\n";  \
            throw TestAbort{};                                                                        \
        }                                                                                             \
    } while (0)

static void check_bytes(const Bytes& actual, const Bytes& expected, const char* what, int line) {
    ++g_checks;
    if (actual == expected) return;
    ++g_failures;
    size_t i = 0;
    while (i < actual.size() && i < expected.size() && actual[i] == expected[i]) ++i;
    std::cerr << "  FAIL " << g_current << " @ line " << line << ": " << what << " differs (sizes "
              << actual.size() << " vs " << expected.size() << ", first mismatch at offset " << i << ")\n";
}
#define CHECK_BYTES(actual, expected) check_bytes((actual), (expected), #actual " == " #expected, __LINE__)

static const char* kind_name(Kind k) {
    switch (k) {
        case Kind::Clean: return "Clean";
        case Kind::Stripped: return "Stripped";
        case Kind::WouldStrip: return "WouldStrip";
        case Kind::Listed: return "Listed";
        case Kind::Error: return "Error";
    }
    return "?";
}
static void check_kind(const Result& r, Kind want, int line) {
    ++g_checks;
    if (r.kind == want) return;
    ++g_failures;
    std::cerr << "  FAIL " << g_current << " @ line " << line << ": expected " << kind_name(want) << ", got "
              << kind_name(r.kind) << " (" << r.msg << ")\n";
}
#define CHECK_KIND(r, k) check_kind((r), (k), __LINE__)

static bool contains(const std::string& hay, const std::string& needle) { return hay.find(needle) != std::string::npos; }
static bool any_contains(const std::vector<std::string>& v, const std::string& needle) {
    for (const auto& s : v) if (contains(s, needle)) return true;
    return false;
}

// ============================================================ file helpers

struct TempDir {
    fs::path path;
    TempDir() {
        static int n = 0;
        std::random_device rd;
        // Bazel hands each test a private scratch dir via TEST_TMPDIR; otherwise use the system temp dir.
        const char* scratch = std::getenv("TEST_TMPDIR");
        const fs::path base = (scratch && *scratch) ? fs::path(scratch) : fs::temp_directory_path();
        path = base / ("strip-cred-test-" + std::to_string(rd()) + "-" + std::to_string(++n));
        fs::create_directories(path);
    }
    ~TempDir() { std::error_code ec; fs::remove_all(path, ec); }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    fs::path operator/(const std::string& s) const { return path / s; }
};

static void write_file(const fs::path& p, const Bytes& b) {
    if (p.has_parent_path()) fs::create_directories(p.parent_path());
    std::ofstream o(p, std::ios::binary | std::ios::trunc);
    o.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}
static Bytes read_file(const fs::path& p) {
    std::ifstream i(p, std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(i)), std::istreambuf_iterator<char>());
}
static bool no_tmp_files(const fs::path& dir) {
    for (const auto& e : fs::recursive_directory_iterator(dir))
        if (e.path().extension() == ".tmp") return false;
    return true;
}

// Analyze raw bytes through the real analyzer (throws ParseError like the tool does).
static Plan analyze_bytes(const Bytes& b, const Options& o = Options{}) {
    TempDir d;
    const fs::path p = d / "a.bin";
    write_file(p, b);
    File f(p);
    return analyze(f, o);
}
static bool throws_parse_error(const Bytes& b) {
    try { analyze_bytes(b); }
    catch (const ParseError&) { return true; }
    catch (...) { return false; }
    return false;
}

// ============================================================ byte builders

static Bytes B(const std::string& s) { return Bytes(s.begin(), s.end()); }
static void add(Bytes& a, const Bytes& b) { a.insert(a.end(), b.begin(), b.end()); }
static Bytes cat(std::initializer_list<Bytes> parts) { Bytes r; for (const auto& p : parts) add(r, p); return r; }
static Bytes be(uint64_t v, int n) {
    Bytes r(static_cast<size_t>(n));
    for (int i = n - 1; i >= 0; --i) { r[static_cast<size_t>(i)] = static_cast<uint8_t>(v & 0xFF); v >>= 8; }
    return r;
}
static Bytes seq(size_t n) { Bytes b(n); for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>(i); return b; }

// The C2PA JUMBF UUID, typed out independently of the tool's own constant.
static Bytes uuid_c2pa() {
    return {0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71};
}
static Bytes uuid_other() { Bytes b(16); for (size_t i = 0; i < 16; ++i) b[i] = static_cast<uint8_t>(0xA0 + i); return b; }

// ---------------------------------------------------------------- PSD / PSB

// Keys with an 8-byte length in PSB: the spec's list, plus two reported from real PSB files.
static const std::set<std::string> kTestLong = {"LMsk", "Lr16", "Lr32", "Layr", "Mt16", "Mt32", "Mtrn", "Alph",
                                                "FMsk", "lnk2", "FEid", "FXid", "PxSD", "cinf", "lnkE"};

struct PsdSpec {
    bool psb = false;
    int pad = 4;                    // padding multiple for global tagged blocks
    bool trimLastPad = false;       // omit the final block's trailing pad
    bool emptySection = false;      // Layer-and-Mask length = 0
    bool omitGlobalMask = false;    // section ends right after layer info
    Bytes layerInfoBody = Bytes(6, 0xAB);
    std::vector<std::pair<int, Bytes>> resources;               // image resources (id, data)
    std::vector<std::pair<std::string, Bytes>> blocks;          // global tagged blocks
};

struct Built {
    Bytes data;
    size_t sectionEnd = 0, lmFieldOff = 0;
    std::vector<std::pair<size_t, size_t>> blockRanges;         // [start,end) incl. padding
};

static Built build_psd(const PsdSpec& s) {
    Built b;
    Bytes& out = b.data;
    add(out, B("8BPS"));
    add(out, be(s.psb ? 2 : 1, 2));
    add(out, Bytes(6, 0));
    add(out, be(3, 2)); add(out, be(8, 4)); add(out, be(8, 4)); add(out, be(8, 2)); add(out, be(3, 2));
    add(out, be(0, 4));                                          // colour mode data

    Bytes res;
    for (const auto& r : s.resources) {
        add(res, B("8BIM")); add(res, be(static_cast<uint64_t>(r.first), 2)); add(res, Bytes{0, 0});
        add(res, be(r.second.size(), 4)); add(res, r.second);
        if (r.second.size() & 1) res.push_back(0);
    }
    add(out, be(res.size(), 4)); add(out, res);

    const int ls = s.psb ? 8 : 4;
    b.lmFieldOff = out.size();
    Bytes lm;
    if (!s.emptySection) {
        add(lm, be(s.layerInfoBody.size(), ls)); add(lm, s.layerInfoBody);
        if (!s.omitGlobalMask) {
            add(lm, be(0, 4));
            for (size_t i = 0; i < s.blocks.size(); ++i) {
                const auto& blk = s.blocks[i];
                const size_t start = b.lmFieldOff + static_cast<size_t>(ls) + lm.size();
                add(lm, B("8BIM")); add(lm, B(blk.first));
                add(lm, be(blk.second.size(), (s.psb && kTestLong.count(blk.first)) ? 8 : 4));
                add(lm, blk.second);
                const size_t p = static_cast<size_t>(s.pad);
                if (!(i + 1 == s.blocks.size() && s.trimLastPad)) add(lm, Bytes((p - blk.second.size() % p) % p, 0));
                b.blockRanges.emplace_back(start, b.lmFieldOff + static_cast<size_t>(ls) + lm.size());
            }
        }
    }
    add(out, be(lm.size(), ls)); add(out, lm);
    b.sectionEnd = out.size();
    add(out, be(0, 2));                                          // image data: raw compression + pixels
    for (int i = 0; i < 100; ++i) out.push_back(static_cast<uint8_t>((i * 7) % 256));
    return b;
}

static PsdSpec base_spec(bool psb) {
    PsdSpec s;
    s.psb = psb;
    s.resources = {{1005, Bytes(16, 0)}, {1060, B("<x:xmpmeta>plain</x:xmpmeta>")}};
    s.blocks = {{"luni", B("hello")}, {"CAI ", seq(77)}, {"Lr16", B("0123456789")}, {"tail", B("xxxxxxxxx")}};
    return s;
}
static PsdSpec without(PsdSpec s, const std::set<std::string>& keys) {
    s.blocks.erase(std::remove_if(s.blocks.begin(), s.blocks.end(),
                                  [&](const std::pair<std::string, Bytes>& b) { return keys.count(b.first) != 0; }),
                   s.blocks.end());
    return s;
}

// Strip `in` with the given options and require the result to equal the rebuilt `expected`.
static void expect_psd_strip(const PsdSpec& in, const PsdSpec& expected, const Options& o = Options{}) {
    TempDir d;
    const fs::path p = d / "x.psd";
    write_file(p, build_psd(in).data);
    Result r = process(p, o);
    CHECK_KIND(r, Kind::Stripped);
    CHECK_BYTES(read_file(p), build_psd(expected).data);
    CHECK(no_tmp_files(d.path));
}

// ---------------------------------------------------------------- JPEG

static Bytes soi() { return {0xFF, 0xD8}; }
static Bytes eoi() { return {0xFF, 0xD9}; }
static Bytes seg(uint8_t marker, const Bytes& payload) {
    Bytes r{0xFF, marker};
    add(r, be(payload.size() + 2, 2));
    add(r, payload);
    return r;
}
static Bytes sos(const Bytes& entropy) { return cat({seg(0xDA, Bytes{1, 1, 0, 0, 63, 0}), entropy}); }
static Bytes entropy() { return {0x12, 0x34, 0xFF, 0x00, 0x56, 0xFF, 0xD0, 0x78, 0xFF, 0x00, 0xFF, 0xD3, 0x9A}; }

static Bytes app11(uint16_t en, uint32_t z, const Bytes& body) {
    Bytes p = B("JP");
    add(p, be(en, 2)); add(p, be(z, 4)); add(p, body);
    return seg(0xEB, p);
}
static Bytes jumd(const Bytes& uuid, const std::string& label) {
    Bytes body = uuid;
    body.push_back(0x03);
    add(body, B(label));
    body.push_back(0);
    Bytes r = be(8 + body.size(), 4);
    add(r, B("jumd")); add(r, body);
    return r;
}
static Bytes jumb_hdr(uint32_t n) { Bytes r = be(n, 4); add(r, B("jumb")); return r; }

// A C2PA manifest store split over `n` APP11 segments (box instance `en`, sequence Z = 1..n).
static std::vector<Bytes> c2pa_segments(uint16_t en, int n = 3) {
    std::vector<Bytes> v;
    v.push_back(app11(en, 1, cat({jumb_hdr(5000), jumd(uuid_c2pa(), "c2pa"), Bytes(200, 'A')})));
    for (int z = 2; z <= n; ++z)
        v.push_back(app11(en, static_cast<uint32_t>(z), cat({jumb_hdr(5000), Bytes(150, static_cast<uint8_t>(64 + z))})));
    return v;
}
// An unrelated JUMBF box (different UUID), `n` segments long.
static std::vector<Bytes> decoy_segments(uint16_t en = 9, int n = 1) {
    std::vector<Bytes> v;
    v.push_back(app11(en, 1, cat({jumb_hdr(300), jumd(uuid_other(), "other"), Bytes(40, 'Z')})));
    for (int z = 2; z <= n; ++z) v.push_back(app11(en, static_cast<uint32_t>(z), cat({jumb_hdr(300), Bytes(30, 'Y')})));
    return v;
}
static Bytes non_jp_app11() { return seg(0xEB, B("XXunrelated-app11-data")); }
static Bytes xmp_segment(bool provenance) {
    std::string x = provenance ? "<x:xmpmeta><rdf:Description dcterms:provenance=\"https://example.invalid/m.c2pa\"/></x:xmpmeta>"
                               : "<x:xmpmeta><rdf:Description dc:title=\"t\"/></x:xmpmeta>";
    Bytes p = B("http://ns.adobe.com/xap/1.0/");
    p.push_back(0);
    add(p, B(x));
    return seg(0xE1, p);
}
static Bytes jfif() { return seg(0xE0, Bytes{'J', 'F', 'I', 'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0}); }
static Bytes dqt() { return seg(0xDB, Bytes(65, 3)); }
static Bytes sof() { return seg(0xC0, Bytes(15, 1)); }

struct Pair { Bytes in, expected; };

// Manifest in three non-adjacent segments, mixed with a decoy JUMBF box and a non-JP APP11.
static Pair jpeg_pair() {
    auto c = c2pa_segments(1);
    Bytes dec = decoy_segments()[0], njp = non_jp_app11();
    Pair p;
    p.in = cat({soi(), jfif(), c[0], dec, c[1], njp, c[2], dqt(), sof(), sos(entropy()), eoi()});
    p.expected = cat({soi(), jfif(), dec, njp, dqt(), sof(), sos(entropy()), eoi()});
    return p;
}
static void expect_jpeg_strip(const Bytes& in, const Bytes& expected, size_t expectSegments = 0) {
    TempDir d;
    const fs::path p = d / "x.jpg";
    write_file(p, in);
    Result r = process(p, Options{});
    CHECK_KIND(r, Kind::Stripped);
    if (expectSegments) CHECK(r.items == expectSegments);
    CHECK_BYTES(read_file(p), expected);
    CHECK(no_tmp_files(d.path));
}

// A malformed file must be reported as an error and left byte-for-byte alone.
static void expect_error_untouched(const Bytes& bad, const std::string& label) {
    TempDir d;
    const fs::path p = d / "bad.bin";
    write_file(p, bad);
    Result r = process(p, Options{});
    CHECK_MSG(r.kind == Kind::Error, label << ": expected Error, got " << kind_name(r.kind));
    CHECK_MSG(read_file(p) == bad, label << ": file was modified");
    CHECK_MSG(no_tmp_files(d.path), label << ": temp file left behind");
}

// ---------------------------------------------------------------- CLI capture

struct Cli { int rc = 0; std::string out, err; };
static Cli cli(std::vector<std::string> args) {
    args.insert(args.begin(), "strip-credentials");
    std::vector<char*> argv;
    for (auto& a : args) argv.push_back(a.data());
    argv.push_back(nullptr);
    std::ostringstream o, e;
    std::streambuf* so = std::cout.rdbuf(o.rdbuf());
    std::streambuf* se = std::cerr.rdbuf(e.rdbuf());
    Cli c;
    try { c.rc = run(static_cast<int>(args.size()), argv.data()); }
    catch (...) { std::cout.rdbuf(so); std::cerr.rdbuf(se); throw; }
    std::cout.rdbuf(so);
    std::cerr.rdbuf(se);
    c.out = o.str();
    c.err = e.str();
    return c;
}

// ============================================================ small helpers

TEST(be_readers_and_writer) {
    const uint8_t b[4] = {0x12, 0x34, 0x56, 0x78};
    CHECK(rd16(b) == 0x1234);
    CHECK(rd32(b) == 0x12345678u);
    std::ostringstream o;
    put_be(o, 0x0102030405060708ULL, 8);
    put_be(o, 0x0A0B, 2);
    CHECK(o.str() == std::string("\x01\x02\x03\x04\x05\x06\x07\x08\x0A\x0B", 10));
}

TEST(parse_key_accepts_documented_forms) {
    std::string k;
    CHECK(parse_key("CAI ", k) && k == "CAI ");
    CHECK(parse_key("CAI", k) && k == "CAI ");           // 3 chars: padded with a space
    CHECK(parse_key("43414920", k) && k == "CAI ");      // 8 hex digits
    CHECK(!parse_key("", k));
    CHECK(!parse_key("abcde", k));
    CHECK(!parse_key("zzzzzzzz", k));                    // 8 chars but not hex
}

TEST(supported_extensions) {
    for (const char* ok : {"a.psd", "a.PSD", "a.psb", "a.jpg", "a.JPG", "a.jpeg", "a.jpe", "a.jfif"})
        CHECK_MSG(is_supported_ext(ok), ok);
    for (const char* no : {"a.png", "a.txt", "a.bak", "a", "a.psd.bak", "a.psd.tmp"})
        CHECK_MSG(!is_supported_ext(no), no);
}

TEST(printable_masks_control_bytes) { CHECK(printable(std::string("a\x01" "b\xFF", 4)) == "a?b?"); }

TEST(dispatch_rejects_unknown_and_tiny_inputs) {
    CHECK(throws_parse_error({}));
    CHECK(throws_parse_error({0xFF, 0xD8, 0xFF}));                          // 3 bytes
    CHECK(throws_parse_error(B("\x89PNG\r\n\x1a\n")));
    CHECK(throws_parse_error({0xFF, 0xD8, 0x00, 0x00, 0x00}));              // SOI not followed by a marker
}

// ============================================================ PSD / PSB

TEST(psd_cuts_and_length_patch_are_exact) {
    Built b = build_psd(base_spec(false));
    Plan P = analyze_bytes(b.data);
    CHECK(P.format == "PSD");
    CHECK(P.unit == "block");
    CHECK(P.itemCount == 4);
    REQUIRE(P.cuts.size() == 1);
    CHECK(P.cuts[0] == b.blockRanges[1]);                                   // exactly the CAI block + padding
    CHECK(P.patchLen);
    CHECK(P.lenOff == b.lmFieldOff);
    CHECK(P.lenSize == 4);
    CHECK(P.lenNew == P.lenValue - (b.blockRanges[1].second - b.blockRanges[1].first));
}

TEST(psd_strip_removes_cai_block) { expect_psd_strip(base_spec(false), without(base_spec(false), {"CAI "})); }

TEST(psb_strip_removes_cai_block_with_8byte_lengths) {
    Plan P = analyze_bytes(build_psd(base_spec(true)).data);
    CHECK(P.format == "PSB");
    CHECK(P.lenSize == 8);
    expect_psd_strip(base_spec(true), without(base_spec(true), {"CAI "}));
}

TEST(psb_long_length_keys_cinf_lnkE_are_walked_correctly) {
    PsdSpec s = base_spec(true);
    s.blocks.insert(s.blocks.begin(), {"cinf", seq(20)});
    s.blocks.push_back({"lnkE", seq(33)});
    s.blocks.push_back({"CAI ", seq(11)});                                   // a second CAI after the 8-byte-length keys
    expect_psd_strip(s, without(s, {"CAI "}));
}

TEST(psd_final_block_with_omitted_pad) {
    PsdSpec s;
    s.trimLastPad = true;
    s.blocks = {{"luni", B("hello")}, {"Lr16", B("0123456789")}, {"CAI ", seq(77)}};
    PsdSpec e = without(s, {"CAI "});
    e.trimLastPad = false;
    expect_psd_strip(s, e);
}

TEST(psd_global_blocks_padded_to_2_and_1) {
    for (int pad : {2, 1}) {
        PsdSpec s = base_spec(false);
        s.pad = pad;
        Plan P = analyze_bytes(build_psd(s).data);
        CHECK_MSG(P.listing[0].find("padded to " + std::to_string(pad)) != std::string::npos, P.listing[0]);
        expect_psd_strip(s, without(s, {"CAI "}));
    }
}

TEST(psd_first_last_and_only_blocks) {
    PsdSpec s;
    s.blocks = {{"CAI ", seq(5)}, {"luni", B("hello")}, {"CAI ", seq(9)}};   // credentials at both ends
    expect_psd_strip(s, without(s, {"CAI "}));
    PsdSpec only;
    only.blocks = {{"CAI ", seq(77)}};                                       // nothing left afterwards
    expect_psd_strip(only, without(only, {"CAI "}));
}

TEST(psd_sniffing_finds_c2pa_payload_under_unknown_key) {
    PsdSpec s = base_spec(false);
    s.blocks.push_back({"zzzz", cat({Bytes(8, 0), uuid_c2pa(), Bytes(16, 1)})});
    expect_psd_strip(s, without(s, {"CAI ", "zzzz"}));

    Options noSniff;
    noSniff.sniff = false;
    expect_psd_strip(s, without(s, {"CAI "}), noSniff);                      // key match only
}

TEST(psd_sniffing_window_is_first_256_bytes) {
    PsdSpec s;
    s.blocks = {{"zzzz", cat({Bytes(300, 0), uuid_c2pa()})}, {"yyyy", cat({Bytes(200, 0), uuid_c2pa()})}};
    expect_psd_strip(s, without(s, {"yyyy"}));                               // inside window -> removed, beyond -> kept
}

TEST(psd_custom_key_option) {
    PsdSpec s = base_spec(false);
    s.blocks.push_back({"abcd", seq(10)});
    Options o;
    o.keys.insert("abcd");
    expect_psd_strip(s, without(s, {"CAI ", "abcd"}), o);
}

TEST(psd_without_credentials_is_untouched) {
    TempDir d;
    const fs::path p = d / "x.psd";
    Bytes data = build_psd(without(base_spec(false), {"CAI "})).data;
    write_file(p, data);
    Result r = process(p, Options{});
    CHECK_KIND(r, Kind::Clean);
    CHECK_BYTES(read_file(p), data);
}

TEST(psd_sections_that_have_no_tagged_blocks) {
    PsdSpec a; a.emptySection = true;
    PsdSpec b; b.omitGlobalMask = true;
    for (const PsdSpec& s : {a, b}) {
        Plan P = analyze_bytes(build_psd(s).data);
        CHECK(P.cuts.empty());
        CHECK(P.itemCount == 0);
    }
}

TEST(psd_xmp_provenance_is_reported_not_modified) {
    PsdSpec s = base_spec(false);
    s.resources[1].second = B("<x:xmpmeta dcterms:provenance=\"https://example.invalid/m.c2pa\"/>");
    CHECK(any_contains(analyze_bytes(build_psd(s).data).notes, "dcterms:provenance"));
    expect_psd_strip(s, without(s, {"CAI "}));                               // exact bytes => XMP resource preserved
    CHECK(!any_contains(analyze_bytes(build_psd(base_spec(false)).data).notes, "dcterms:provenance"));
}

TEST(psd_image_resource_with_c2pa_payload_is_reported_not_removed) {
    PsdSpec s = base_spec(false);
    s.resources.push_back({1234, cat({Bytes(4, 0), uuid_c2pa(), Bytes(8, 7)})});
    CHECK(any_contains(analyze_bytes(build_psd(s).data).notes, "image resource 1234"));
    expect_psd_strip(s, without(s, {"CAI "}));
}

TEST(psd_malformed_structures_are_rejected_untouched) {
    const Built good = build_psd(base_spec(false));
    { Bytes b = good.data; b[3] = 'X';                              expect_error_untouched(b, "bad magic"); }
    { Bytes b = good.data; b[5] = 3;                                expect_error_untouched(b, "version 3"); }
    { Bytes b = good.data; b[good.blockRanges[1].first] = 'X';      expect_error_untouched(b, "corrupt block signature"); }
    { Bytes b = good.data; for (int i = 0; i < 4; ++i) b[good.blockRanges[1].first + 8 + i] = 0xFF;
                                                                    expect_error_untouched(b, "block length overruns section"); }
    { Bytes b = good.data; for (int i = 0; i < 4; ++i) b[good.lmFieldOff + i] = 0xFF;
                                                                    expect_error_untouched(b, "section length overruns file"); }
    { Bytes b = good.data; for (int i = 0; i < 4; ++i) b[good.lmFieldOff + static_cast<size_t>(i)] = i == 3 ? 2 : 0;
                                                                    expect_error_untouched(b, "section too short for its own length field"); }
    { Bytes b = good.data; for (int i = 0; i < 4; ++i) b[26 + i] = 0xFF;
                                                                    expect_error_untouched(b, "colour mode length overruns file"); }
}

TEST(psb_layer_info_length_overflow_is_rejected) {
    Built good = build_psd(base_spec(true));
    const size_t lmStart = good.lmFieldOff + 8;
    for (uint8_t last : {0xF8, 0xFC, 0xFE, 0xFF}) {                           // 8 + length would wrap past 2^64
        Bytes b = good.data;
        for (int i = 0; i < 7; ++i) b[lmStart + i] = 0xFF;
        b[lmStart + 7] = last;
        expect_error_untouched(b, "layer info length 0xFFFFFFFFFFFFFF" + std::to_string(last));
    }
}

static void psd_truncation_sweep(bool psb) {
    Built b = build_psd(base_spec(psb));
    TempDir d;
    const fs::path p = d / "t.psd";
    Options o;
    o.dryRun = true;
    for (size_t len = 0; len < b.data.size(); ++len) {
        Bytes prefix(b.data.begin(), b.data.begin() + static_cast<std::ptrdiff_t>(len));
        write_file(p, prefix);
        Result r = process(p, o);
        // Cutting inside the header/resources/layer-and-mask section is an error; cutting only
        // image data is fine because that part is never parsed.
        CHECK_MSG(r.kind == (len < b.sectionEnd ? Kind::Error : Kind::WouldStrip),
                  "prefix " << len << " -> " << kind_name(r.kind));
        CHECK_MSG(read_file(p) == prefix, "prefix " << len << " modified");
    }
}
TEST(psd_truncation_sweep_every_prefix) { psd_truncation_sweep(false); }
TEST(psb_truncation_sweep_every_prefix) { psd_truncation_sweep(true); }

// ============================================================ JPEG

TEST(jpeg_strips_noncontiguous_manifest_segments) {
    Pair pr = jpeg_pair();
    Plan P = analyze_bytes(pr.in);
    CHECK(P.format == "JPEG");
    CHECK(P.cuts.size() == 3);
    CHECK(!P.patchLen);
    expect_jpeg_strip(pr.in, pr.expected, 3);
}

TEST(jpeg_unrelated_jumbf_and_other_app11_are_kept) {
    auto dec = decoy_segments(9, 2);                                          // two-segment non-C2PA JUMBF box
    Bytes in = cat({soi(), jfif(), dec[0], non_jp_app11(), seg(0xEB, Bytes{'J', 'P', 0}), dec[1], dqt(),
                    sof(), sos(entropy()), eoi()});
    TempDir d;
    const fs::path p = d / "x.jpg";
    write_file(p, in);
    Result r = process(p, Options{});
    CHECK_KIND(r, Kind::Clean);
    CHECK_BYTES(read_file(p), in);
}

TEST(jpeg_manifest_between_progressive_scans) {
    auto c = c2pa_segments(3, 1);
    Bytes in = cat({soi(), jfif(), dqt(), sof(), sos(entropy()), c[0], sos(entropy()), eoi()});
    Bytes ex = cat({soi(), jfif(), dqt(), sof(), sos(entropy()), sos(entropy()), eoi()});
    expect_jpeg_strip(in, ex, 1);
}

TEST(jpeg_entropy_data_lookalikes_are_not_segments) {
    // Stuffed bytes (FF 00) and restart markers inside a scan must not be mistaken for an APP11 segment,
    // even when they spell out a manifest header. The real manifest after the scan is still found.
    Bytes tricky = cat({Bytes{0x11, 0xFF, 0x00, 0xEB, 0x00, 0x30, 'J', 'P'}, uuid_c2pa(), Bytes{0xFF, 0xD1, 0x22, 0xFF, 0xD7, 0x33}});
    auto c = c2pa_segments(1, 1);
    Bytes in = cat({soi(), jfif(), sof(), sos(tricky), c[0], eoi()});
    Bytes ex = cat({soi(), jfif(), sof(), sos(tricky), eoi()});
    expect_jpeg_strip(in, ex, 1);

    TempDir d;                                                                // and with no real manifest: untouched
    write_file(d / "x.jpg", ex);
    CHECK_KIND(process(d / "x.jpg", Options{}), Kind::Clean);
}

TEST(jpeg_bytes_after_eoi_are_never_touched) {
    auto c = c2pa_segments(1);
    Bytes trailer = cat({B("TRAILER"), c[0], B("END")});                      // looks like a manifest, but after EOI
    Bytes in = cat({soi(), jfif(), c[0], sof(), sos(entropy()), eoi(), trailer});
    Bytes ex = cat({soi(), jfif(), sof(), sos(entropy()), eoi(), trailer});
    expect_jpeg_strip(in, ex, 1);
}

TEST(jpeg_fill_bytes_before_markers) {
    auto c = c2pa_segments(1, 1);
    Bytes in = cat({soi(), Bytes{0xFF}, c[0], jfif(), sof(), sos(entropy()), Bytes{0xFF}, eoi()});
    Bytes ex = cat({soi(), Bytes{0xFF}, jfif(), sof(), sos(entropy()), Bytes{0xFF}, eoi()});
    expect_jpeg_strip(in, ex, 1);
}

TEST(jpeg_xlbox_manifest_is_detected) {
    // LBox == 1 means a 64-bit XLBox follows, pushing the description box (and UUID) 8 bytes later.
    Bytes first = cat({be(1, 4), B("jumb"), be(5000, 8), jumd(uuid_c2pa(), "c2pa"), Bytes(60, 'A')});
    Bytes seg1 = app11(1, 1, first);
    Bytes in = cat({soi(), jfif(), seg1, sof(), sos(entropy()), eoi()});
    Bytes ex = cat({soi(), jfif(), sof(), sos(entropy()), eoi()});
    expect_jpeg_strip(in, ex, 1);
}

TEST(jpeg_multiple_manifests_and_out_of_order_sequence) {
    auto a = c2pa_segments(1, 3), b = c2pa_segments(3, 1);
    Bytes in = cat({soi(), jfif(), a[1], b[0], a[0], a[2], sof(), sos(entropy()), eoi()});   // Z=2 before Z=1
    Bytes ex = cat({soi(), jfif(), sof(), sos(entropy()), eoi()});
    expect_jpeg_strip(in, ex, 4);
}

TEST(jpeg_xmp_provenance_is_reported_not_modified) {
    Bytes in = cat({soi(), xmp_segment(true), sof(), sos(entropy()), eoi()});
    CHECK(any_contains(analyze_bytes(in).notes, "dcterms:provenance"));
    Bytes plain = cat({soi(), xmp_segment(false), sof(), sos(entropy()), eoi()});
    CHECK(analyze_bytes(plain).notes.empty());
    TempDir d;
    write_file(d / "x.jpg", in);
    CHECK_KIND(process(d / "x.jpg", Options{}), Kind::Clean);
    CHECK_BYTES(read_file(d / "x.jpg"), in);
}

TEST(jpeg_without_credentials_is_untouched_and_listing_says_so) {
    Bytes in = cat({soi(), jfif(), dqt(), sof(), sos(entropy()), eoi()});
    CHECK(any_contains(analyze_bytes(in).listing, "no APP11 JUMBF segments"));
    TempDir d;
    write_file(d / "x.jpg", in);
    CHECK_KIND(process(d / "x.jpg", Options{}), Kind::Clean);
    CHECK_BYTES(read_file(d / "x.jpg"), in);
}

TEST(jpeg_listing_marks_only_the_manifest_segments) {
    Plan P = analyze_bytes(jpeg_pair().in);
    int removable = 0, kept = 0;
    for (const auto& l : P.listing) {
        if (contains(l, "would remove")) { ++removable; CHECK(contains(l, "En=1")); }
        else if (contains(l, "En=9")) ++kept;
    }
    CHECK(removable == 3);
    CHECK(kept == 1);
}

TEST(jpeg_missing_eoi_is_tolerated) {
    auto c = c2pa_segments(1, 1);
    expect_jpeg_strip(cat({soi(), jfif(), c[0], sof(), sos(entropy())}), cat({soi(), jfif(), sof(), sos(entropy())}), 1);
}

TEST(jpeg_malformed_structures_are_rejected_untouched) {
    expect_error_untouched({0xFF, 0xD8, 0xFF, 0x00, 0x00, 0x00}, "FF00 where a marker should be");
    expect_error_untouched({0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x01, 0x00}, "segment length < 2");
    expect_error_untouched({0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xFF, 0x00, 0x00}, "segment length overruns file");
    expect_error_untouched({0xFF, 0xD8, 0xFF, 0xE0}, "truncated segment header");
    expect_error_untouched({0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x05, 0x41}, "payload shorter than its length");
    expect_error_untouched({0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02, 0x12, 0x34}, "garbage where a marker should be");
    expect_error_untouched(B("\x89PNG\r\n\x1a\n-----"), "not a JPEG or PSD");
}

TEST(jpeg_truncation_sweep_every_prefix) {
    Pair pr = jpeg_pair();
    const size_t segStart = 2 + jfif().size(), segEnd = segStart + c2pa_segments(1)[0].size();
    TempDir d;
    const fs::path p = d / "t.jpg";
    Options o;
    o.dryRun = true;
    for (size_t len = 0; len < pr.in.size(); ++len) {
        Bytes prefix(pr.in.begin(), pr.in.begin() + static_cast<std::ptrdiff_t>(len));
        write_file(p, prefix);
        Result r = process(p, o);
        CHECK_MSG(r.kind == Kind::Error || r.kind == Kind::Clean || r.kind == Kind::WouldStrip,
                  "prefix " << len << " -> " << kind_name(r.kind));
        if (len >= segStart + 2 && len < segEnd)                              // cut inside the first manifest segment
            CHECK_MSG(r.kind == Kind::Error, "prefix " << len << " -> " << kind_name(r.kind));
        CHECK_MSG(read_file(p) == prefix, "prefix " << len << " modified");
    }
}

// ============================================================ process(): filesystem behaviour

TEST(format_is_detected_from_magic_not_extension) {
    Pair j = jpeg_pair();
    Bytes psd = build_psd(base_spec(false)).data;
    TempDir d;
    write_file(d / "jpeg_named.psd", j.in);
    write_file(d / "psd_named.jpg", psd);
    CHECK_KIND(process(d / "jpeg_named.psd", Options{}), Kind::Stripped);
    CHECK_KIND(process(d / "psd_named.jpg", Options{}), Kind::Stripped);
    CHECK_BYTES(read_file(d / "jpeg_named.psd"), j.expected);
    CHECK_BYTES(read_file(d / "psd_named.jpg"), build_psd(without(base_spec(false), {"CAI "})).data);
}

TEST(stripping_is_idempotent) {
    Pair j = jpeg_pair();
    TempDir d;
    write_file(d / "x.jpg", j.in);
    CHECK_KIND(process(d / "x.jpg", Options{}), Kind::Stripped);
    CHECK_KIND(process(d / "x.jpg", Options{}), Kind::Clean);
    CHECK_BYTES(read_file(d / "x.jpg"), j.expected);
}

TEST(dry_run_and_list_never_write) {
    Pair j = jpeg_pair();
    TempDir d;
    write_file(d / "x.jpg", j.in);
    Options o;
    o.dryRun = true;
    Result r = process(d / "x.jpg", o);
    CHECK_KIND(r, Kind::WouldStrip);
    CHECK(r.items == 3);
    o = Options{};
    o.list = true;
    std::ostringstream sink;
    std::streambuf* old = std::cout.rdbuf(sink.rdbuf());
    Result r2 = process(d / "x.jpg", o);
    std::cout.rdbuf(old);
    CHECK_KIND(r2, Kind::Listed);
    CHECK_BYTES(read_file(d / "x.jpg"), j.in);
    CHECK(no_tmp_files(d.path));
}

TEST(backup_preserves_original_and_never_clobbers_an_existing_backup) {
    Pair j = jpeg_pair();
    TempDir d;
    const fs::path p = d / "x.jpg", bak = d / "x.jpg.bak";
    write_file(p, j.in);
    Options o;
    o.backup = true;
    CHECK_KIND(process(p, o), Kind::Stripped);
    CHECK_BYTES(read_file(bak), j.in);
    CHECK_BYTES(read_file(p), j.expected);

    write_file(p, j.in);                                                      // credentials again; .bak already exists
    const Bytes oldBak = read_file(bak);
    Result r = process(p, o);
    CHECK_KIND(r, Kind::Error);
    CHECK(contains(r.msg, "backup already exists"));
    CHECK_BYTES(read_file(p), j.in);
    CHECK_BYTES(read_file(bak), oldBak);
    CHECK(no_tmp_files(d.path));
}

TEST(keep_mtime_option) {
    Pair j = jpeg_pair();
    for (bool keep : {true, false}) {
        TempDir d;
        const fs::path p = d / "x.jpg";
        write_file(p, j.in);
        const auto old = fs::file_time_type::clock::now() - std::chrono::hours(48);
        fs::last_write_time(p, old);
        Options o;
        o.keepMtime = keep;
        CHECK_KIND(process(p, o), Kind::Stripped);
        auto diff = fs::last_write_time(p) - old;
        if (diff < diff.zero()) diff = -diff;
        if (keep) CHECK_MSG(diff < std::chrono::seconds(2), "mtime drifted");
        else CHECK_MSG(diff > std::chrono::hours(1), "mtime should have advanced");
    }
}

#ifndef _WIN32
TEST(file_permissions_are_preserved) {
    Pair j = jpeg_pair();
    TempDir d;
    const fs::path p = d / "x.jpg";
    write_file(p, j.in);
    const fs::perms want = fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read;
    fs::permissions(p, want, fs::perm_options::replace);
    CHECK_KIND(process(p, Options{}), Kind::Stripped);
    CHECK(fs::status(p).permissions() == want);
}

TEST(symlinked_file_is_stripped_in_place_and_the_link_survives) {
    Pair j = jpeg_pair();
    TempDir d;
    const fs::path target = d / "real/photo.jpg", link = d / "link.jpg";
    write_file(target, j.in);
    fs::create_symlink(target, link);
    CHECK_KIND(process(link, Options{}), Kind::Stripped);
    CHECK(fs::is_symlink(link));
    CHECK_BYTES(read_file(target), j.expected);
}
#endif

// ============================================================ CLI (run)

TEST(cli_usage_errors_exit_2) {
    Cli a = cli({});
    CHECK(a.rc == 2 && contains(a.err, "Usage"));
    Cli b = cli({"--bogus", "x"});
    CHECK(b.rc == 2 && contains(b.err, "unknown option"));
    CHECK(cli({"--key"}).rc == 2);
    CHECK(cli({"--key", "toolongkey", "x"}).rc == 2);
    Cli h = cli({"--help"});
    CHECK(h.rc == 0 && contains(h.err, "Usage"));
}

TEST(cli_directory_scan_rules) {
    TempDir d;
    Pair j = jpeg_pair();
    Bytes psd = build_psd(base_spec(false)).data;
    const Bytes psdExpected = build_psd(without(base_spec(false), {"CAI "})).data;
    write_file(d / "a.psd", psd);
    write_file(d / "b.JPG", j.in);
    write_file(d / "c.txt", psd);                       // wrong extension: ignored
    write_file(d / "d.psd.bak", psd);                   // backup files: ignored
    write_file(d / "sub/e.jpeg", j.in);                 // subdirectory: only with -r

    Cli c1 = cli({d.path.string()});
    CHECK(c1.rc == 0);
    CHECK(contains(c1.out, "2 file(s): 2 stripped"));
    CHECK_BYTES(read_file(d / "a.psd"), psdExpected);
    CHECK_BYTES(read_file(d / "b.JPG"), j.expected);
    CHECK_BYTES(read_file(d / "c.txt"), psd);
    CHECK_BYTES(read_file(d / "d.psd.bak"), psd);
    CHECK_BYTES(read_file(d / "sub/e.jpeg"), j.in);

    Cli c2 = cli({"-r", d.path.string()});
    CHECK(c2.rc == 0);
    CHECK(contains(c2.out, "3 file(s): 1 stripped"));
    CHECK_BYTES(read_file(d / "sub/e.jpeg"), j.expected);
    CHECK(no_tmp_files(d.path));
}

TEST(cli_errors_do_not_abort_the_run_and_set_exit_code_1) {
    TempDir d;
    Bytes psd = build_psd(base_spec(false)).data;
    Bytes broken(psd.begin(), psd.begin() + 40);
    write_file(d / "a.psd", psd);
    write_file(d / "b_broken.psd", broken);
    write_file(d / "c.jpg", jpeg_pair().in);
    Cli c = cli({d.path.string()});
    CHECK(c.rc == 1);
    CHECK(contains(c.err, "[error]") && contains(c.err, "b_broken.psd"));
    CHECK(contains(c.out, "2 stripped"));                                      // the good files were still processed
    CHECK_BYTES(read_file(d / "b_broken.psd"), broken);
    CHECK_BYTES(read_file(d / "c.jpg"), jpeg_pair().expected);
}

TEST(cli_dry_run_and_list_do_not_modify) {
    TempDir d;
    Pair j = jpeg_pair();
    write_file(d / "a.jpg", j.in);
    Cli n = cli({"-n", d.path.string()});
    CHECK(n.rc == 0 && contains(n.out, "[would strip]") && contains(n.out, "removable"));
    Cli l = cli({"-l", d.path.string()});
    CHECK(l.rc == 0 && contains(l.out, "would remove (C2PA manifest store)"));
    CHECK_BYTES(read_file(d / "a.jpg"), j.in);
}

TEST(cli_backup_flag) {
    TempDir d;
    Pair j = jpeg_pair();
    write_file(d / "a.jpg", j.in);
    CHECK(cli({"--backup", d.path.string()}).rc == 0);
    CHECK_BYTES(read_file(d / "a.jpg.bak"), j.in);
    CHECK_BYTES(read_file(d / "a.jpg"), j.expected);
}

TEST(cli_key_option_accepts_hex) {
    TempDir d;
    PsdSpec s = base_spec(false);
    s.blocks.push_back({"abcd", seq(10)});
    write_file(d / "a.psd", build_psd(s).data);
    CHECK(cli({"--key", "61626364", (d / "a.psd").string()}).rc == 0);          // "abcd"
    CHECK_BYTES(read_file(d / "a.psd"), build_psd(without(s, {"CAI ", "abcd"})).data);
}

TEST(cli_explicit_file_ignores_extension_and_duplicates_collapse) {
    TempDir d;
    Pair j = jpeg_pair();
    write_file(d / "photo.dat", j.in);
    const std::string p = (d / "photo.dat").string();
    Cli c = cli({p, p});
    CHECK(c.rc == 0);
    CHECK(contains(c.out, "1 file(s): 1 stripped"));
    CHECK_BYTES(read_file(d / "photo.dat"), j.expected);
}

TEST(cli_reports_missing_paths_and_nothing_matched_hint) {
    TempDir d;
    Cli m = cli({(d / "nope").string()});
    CHECK(m.rc == 1 && contains(m.err, "not a file or directory"));
    write_file(d / "plain.psd", build_psd(without(base_spec(false), {"CAI "})).data);
    Cli n = cli({d.path.string()});
    CHECK(n.rc == 0 && contains(n.out, "Nothing matched"));
}

// ============================================================ property / fuzz tests

TEST(fuzz_random_buffers_never_crash_or_modify) {
    std::mt19937 rng(12345);
    TempDir d;
    const fs::path p = d / "f.bin";
    Options o;
    o.dryRun = true;
    for (int i = 0; i < 600; ++i) {
        Bytes b;
        if (i % 3 == 0) b = {'8', 'B', 'P', 'S', 0, static_cast<uint8_t>(1 + (i & 1))};
        else if (i % 3 == 1) b = {0xFF, 0xD8, 0xFF};
        const size_t n = rng() % 300;
        for (size_t k = 0; k < n; ++k) b.push_back(static_cast<uint8_t>(rng()));
        write_file(p, b);
        Result r = process(p, o);
        CHECK_MSG(r.kind == Kind::Error || r.kind == Kind::Clean || r.kind == Kind::WouldStrip,
                  "iteration " << i << " -> " << kind_name(r.kind));
        CHECK_MSG(read_file(p) == b, "iteration " << i << " modified the file");
    }
}

// Invariant for ANY input: after process(), the file is either byte-identical to what it was
// (error / nothing to do), or it is a smaller file that re-parses cleanly with nothing left to cut.
TEST(fuzz_mutated_valid_files_never_leave_a_corrupt_result) {
    std::vector<Bytes> bases = {build_psd(base_spec(false)).data, build_psd(base_spec(true)).data, jpeg_pair().in};
    {
        auto c = c2pa_segments(3, 1);
        bases.push_back(cat({soi(), jfif(), sof(), sos(entropy()), c[0], sos(entropy()), eoi()}));
    }
    std::mt19937 rng(987654321);
    TempDir d;
    const fs::path p = d / "m.bin";
    int stripped = 0, errors = 0;
    for (int i = 0; i < 1500; ++i) {
        Bytes m = bases[static_cast<size_t>(i) % bases.size()];
        if (rng() % 5 == 0) {
            m.resize(rng() % m.size());
        } else {
            const int edits = 1 + static_cast<int>(rng() % 4);
            for (int e = 0; e < edits; ++e) {
                const size_t pos = (rng() % 2) ? rng() % std::min<size_t>(m.size(), 120) : rng() % m.size();
                m[pos] = static_cast<uint8_t>(rng());
            }
        }
        write_file(p, m);
        Result r = process(p, Options{});
        const Bytes after = read_file(p);
        CHECK_MSG(!fs::exists(p.string() + ".cai-strip.tmp"), "iteration " << i << ": temp file left behind");
        if (r.kind == Kind::Stripped) {
            ++stripped;
            bool clean = false;
            try { File f(p); clean = analyze(f, Options{}).cuts.empty(); } catch (...) {}
            CHECK_MSG(after.size() < m.size() && clean, "iteration " << i << ": stripped output does not re-parse cleanly");
        } else {
            errors += r.kind == Kind::Error;
            CHECK_MSG(after == m, "iteration " << i << ": " << kind_name(r.kind) << " but file changed");
        }
    }
    CHECK_MSG(stripped > 100, "mutation corpus too weak: only " << stripped << " files were stripped");
    CHECK_MSG(errors > 100, "mutation corpus too weak: only " << errors << " files were rejected");
}

// ============================================================ runner

int main(int argc, char** argv) {
    const std::string filter = argc > 1 ? argv[1] : "";
    int ran = 0, failedTests = 0;
    for (const auto& t : registry()) {
        if (!filter.empty() && !contains(t.name, filter)) continue;
        const int before = g_failures;
        g_current = t.name;
        ++ran;
        try { t.fn(); }
        catch (const TestAbort&) {}
        catch (const std::exception& e) { ++g_failures; std::cerr << "  FAIL " << t.name << ": uncaught exception: " << e.what() << "\n"; }
        catch (...) { ++g_failures; std::cerr << "  FAIL " << t.name << ": uncaught non-standard exception\n"; }
        const bool ok = g_failures == before;
        failedTests += !ok;
        std::cout << (ok ? "[ PASS ] " : "[ FAIL ] ") << t.name << "\n";
    }
    std::cout << "\n" << ran << " test(s), " << g_checks << " check(s), " << failedTests << " failed test(s)\n";
    return failedTests ? 1 : 0;
}
