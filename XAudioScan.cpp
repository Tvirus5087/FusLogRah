// =====================================================================
//  XAudioScan - finds (and optionally repairs) Skyrim audio that
//               XAudio2 2.7 cannot play
//
//  Standalone. No external libraries. Build with:
//      cl /std:c++20 /EHsc /O2 /utf-8 XAudioScan.cpp
//
//  Targets Skyrim Special Edition. Includes its own LZ4-block
//  decompressor so compressed BSA entries can be read without any
//  external library. Skyrim LE archives (v103/v104) are reported and
//  skipped rather than guessed at.
//
//  Run with --help for usage.
// =====================================================================

#define NOMINMAX

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

// =====================================================================
//  LZ4 block format decompression
// =====================================================================

bool Lz4BlockDecompress(const std::uint8_t* src, std::size_t srcSize,
                        std::vector<std::uint8_t>& out, std::size_t expected)
{
    out.clear();
    out.reserve(expected);

    std::size_t ip = 0;
    while (ip < srcSize) {
        const std::uint8_t token = src[ip++];

        // ---- literals ----
        std::size_t litLen = token >> 4;
        if (litLen == 15) {
            for (;;) {
                if (ip >= srcSize) return false;
                const std::uint8_t b = src[ip++];
                litLen += b;
                if (b != 255) break;
            }
        }
        if (ip + litLen > srcSize || out.size() + litLen > expected) {
            return false;
        }
        out.insert(out.end(), src + ip, src + ip + litLen);
        ip += litLen;

        // The final sequence is literals only and carries no match.
        if (ip >= srcSize) {
            break;
        }

        // ---- match ----
        if (ip + 2 > srcSize) {
            return false;
        }
        const std::size_t offset =
            static_cast<std::size_t>(src[ip]) | (static_cast<std::size_t>(src[ip + 1]) << 8);
        ip += 2;
        if (offset == 0 || offset > out.size()) {
            return false;
        }

        std::size_t matchLen = token & 0x0F;
        if (matchLen == 15) {
            for (;;) {
                if (ip >= srcSize) return false;
                const std::uint8_t b = src[ip++];
                matchLen += b;
                if (b != 255) break;
            }
        }
        matchLen += 4;  // minimum match length

        if (out.size() + matchLen > expected) {
            return false;
        }
        const std::size_t start = out.size() - offset;
        for (std::size_t i = 0; i < matchLen; ++i) {
            out.push_back(out[start + i]);  // overlapping copies are legal
        }
    }

    return out.size() == expected;
}

// =====================================================================
//  Audio format structures
// =====================================================================

#pragma pack(push, 1)
struct WaveFormatEx {
    std::uint16_t formatTag;
    std::uint16_t channels;
    std::uint32_t samplesPerSec;
    std::uint32_t avgBytesPerSec;
    std::uint16_t blockAlign;
    std::uint16_t bitsPerSample;
    std::uint16_t cbSize;
};
#pragma pack(pop)

constexpr std::uint16_t kFmtPCM = 0x0001;
constexpr std::uint16_t kFmtADPCM = 0x0002;
constexpr std::uint16_t kFmtFloat = 0x0003;
constexpr std::uint16_t kFmtALaw = 0x0006;
constexpr std::uint16_t kFmtMuLaw = 0x0007;
constexpr std::uint16_t kFmtIMAADPCM = 0x0011;
constexpr std::uint16_t kFmtGSM610 = 0x0031;
constexpr std::uint16_t kFmtMP3 = 0x0055;
constexpr std::uint16_t kFmtWMAudio2 = 0x0161;
constexpr std::uint16_t kFmtWMAudio3 = 0x0162;
constexpr std::uint16_t kFmtWMALossless = 0x0163;
constexpr std::uint16_t kFmtWMASpdif = 0x0164;
constexpr std::uint16_t kFmtExtensible = 0xFFFE;

constexpr std::uint32_t kMinSampleRate = 1000;
constexpr std::uint32_t kMaxSampleRate = 200000;
constexpr std::uint32_t kMaxChannels = 64;

std::string FormatTagName(std::uint16_t tag)
{
    switch (tag) {
    case kFmtPCM:         return "PCM";
    case kFmtADPCM:       return "MS ADPCM";
    case kFmtFloat:       return "IEEE float";
    case kFmtALaw:        return "A-law";
    case kFmtMuLaw:       return "mu-law";
    case kFmtIMAADPCM:    return "IMA/DVI ADPCM";
    case kFmtGSM610:      return "GSM 6.10";
    case kFmtMP3:         return "MP3";
    case kFmtWMAudio2:    return "xWMA (WMAudio2)";
    case kFmtWMAudio3:    return "xWMA (WMAudio3)";
    case kFmtWMALossless: return "WMA Lossless";
    case kFmtWMASpdif:    return "WMA S/PDIF";
    case kFmtExtensible:  return "WAVE_FORMAT_EXTENSIBLE";
    default:              return "unknown codec";
    }
}

// =====================================================================
//  Findings
// =====================================================================

enum class Severity { Ok = 0, Warning = 1, Fatal = 2 };

struct Finding {
    Severity    severity{ Severity::Warning };
    std::string reason;
    std::string fix;
};

struct Report {
    Severity             severity{ Severity::Ok };
    std::vector<Finding> findings;

    void Add(Severity sev, std::string reason, std::string fix)
    {
        if (sev > severity) {
            severity = sev;
        }
        findings.push_back({ sev, std::move(reason), std::move(fix) });
    }
    bool Fatal() const { return severity == Severity::Fatal; }
    bool Clean() const { return severity == Severity::Ok; }
};

// =====================================================================
//  Blob
// =====================================================================

struct Blob {
    std::vector<std::uint8_t> bytes;
    std::uint64_t             trueSize{ 0 };
    bool                      complete{ true };

    bool ReadAt(std::uint64_t off, void* dst, std::size_t n) const
    {
        if (off + n > bytes.size()) {
            return false;
        }
        std::memcpy(dst, bytes.data() + off, n);
        return true;
    }
    std::uint32_t U32At(std::uint64_t off, bool& good) const
    {
        std::uint32_t v = 0;
        good = ReadAt(off, &v, sizeof(v));
        return v;
    }
};

constexpr std::uint32_t FourCC(const char (&s)[5])
{
    return static_cast<std::uint32_t>(static_cast<std::uint8_t>(s[0])) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(s[1])) << 8) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(s[2])) << 16) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(s[3])) << 24);
}

constexpr std::uint32_t kRIFF = FourCC("RIFF");
constexpr std::uint32_t kWAVE = FourCC("WAVE");
constexpr std::uint32_t kXWMA = FourCC("XWMA");
constexpr std::uint32_t kFMT_ = FourCC("fmt ");
constexpr std::uint32_t kDATA = FourCC("data");
constexpr std::uint32_t kDPDS = FourCC("dpds");
constexpr std::uint32_t kFUZE = FourCC("FUZE");

// =====================================================================
//  Format inspection
// =====================================================================

std::uint16_t EffectiveTag(const std::vector<std::uint8_t>& fmtChunk, const WaveFormatEx& fmt)
{
    if (fmt.formatTag != kFmtExtensible || fmtChunk.size() < 40) {
        return fmt.formatTag;
    }
    static constexpr std::uint8_t tail[12] = {
        0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71
    };
    if (std::memcmp(fmtChunk.data() + 28, tail, sizeof(tail)) != 0) {
        return kFmtExtensible;
    }
    std::uint32_t subData1 = 0;
    std::memcpy(&subData1, fmtChunk.data() + 24, 4);
    return static_cast<std::uint16_t>(subData1);
}

bool ParseFormat(const std::vector<std::uint8_t>& fmtChunk, WaveFormatEx& fmt)
{
    if (fmtChunk.size() < 16) {
        return false;
    }
    std::memset(&fmt, 0, sizeof(fmt));
    std::memcpy(&fmt, fmtChunk.data(), (std::min)(fmtChunk.size(), sizeof(WaveFormatEx)));
    if (fmtChunk.size() < 18) {
        fmt.cbSize = 0;
    }
    return true;
}

void InspectFormat(const std::vector<std::uint8_t>& fmtChunk, Report& r)
{
    WaveFormatEx fmt{};
    if (!ParseFormat(fmtChunk, fmt)) {
        r.Add(Severity::Fatal,
              std::format("The 'fmt ' chunk is only {} bytes; 16 is the minimum.", fmtChunk.size()),
              "Re-export the file from the original source.");
        return;
    }

    const std::uint16_t bits = fmt.bitsPerSample;
    std::uint16_t effectiveTag = fmt.formatTag;

    if (fmt.formatTag == kFmtExtensible) {
        if (fmtChunk.size() < 40 || fmt.cbSize < 22) {
            r.Add(Severity::Fatal,
                  std::format("WAVE_FORMAT_EXTENSIBLE declares cbSize={} in a {}-byte chunk, but "
                              "22 extra bytes are required.", fmt.cbSize, fmtChunk.size()),
                  "Re-export as plain 16-bit PCM WAV.");
            return;
        }
        effectiveTag = EffectiveTag(fmtChunk, fmt);
        if (effectiveTag == kFmtExtensible) {
            r.Add(Severity::Fatal,
                  "WAVE_FORMAT_EXTENSIBLE uses a non-standard SubFormat GUID that XAudio2 2.7 "
                  "cannot map to a known codec.",
                  "Re-export as plain 16-bit PCM WAV.");
            return;
        }
        std::uint16_t validBits = 0;
        std::memcpy(&validBits, fmtChunk.data() + 18, 2);
        if (validBits != 0 && validBits > bits) {
            r.Add(Severity::Fatal,
                  std::format("wValidBitsPerSample ({}) exceeds wBitsPerSample ({}).", validBits, bits),
                  "Re-export as plain 16-bit PCM WAV.");
        }
    }

    if (fmt.channels == 0) {
        r.Add(Severity::Fatal,
              "Channel count is 0. Every buffer-size calculation downstream divides by this.",
              "Header is corrupt. Re-encode from the original source.");
    } else if (fmt.channels > kMaxChannels) {
        r.Add(Severity::Fatal,
              std::format("Channel count is {}. XAudio2 2.7 supports at most {}.",
                          fmt.channels, kMaxChannels),
              "Downmix to mono for sound effects, stereo for music.");
    } else if (fmt.channels > 2) {
        r.Add(Severity::Warning,
              std::format("{} channels. Skyrim's audio graph is built around mono and stereo; "
                          "multichannel sources behave unpredictably through the 3D emitter path.",
                          fmt.channels),
              "Downmix to mono for sound effects, stereo for music.");
    }

    if (fmt.samplesPerSec < kMinSampleRate || fmt.samplesPerSec > kMaxSampleRate) {
        r.Add(Severity::Fatal,
              std::format("Sample rate is {} Hz. XAudio2 2.7 accepts {}-{} Hz only.",
                          fmt.samplesPerSec, kMinSampleRate, kMaxSampleRate),
              "Resample to 44100 Hz.");
    } else {
        static constexpr std::uint32_t common[] = {
            8000, 11025, 16000, 22050, 24000, 32000, 44100, 48000
        };
        if (std::find(std::begin(common), std::end(common), fmt.samplesPerSec) == std::end(common)) {
            r.Add(Severity::Warning,
                  std::format("Unusual sample rate ({} Hz). Legal, but pitch-shifted variants of a "
                              "high-rate source can exceed the 200 kHz ceiling XAudio2 2.7 enforces.",
                              fmt.samplesPerSec),
                  "Resample to 44100 Hz.");
        }
    }

    switch (effectiveTag) {
    case kFmtPCM:
        if (bits != 8 && bits != 16 && bits != 24 && bits != 32) {
            r.Add(Severity::Fatal,
                  std::format("{}-bit PCM. XAudio2 2.7 supports 8, 16, 24 and 32-bit PCM only.", bits),
                  "Re-export as 16-bit PCM.");
        } else if (bits != 16) {
            r.Add(Severity::Warning,
                  std::format("{}-bit PCM. XAudio2 accepts it, but Skyrim's own code paths assume "
                              "16-bit and several mod tools mishandle it.", bits),
                  "Re-export as 16-bit PCM.");
        }
        break;

    case kFmtFloat:
        if (bits != 32 && bits != 64) {
            r.Add(Severity::Fatal,
                  std::format("IEEE float declared with {} bits per sample; only 32 or 64 is valid.", bits),
                  "Re-export as 16-bit PCM.");
        } else {
            r.Add(Severity::Warning,
                  std::format("{}-bit float WAV. This is what a modern DAW exports by default and "
                              "it is not what Skyrim expects.", bits),
                  "Re-export as 16-bit PCM. Audacity: File > Export > WAV, 'Signed 16-bit PCM'.");
        }
        break;

    case kFmtADPCM:
    case kFmtIMAADPCM:
    case kFmtGSM610:
    case kFmtMP3:
    case kFmtALaw:
    case kFmtMuLaw:
        r.Add(Severity::Fatal,
              std::format("Codec is {} (0x{:04X}). XAudio2 2.7 has no decoder for this; "
                          "CreateSourceVoice fails and the caller is left with a null voice pointer.",
                          FormatTagName(effectiveTag), effectiveTag),
              "Re-encode to 16-bit PCM WAV, or to xWMA if you need the compression.");
        break;

    case kFmtWMAudio2:
    case kFmtWMAudio3:
        if (fmt.blockAlign == 0) {
            r.Add(Severity::Fatal, "xWMA format with nBlockAlign = 0.",
                  "Re-encode with xWMAEncode.exe from the DirectX SDK, or Yakitori Audio Converter.");
        }
        break;

    case kFmtWMALossless:
    case kFmtWMASpdif:
        r.Add(Severity::Fatal,
              std::format("Codec is {} (0x{:04X}), which XAudio2 2.7 cannot play.",
                          FormatTagName(effectiveTag), effectiveTag),
              "Re-encode to 16-bit PCM WAV or standard xWMA.");
        break;

    default:
        r.Add(Severity::Fatal, std::format("Unrecognised codec tag 0x{:04X}.", effectiveTag),
              "Re-encode to 16-bit PCM WAV.");
        break;
    }

    if (fmt.blockAlign == 0) {
        r.Add(Severity::Fatal,
              "nBlockAlign is 0. Buffer length is computed as bytes / nBlockAlign, which is a "
              "divide-by-zero waiting to happen.",
              "Rebuild the WAV header - any re-export from Audacity or ffmpeg fixes it.");
    }

    const bool linearPcm = (effectiveTag == kFmtPCM || effectiveTag == kFmtFloat);
    if (linearPcm && fmt.channels > 0 && bits > 0) {
        const auto expectedAlign = static_cast<std::uint16_t>(fmt.channels * (bits / 8));
        const auto expectedAvg = static_cast<std::uint32_t>(fmt.samplesPerSec) * expectedAlign;

        if (expectedAlign != 0 && fmt.blockAlign != expectedAlign) {
            r.Add(Severity::Fatal,
                  std::format("nBlockAlign is {} but {} channels x {} bits requires {}. The decoder "
                              "will walk off the end of every buffer it is given.",
                              fmt.blockAlign, fmt.channels, bits, expectedAlign),
                  "Header is malformed. Re-export the file.");
        }
        if (expectedAvg != 0 && fmt.avgBytesPerSec != expectedAvg && fmt.blockAlign == expectedAlign) {
            r.Add(Severity::Warning,
                  std::format("nAvgBytesPerSec is {} but the declared format implies {}.",
                              fmt.avgBytesPerSec, expectedAvg),
                  "Cosmetic, but it means the header was hand-edited or written by a broken tool.");
        }
    }
}

// =====================================================================
//  RIFF walking
// =====================================================================

struct RiffInfo {
    bool                      valid{ false };
    std::uint32_t             formType{ 0 };
    std::vector<std::uint8_t> fmtChunk;
    std::vector<std::uint8_t> dpdsChunk;
    bool                      haveData{ false };
    std::uint64_t             dataOffset{ 0 };
    std::uint64_t             dataSize{ 0 };
    bool                      haveDpds{ false };
    bool                      truncated{ false };
    bool                      chunkOverrun{ false };
    bool                      incomplete{ false };
};

RiffInfo WalkRiff(const Blob& blob, std::uint64_t base)
{
    RiffInfo info;
    bool good = false;

    if (blob.U32At(base, good) != kRIFF || !good) {
        return info;
    }
    const auto riffSize = blob.U32At(base + 4, good);
    if (!good) {
        return info;
    }
    info.formType = blob.U32At(base + 8, good);
    if (!good) {
        return info;
    }
    info.valid = true;

    std::uint64_t declaredEnd = base + 8 + riffSize;
    if (declaredEnd > blob.trueSize) {
        info.truncated = true;
        declaredEnd = blob.trueSize;
    }

    std::uint64_t offset = base + 12;
    while (offset + 8 <= declaredEnd) {
        if (offset + 8 > blob.bytes.size()) {
            info.incomplete = true;
            break;
        }
        const auto id = blob.U32At(offset, good);
        if (!good) break;
        const auto chunkSize = blob.U32At(offset + 4, good);
        if (!good) break;

        const std::uint64_t body = offset + 8;
        if (body + chunkSize > blob.trueSize) {
            info.chunkOverrun = true;
        }

        if (id == kFMT_) {
            const auto want = (std::min)(static_cast<std::uint64_t>(chunkSize), std::uint64_t{ 64 });
            info.fmtChunk.resize(static_cast<std::size_t>(want));
            if (want == 0 || !blob.ReadAt(body, info.fmtChunk.data(), static_cast<std::size_t>(want))) {
                info.fmtChunk.clear();
            }
        } else if (id == kDATA) {
            info.haveData = true;
            info.dataOffset = body;
            info.dataSize = chunkSize;
        } else if (id == kDPDS) {
            info.haveDpds = true;
            const auto want = (std::min)(static_cast<std::uint64_t>(chunkSize),
                                         std::uint64_t{ 1 } << 20);
            info.dpdsChunk.resize(static_cast<std::size_t>(want));
            if (want == 0 || !blob.ReadAt(body, info.dpdsChunk.data(), static_cast<std::size_t>(want))) {
                info.dpdsChunk.clear();
            }
        }

        const std::uint64_t advance = 8ull + chunkSize + (chunkSize & 1);
        if (advance <= 8) break;
        offset += advance;
    }

    return info;
}

void EvaluateRiff(const RiffInfo& info, const std::string& displayPath, Report& r)
{
    if (!info.valid) {
        r.Add(Severity::Fatal, "Not a valid RIFF container - does not start with 'RIFF'.",
              "The file is corrupt, truncated, or a different format with the wrong extension.");
        return;
    }

    const bool isXwma = (info.formType == kXWMA);

    if (info.formType != kWAVE && !isXwma) {
        r.Add(Severity::Fatal, "RIFF form type is neither 'WAVE' nor 'XWMA'.",
              "Re-encode to 16-bit PCM WAV or xWMA.");
    }
    if (info.truncated) {
        r.Add(Severity::Fatal,
              "The RIFF header declares more data than the file contains. The file is truncated.",
              "Re-download or re-extract the mod - usually a bad extraction or interrupted download.");
    }
    if (info.chunkOverrun) {
        r.Add(Severity::Fatal, "At least one chunk claims to extend past the end of the file.",
              "Header is corrupt. Re-export the file.");
    }

    if (info.fmtChunk.empty()) {
        if (!info.incomplete) {
            r.Add(Severity::Fatal, "No usable 'fmt ' chunk.",
                  "Re-export the file from the original source.");
        }
    } else {
        InspectFormat(info.fmtChunk, r);

        std::string lower = displayPath;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) {
                           c = static_cast<unsigned char>(std::tolower(c));
                           return static_cast<char>(c == '\\' ? '/' : c);
                       });
        if (lower.find("sound/fx/") != std::string::npos && info.fmtChunk.size() >= 4) {
            std::uint16_t ch = 0;
            std::memcpy(&ch, info.fmtChunk.data() + 2, 2);
            if (ch == 2) {
                r.Add(Severity::Warning,
                      "Stereo file inside Sound\\FX. Skyrim submits these to a 3D emitter, which "
                      "expects a mono source; the channel counts on the output matrix then disagree.",
                      "Convert to mono, or make sure the Sound Descriptor is not flagged as 3D.");
            }
        }
    }

    if (!info.haveData && !info.incomplete) {
        r.Add(Severity::Fatal, "No 'data' chunk. The file declares a format but contains no audio.",
              "Re-export the file.");
    } else if (info.haveData && info.dataSize == 0) {
        r.Add(Severity::Fatal, "The 'data' chunk is zero bytes long.",
              "Re-export the file. A zero-length placeholder faults as soon as it is submitted.");
    }

    if (isXwma && !info.incomplete) {
        if (!info.haveDpds) {
            r.Add(Severity::Fatal,
                  "xWMA file with no 'dpds' chunk. XAudio2's xWMA path needs that seek table to "
                  "locate packet boundaries; without it, playback reads garbage packet offsets.",
                  "Re-encode with xWMAEncode.exe, or Yakitori Audio Converter. This almost always "
                  "comes from renaming a .wma to .xwm.");
        } else if (info.dpdsChunk.size() < 4) {
            r.Add(Severity::Fatal, "The 'dpds' seek table is present but empty.",
                  "Re-encode with xWMAEncode.exe.");
        }
    }
}

// =====================================================================
//  Asset inspection
// =====================================================================

std::uint64_t FindEmbeddedRiff(const Blob& blob, std::uint64_t from)
{
    if (blob.bytes.size() < 12) {
        return UINT64_MAX;
    }
    for (std::uint64_t i = from; i + 12 <= blob.bytes.size(); ++i) {
        bool good = false;
        if (blob.U32At(i, good) == kRIFF && good) {
            const auto form = blob.U32At(i + 8, good);
            if (good && (form == kXWMA || form == kWAVE)) {
                return i;
            }
        }
    }
    return UINT64_MAX;
}

Report InspectBlob(const Blob& blob, const std::string& displayPath, std::string_view ext)
{
    Report r;

    if (blob.trueSize == 0) {
        r.Add(Severity::Fatal, "Zero-byte file.",
              "Delete or replace it. Usually left behind by a failed archive extraction.");
        return r;
    }
    if (blob.trueSize < 12 || blob.bytes.size() < 12) {
        r.Add(Severity::Fatal,
              std::format("File is only {} bytes - too small to contain a header.", blob.trueSize),
              "Delete or replace the file.");
        return r;
    }

    bool good = false;
    const auto magic = blob.U32At(0, good);
    if (!good) {
        r.Add(Severity::Fatal, "Could not read the first four bytes.", "Replace the file.");
        return r;
    }

    if (ext == ".fuz") {
        if (magic == kRIFF) {
            r.Add(Severity::Fatal,
                  "This .fuz is actually a bare RIFF. Skyrim reads the first 12 bytes as a FUZE "
                  "header, gets a nonsense LIP length, and seeks to an arbitrary offset.",
                  "Wrap it properly, or rename it to match its contents. Repairable with --fix.");
            return r;
        }
        if (magic != kFUZE) {
            r.Add(Severity::Fatal, "Not a FUZE container - does not start with 'FUZE'.",
                  "Rebuild the .fuz from its audio and .lip parts.");
            return r;
        }

        const auto version = blob.U32At(4, good);
        if (good && version != 1) {
            r.Add(Severity::Warning,
                  std::format("FUZE version field is {}; every vanilla file uses 1.", version),
                  "Rebuild the .fuz with a current tool.");
        }

        const auto lipSize = blob.U32At(8, good);
        if (!good) {
            r.Add(Severity::Fatal, "Truncated FUZE header.", "Rebuild the .fuz.");
            return r;
        }

        const std::uint64_t audioOffset = 12ull + lipSize;
        RiffInfo inner;
        if (audioOffset + 12 <= blob.bytes.size()) {
            inner = WalkRiff(blob, audioOffset);
        }

        if (!inner.valid) {
            const auto actual = FindEmbeddedRiff(blob, 12);
            if (actual != UINT64_MAX) {
                r.Add(Severity::Fatal,
                      std::format("The FUZE header points at offset {} but the embedded RIFF "
                                  "actually starts at {}. The declared LIP length is wrong.",
                                  audioOffset, actual),
                      std::format("The LIP length field should be {}. Repairable with --fix.",
                                  actual - 12));
                auto real = WalkRiff(blob, actual);
                EvaluateRiff(real, displayPath, r);
            } else if (audioOffset >= blob.trueSize) {
                r.Add(Severity::Fatal,
                      std::format("FUZE header says the LIP block is {} bytes, putting the audio "
                                  "start at offset {} in a {}-byte file.",
                                  lipSize, audioOffset, blob.trueSize),
                      "Header is corrupt or the file is truncated. Rebuild the .fuz.");
            } else {
                r.Add(Severity::Fatal,
                      "The embedded audio block inside the .fuz is not a RIFF container, and no "
                      "RIFF header was found anywhere in the file.",
                      "Rebuild the .fuz from its source audio.");
            }
            return r;
        }
        EvaluateRiff(inner, displayPath, r);
        return r;
    }

    if (magic == kFUZE) {
        r.Add(Severity::Fatal, std::format("This {} file is actually a FUZE container.", ext),
              "Rename it to .fuz, or unpack the audio out of it.");
        return r;
    }

    auto info = WalkRiff(blob, 0);
    EvaluateRiff(info, displayPath, r);

    if (info.valid) {
        if (ext == ".xwm" && info.formType == kWAVE) {
            r.Add(Severity::Warning, "Extension is .xwm but the form type is 'WAVE'.",
                  "If it really is a plain WAV, rename it to .wav and update the sound record.");
        } else if (ext == ".wav" && info.formType == kXWMA) {
            r.Add(Severity::Fatal, "Extension is .wav but the contents are xWMA.",
                  "Rename it to .xwm and update the sound record, or decode it to PCM.");
        }
    }

    return r;
}

// =====================================================================
//  Repair engine
//
//  Everything here rebuilds a clean container from the parts that are
//  recoverable. Sample data is only ever converted between linear PCM
//  representations - nothing is re-encoded through a lossy codec.
// =====================================================================

struct RepairOptions {
    bool monoFx = false;
    bool placeholders = false;
};

struct RepairResult {
    bool                      changed = false;
    bool                      unfixable = false;
    bool                      isPlaceholder = false;
    std::vector<std::uint8_t> data;
    std::vector<std::string>  actions;
};

void AppendU32(std::vector<std::uint8_t>& v, std::uint32_t x)
{
    v.push_back(static_cast<std::uint8_t>(x & 0xFF));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<std::uint8_t>((x >> 24) & 0xFF));
}

void AppendTag(std::vector<std::uint8_t>& v, const char (&s)[5])
{
    v.insert(v.end(), s, s + 4);
}

std::vector<std::uint8_t> BuildRiff(std::uint32_t formType,
                                    const std::vector<std::uint8_t>& fmtChunk,
                                    const std::vector<std::uint8_t>& dpdsChunk,
                                    const std::uint8_t* data, std::size_t dataSize)
{
    std::vector<std::uint8_t> out;
    out.reserve(dataSize + fmtChunk.size() + dpdsChunk.size() + 64);

    AppendTag(out, "RIFF");
    AppendU32(out, 0);  // patched at the end
    AppendU32(out, formType);

    AppendTag(out, "fmt ");
    AppendU32(out, static_cast<std::uint32_t>(fmtChunk.size()));
    out.insert(out.end(), fmtChunk.begin(), fmtChunk.end());
    if (fmtChunk.size() & 1) {
        out.push_back(0);
    }

    if (!dpdsChunk.empty()) {
        AppendTag(out, "dpds");
        AppendU32(out, static_cast<std::uint32_t>(dpdsChunk.size()));
        out.insert(out.end(), dpdsChunk.begin(), dpdsChunk.end());
        if (dpdsChunk.size() & 1) {
            out.push_back(0);
        }
    }

    AppendTag(out, "data");
    AppendU32(out, static_cast<std::uint32_t>(dataSize));
    out.insert(out.end(), data, data + dataSize);
    if (dataSize & 1) {
        out.push_back(0);
    }

    const std::uint32_t riffSize = static_cast<std::uint32_t>(out.size() - 8);
    std::memcpy(out.data() + 4, &riffSize, 4);
    return out;
}

std::vector<std::uint8_t> MakePcmFmtChunk(std::uint16_t channels, std::uint32_t rate)
{
    WaveFormatEx fmt{};
    fmt.formatTag = kFmtPCM;
    fmt.channels = channels;
    fmt.samplesPerSec = rate;
    fmt.bitsPerSample = 16;
    fmt.blockAlign = static_cast<std::uint16_t>(channels * 2);
    fmt.avgBytesPerSec = rate * fmt.blockAlign;

    std::vector<std::uint8_t> chunk(16);
    std::memcpy(chunk.data(), &fmt, 16);  // 16 bytes = classic PCM header, no cbSize
    return chunk;
}

std::vector<std::uint8_t> MakeSilentWav(std::uint16_t channels, std::uint32_t rate, double seconds)
{
    if (channels == 0 || channels > 2) channels = 1;
    if (rate < kMinSampleRate || rate > kMaxSampleRate) rate = 44100;

    const auto frames = static_cast<std::size_t>(rate * seconds);
    std::vector<std::uint8_t> silence(frames * channels * 2, 0);
    return BuildRiff(kWAVE, MakePcmFmtChunk(channels, rate), {}, silence.data(), silence.size());
}

std::int16_t ClampToI16(double v)
{
    if (v > 32767.0) return 32767;
    if (v < -32768.0) return -32768;
    return static_cast<std::int16_t>(v);
}

bool ConvertToPcm16(const std::uint8_t* src, std::size_t srcSize,
                    std::uint16_t tag, std::uint16_t bits, std::uint16_t channels,
                    std::vector<std::int16_t>& out)
{
    if (channels == 0 || bits == 0) {
        return false;
    }
    const std::size_t bytesPerSample = bits / 8u;
    if (bytesPerSample == 0) {
        return false;
    }
    const std::size_t sampleCount = srcSize / bytesPerSample;
    out.assign(sampleCount, 0);

    if (tag == kFmtPCM) {
        switch (bits) {
        case 8:
            for (std::size_t i = 0; i < sampleCount; ++i) {
                out[i] = static_cast<std::int16_t>((static_cast<int>(src[i]) - 128) << 8);
            }
            return true;
        case 16:
            if (sampleCount > 0) {
                std::memcpy(out.data(), src, sampleCount * 2);
            }
            return true;
        case 24:
            for (std::size_t i = 0; i < sampleCount; ++i) {
                const std::uint8_t* p = src + i * 3;
                const auto v = static_cast<std::int32_t>((static_cast<std::uint32_t>(p[2]) << 24) |
                                                         (static_cast<std::uint32_t>(p[1]) << 16) |
                                                         (static_cast<std::uint32_t>(p[0]) << 8));
                out[i] = static_cast<std::int16_t>(v >> 16);
            }
            return true;
        case 32:
            for (std::size_t i = 0; i < sampleCount; ++i) {
                std::int32_t v = 0;
                std::memcpy(&v, src + i * 4, 4);
                out[i] = static_cast<std::int16_t>(v >> 16);
            }
            return true;
        default:
            return false;
        }
    }

    if (tag == kFmtFloat) {
        if (bits == 32) {
            for (std::size_t i = 0; i < sampleCount; ++i) {
                float f = 0.0f;
                std::memcpy(&f, src + i * 4, 4);
                out[i] = ClampToI16(static_cast<double>(f) * 32767.0);
            }
            return true;
        }
        if (bits == 64) {
            for (std::size_t i = 0; i < sampleCount; ++i) {
                double d = 0.0;
                std::memcpy(&d, src + i * 8, 8);
                out[i] = ClampToI16(d * 32767.0);
            }
            return true;
        }
    }

    return false;
}

RepairResult RepairRiff(const Blob& blob, std::uint64_t base, const std::string& displayPath,
                        const RepairOptions& opts)
{
    RepairResult res;

    auto info = WalkRiff(blob, base);
    if (!info.valid || info.fmtChunk.empty()) {
        res.unfixable = true;
        return res;
    }

    WaveFormatEx fmt{};
    if (!ParseFormat(info.fmtChunk, fmt)) {
        res.unfixable = true;
        return res;
    }
    const std::uint16_t tag = EffectiveTag(info.fmtChunk, fmt);

    if (!info.haveData) {
        res.unfixable = true;
        return res;
    }

    std::uint64_t dataEnd = info.dataOffset + info.dataSize;
    bool clamped = false;
    if (dataEnd > blob.bytes.size()) {
        dataEnd = blob.bytes.size();
        clamped = true;
    }
    if (dataEnd <= info.dataOffset) {
        res.unfixable = true;
        return res;
    }
    const auto dataSize = static_cast<std::size_t>(dataEnd - info.dataOffset);
    const std::uint8_t* data = blob.bytes.data() + info.dataOffset;

    // ---- xWMA: header repairs only, the payload is opaque to us -------
    if (info.formType == kXWMA || tag == kFmtWMAudio2 || tag == kFmtWMAudio3) {
        if (!info.haveDpds || info.dpdsChunk.size() < 4) {
            res.unfixable = true;
            res.actions.push_back("xWMA without a usable dpds seek table cannot be repaired "
                                  "without re-encoding");
            return res;
        }
        if (!info.truncated && !info.chunkOverrun && !clamped) {
            return res;  // already fine
        }
        res.data = BuildRiff(kXWMA, info.fmtChunk, info.dpdsChunk, data, dataSize);
        res.changed = true;
        res.actions.push_back(std::format(
            "rebuilt the xWMA container around the {} bytes of audio that exist", dataSize));
        return res;
    }

    // ---- linear PCM family -------------------------------------------
    if (tag != kFmtPCM && tag != kFmtFloat) {
        res.unfixable = true;
        res.actions.push_back(std::format(
            "{} (0x{:04X}) would have to be re-encoded, which needs a real audio tool",
            FormatTagName(tag), tag));
        return res;
    }

    std::uint16_t channels = fmt.channels;
    if (channels == 0 || channels > kMaxChannels) {
        res.unfixable = true;
        res.actions.push_back("channel count is not recoverable from the header");
        return res;
    }

    std::uint32_t rate = fmt.samplesPerSec;
    bool rateFixed = false;
    if (rate < kMinSampleRate || rate > kMaxSampleRate) {
        rate = 44100;
        rateFixed = true;
    }

    std::vector<std::int16_t> samples;
    if (!ConvertToPcm16(data, dataSize, tag, fmt.bitsPerSample, channels, samples)) {
        res.unfixable = true;
        res.actions.push_back(std::format("{}-bit {} could not be converted to 16-bit PCM",
                                          fmt.bitsPerSample, FormatTagName(tag)));
        return res;
    }
    if (samples.empty()) {
        res.unfixable = true;
        return res;
    }

    // Drop a trailing partial frame so the payload is a whole number of frames.
    if (channels > 1 && (samples.size() % channels) != 0) {
        samples.resize(samples.size() - (samples.size() % channels));
    }

    const bool converted = (tag != kFmtPCM || fmt.bitsPerSample != 16);
    bool downmixed = false;

    std::string lower = displayPath;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) {
                       c = static_cast<unsigned char>(std::tolower(c));
                       return static_cast<char>(c == '\\' ? '/' : c);
                   });
    const bool inFx = lower.find("sound/fx/") != std::string::npos;

    if (opts.monoFx && inFx && channels == 2 && samples.size() >= 2) {
        std::vector<std::int16_t> mono(samples.size() / 2);
        for (std::size_t i = 0; i < mono.size(); ++i) {
            mono[i] = static_cast<std::int16_t>(
                (static_cast<int>(samples[i * 2]) + static_cast<int>(samples[i * 2 + 1])) / 2);
        }
        samples = std::move(mono);
        channels = 1;
        downmixed = true;
    }

    const auto expectedAlign = static_cast<std::uint16_t>(fmt.channels * (fmt.bitsPerSample / 8));
    const bool headerBad = (expectedAlign == 0) || (fmt.blockAlign != expectedAlign) ||
                           (fmt.avgBytesPerSec != fmt.samplesPerSec * expectedAlign) ||
                           (fmt.formatTag == kFmtExtensible);

    if (!converted && !downmixed && !rateFixed && !clamped && !headerBad &&
        !info.truncated && !info.chunkOverrun) {
        return res;  // genuinely clean
    }

    res.data = BuildRiff(kWAVE, MakePcmFmtChunk(channels, rate), {},
                         reinterpret_cast<const std::uint8_t*>(samples.data()),
                         samples.size() * 2);
    res.changed = true;

    if (converted) {
        res.actions.push_back(std::format("converted {}-bit {} to 16-bit PCM",
                                          fmt.bitsPerSample, FormatTagName(tag)));
    }
    if (fmt.formatTag == kFmtExtensible) {
        res.actions.push_back("rewrote the WAVE_FORMAT_EXTENSIBLE header as a plain PCM header");
    }
    if (headerBad && !converted && fmt.formatTag != kFmtExtensible) {
        res.actions.push_back(std::format("corrected the header (blockAlign {} -> {})",
                                          fmt.blockAlign, channels * 2));
    }
    if (rateFixed) {
        res.actions.push_back(std::format("replaced an out-of-range sample rate ({} Hz) with "
                                          "44100 Hz - pitch will be wrong, but it will play",
                                          fmt.samplesPerSec));
    }
    if (clamped || info.truncated || info.chunkOverrun) {
        res.actions.push_back("rebuilt a truncated container around the audio that exists");
    }
    if (downmixed) {
        res.actions.push_back("downmixed stereo to mono for 3D positioning");
    }

    return res;
}

RepairResult RepairAsset(const Blob& blob, const std::string& displayPath, std::string_view ext,
                         const RepairOptions& opts)
{
    RepairResult res;

    if (!blob.complete) {
        res.unfixable = true;
        res.actions.push_back("only part of the asset was read, so it was not repaired "
                              "(raise --window)");
        return res;
    }

    // ---- .fuz ---------------------------------------------------------
    if (ext == ".fuz") {
        bool good = false;
        const auto magic = blob.U32At(0, good);

        std::uint64_t audioOffset = UINT64_MAX;
        std::uint32_t lipSize = 0;
        bool          rebuildHeader = false;
        bool          keepLip = false;

        if (good && magic == kFUZE) {
            lipSize = blob.U32At(8, good);
            const std::uint64_t declared = 12ull + lipSize;
            RiffInfo probe;
            if (declared + 12 <= blob.bytes.size()) {
                probe = WalkRiff(blob, declared);
            }
            if (probe.valid) {
                audioOffset = declared;
                keepLip = true;
            } else {
                audioOffset = FindEmbeddedRiff(blob, 12);
                if (audioOffset != UINT64_MAX) {
                    lipSize = static_cast<std::uint32_t>(audioOffset - 12);
                    rebuildHeader = true;
                    keepLip = true;
                    res.actions.push_back(std::format(
                        "corrected the FUZE LIP length to {} so it points at the embedded RIFF",
                        lipSize));
                }
            }
        } else if (good && magic == kRIFF) {
            audioOffset = 0;
            lipSize = 0;
            rebuildHeader = true;
            res.actions.push_back("wrapped a bare RIFF in a FUZE header with an empty LIP block");
        }

        if (audioOffset == UINT64_MAX) {
            res.unfixable = true;
            return res;
        }

        auto inner = RepairRiff(blob, audioOffset, displayPath, opts);
        if (inner.unfixable && !rebuildHeader) {
            res.unfixable = true;
            res.actions.insert(res.actions.end(), inner.actions.begin(), inner.actions.end());
            return res;
        }
        if (inner.unfixable && rebuildHeader) {
            res.unfixable = true;
            res.actions.insert(res.actions.end(), inner.actions.begin(), inner.actions.end());
            return res;
        }
        if (!rebuildHeader && !inner.changed) {
            return res;  // nothing to do
        }

        std::vector<std::uint8_t> innerBytes;
        if (!inner.data.empty()) {
            innerBytes = std::move(inner.data);
            res.actions.insert(res.actions.end(), inner.actions.begin(), inner.actions.end());
        } else {
            innerBytes.assign(blob.bytes.begin() + static_cast<std::ptrdiff_t>(audioOffset),
                              blob.bytes.end());
        }

        std::vector<std::uint8_t> lip;
        if (keepLip && lipSize > 0) {
            const auto lipEnd = (std::min)(static_cast<std::uint64_t>(12) + lipSize,
                                           static_cast<std::uint64_t>(blob.bytes.size()));
            if (lipEnd > 12) {
                lip.assign(blob.bytes.begin() + 12,
                           blob.bytes.begin() + static_cast<std::ptrdiff_t>(lipEnd));
            }
        }

        res.data.clear();
        AppendTag(res.data, "FUZE");
        AppendU32(res.data, 1);
        AppendU32(res.data, static_cast<std::uint32_t>(lip.size()));
        res.data.insert(res.data.end(), lip.begin(), lip.end());
        res.data.insert(res.data.end(), innerBytes.begin(), innerBytes.end());
        res.changed = true;
        return res;
    }

    // ---- .wav / .xwm --------------------------------------------------
    auto result = RepairRiff(blob, 0, displayPath, opts);

    if (result.unfixable && opts.placeholders) {
        auto info = WalkRiff(blob, 0);
        WaveFormatEx fmt{};
        std::uint16_t ch = 1;
        std::uint32_t rate = 44100;
        if (ParseFormat(info.fmtChunk, fmt)) {
            if (fmt.channels >= 1 && fmt.channels <= 2) ch = fmt.channels;
            if (fmt.samplesPerSec >= kMinSampleRate && fmt.samplesPerSec <= kMaxSampleRate) {
                rate = fmt.samplesPerSec;
            }
        }
        result.data = MakeSilentWav(ch, rate, 0.10);
        result.changed = true;
        result.unfixable = false;
        result.isPlaceholder = true;
        result.actions.push_back("replaced with 0.1 s of silence because the audio itself could "
                                 "not be recovered");
    }

    return result;
}

// =====================================================================
//  BSA reading
// =====================================================================

struct BsaEntry {
    std::string   path;
    std::uint64_t offset{ 0 };
    std::uint32_t size{ 0 };
    bool          compressed{ false };
};

struct BsaArchive {
    bool                  ok{ false };
    std::string           error;
    std::uint32_t         version{ 0 };
    bool                  embedFileNames{ false };
    std::vector<BsaEntry> entries;
};

BsaArchive ReadBsaIndex(const fs::path& path)
{
    BsaArchive out;

    std::ifstream f{ path, std::ios::binary };
    if (!f) {
        out.error = "could not open the archive";
        return out;
    }

    struct Header {
        char          magic[4];
        std::uint32_t version;
        std::uint32_t folderRecordOffset;
        std::uint32_t archiveFlags;
        std::uint32_t folderCount;
        std::uint32_t fileCount;
        std::uint32_t totalFolderNameLength;
        std::uint32_t totalFileNameLength;
        std::uint32_t fileFlags;
    } hdr{};

    f.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (f.gcount() != sizeof(hdr)) {
        out.error = "file is too small to be a BSA";
        return out;
    }
    if (std::memcmp(hdr.magic, "BSA\0", 4) != 0) {
        out.error = "not a BSA archive (bad magic)";
        return out;
    }
    if (hdr.version == 103 || hdr.version == 104) {
        out.error = std::format("this is a Skyrim LE archive (BSA v{}). This tool targets "
                                "Special Edition and does not decode LE compression",
                                hdr.version);
        return out;
    }
    if (hdr.version != 105) {
        out.error = std::format("unsupported BSA version {}", hdr.version);
        return out;
    }

    out.version = hdr.version;
    const bool includeDirNames = (hdr.archiveFlags & 0x1) != 0;
    const bool includeFileNames = (hdr.archiveFlags & 0x2) != 0;
    const bool defaultCompressed = (hdr.archiveFlags & 0x4) != 0;
    out.embedFileNames = (hdr.archiveFlags & 0x100) != 0;

    if (!includeFileNames) {
        out.error = "archive does not store file names, so its contents cannot be identified";
        return out;
    }

    struct Folder {
        std::uint32_t count;
        std::uint64_t offset;
    };
    std::vector<Folder> folders;
    folders.reserve(hdr.folderCount);

    f.seekg(hdr.folderRecordOffset, std::ios::beg);
    for (std::uint32_t i = 0; i < hdr.folderCount; ++i) {
        std::uint64_t nameHash = 0;
        std::uint32_t count = 0;
        f.read(reinterpret_cast<char*>(&nameHash), 8);
        f.read(reinterpret_cast<char*>(&count), 4);

        std::uint32_t padding = 0;
        std::uint64_t offset = 0;
        f.read(reinterpret_cast<char*>(&padding), 4);
        f.read(reinterpret_cast<char*>(&offset), 8);
        if (!f) {
            out.error = "truncated folder record table";
            return out;
        }
        folders.push_back({ count, offset });
    }

    struct RawFile {
        std::uint32_t size;
        std::uint32_t offset;
    };
    std::vector<std::string> folderNames;
    std::vector<RawFile>     rawFiles;
    std::vector<std::size_t> fileFolderIndex;
    rawFiles.reserve(hdr.fileCount);

    for (std::size_t i = 0; i < folders.size(); ++i) {
        const std::uint64_t blockPos = folders[i].offset - hdr.totalFileNameLength;
        f.seekg(static_cast<std::streamoff>(blockPos), std::ios::beg);

        std::string folderName;
        if (includeDirNames) {
            std::uint8_t len = 0;
            f.read(reinterpret_cast<char*>(&len), 1);
            if (len > 0) {
                std::string buf(len, '\0');
                f.read(buf.data(), len);
                if (!buf.empty() && buf.back() == '\0') {
                    buf.pop_back();
                }
                folderName = std::move(buf);
            }
        }
        folderNames.push_back(folderName);

        for (std::uint32_t j = 0; j < folders[i].count; ++j) {
            std::uint64_t nameHash = 0;
            RawFile rf{};
            f.read(reinterpret_cast<char*>(&nameHash), 8);
            f.read(reinterpret_cast<char*>(&rf.size), 4);
            f.read(reinterpret_cast<char*>(&rf.offset), 4);
            if (!f) {
                out.error = "truncated file record block";
                return out;
            }
            rawFiles.push_back(rf);
            fileFolderIndex.push_back(i);
        }
    }

    std::vector<char> nameBlock(hdr.totalFileNameLength);
    f.read(nameBlock.data(), static_cast<std::streamsize>(nameBlock.size()));
    if (!f) {
        out.error = "truncated file name block";
        return out;
    }

    std::vector<std::string> fileNames;
    fileNames.reserve(hdr.fileCount);
    {
        std::size_t pos = 0;
        while (pos < nameBlock.size() && fileNames.size() < rawFiles.size()) {
            const auto start = pos;
            while (pos < nameBlock.size() && nameBlock[pos] != '\0') {
                ++pos;
            }
            fileNames.emplace_back(nameBlock.data() + start, pos - start);
            ++pos;
        }
    }

    if (fileNames.size() != rawFiles.size()) {
        out.error = std::format("name block holds {} names for {} file records",
                                fileNames.size(), rawFiles.size());
        return out;
    }

    out.entries.reserve(rawFiles.size());
    for (std::size_t i = 0; i < rawFiles.size(); ++i) {
        BsaEntry e;
        const auto& folder = folderNames[fileFolderIndex[i]];
        e.path = folder.empty() ? fileNames[i] : folder + "\\" + fileNames[i];

        const bool invert = (rawFiles[i].size & 0x40000000u) != 0;
        e.size = rawFiles[i].size & 0x3FFFFFFFu;
        e.compressed = defaultCompressed != invert;
        e.offset = rawFiles[i].offset;
        out.entries.push_back(std::move(e));
    }

    out.ok = true;
    return out;
}

// Pulls one entry out of an archive, decompressing if necessary.
bool ExtractEntry(std::ifstream& f, const BsaArchive& bsa, const BsaEntry& e,
                  std::vector<std::uint8_t>& out, std::string& error)
{
    out.clear();
    if (e.size == 0) {
        error = "zero-length entry";
        return false;
    }

    std::uint32_t remaining = e.size;

    f.clear();
    f.seekg(static_cast<std::streamoff>(e.offset), std::ios::beg);

    if (bsa.embedFileNames) {
        std::uint8_t nameLen = 0;
        f.read(reinterpret_cast<char*>(&nameLen), 1);
        if (!f) {
            error = "could not read the embedded name prefix";
            return false;
        }
        f.seekg(nameLen, std::ios::cur);
        if (remaining < 1u + nameLen) {
            error = "entry is smaller than its embedded name";
            return false;
        }
        remaining -= (1u + nameLen);
    }

    if (!e.compressed) {
        out.resize(remaining);
        f.read(reinterpret_cast<char*>(out.data()), remaining);
        out.resize(static_cast<std::size_t>(f.gcount()));
        if (out.empty()) {
            error = "could not read the entry payload";
            return false;
        }
        return true;
    }

    if (remaining < 4) {
        error = "compressed entry is too small to hold its size field";
        return false;
    }
    std::uint32_t originalSize = 0;
    f.read(reinterpret_cast<char*>(&originalSize), 4);
    if (!f) {
        error = "could not read the uncompressed size field";
        return false;
    }
    remaining -= 4;

    constexpr std::uint32_t kMaxUncompressed = 256u * 1024u * 1024u;
    if (originalSize == 0 || originalSize > kMaxUncompressed) {
        error = std::format("implausible uncompressed size ({} bytes)", originalSize);
        return false;
    }

    std::vector<std::uint8_t> packed(remaining);
    f.read(reinterpret_cast<char*>(packed.data()), remaining);
    packed.resize(static_cast<std::size_t>(f.gcount()));
    if (packed.empty()) {
        error = "could not read the compressed payload";
        return false;
    }

    if (!Lz4BlockDecompress(packed.data(), packed.size(), out, originalSize)) {
        error = "LZ4 decompression failed - the entry may be damaged";
        return false;
    }

    return true;
}

// =====================================================================
//  Scanning and the override folder
// =====================================================================

struct Options {
    std::vector<fs::path> roots;
    bool          scanBsa = true;
    bool          scanLoose = true;
    bool          showWarnings = true;
    bool          listAll = false;
    std::uint64_t window = 16ull << 20;
    fs::path      outFile = "XAudioScan_Report.txt";
    fs::path      fixDir;
    RepairOptions repair;
};

struct Stats {
    std::uint64_t scanned = 0;
    std::uint64_t fatal = 0;
    std::uint64_t warnings = 0;
    std::uint64_t archives = 0;
    std::uint64_t decompressed = 0;
    std::uint64_t decompressFailed = 0;
    std::uint64_t repaired = 0;
    std::uint64_t placeholders = 0;
    std::uint64_t unfixable = 0;
};

class Output {
public:
    explicit Output(const fs::path& p) : file_(p, std::ios::trunc) {}
    bool Ok() const { return file_.good(); }
    void Line(const std::string& s)
    {
        std::cout << s << '\n';
        file_ << s << '\n';
    }
    void Flush()
    {
        std::cout.flush();
        file_.flush();
    }

private:
    std::ofstream file_;
};

std::string LowerExt(const fs::path& p)
{
    auto ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return ext;
}

bool IsAudioExt(std::string_view ext)
{
    return ext == ".wav" || ext == ".xwm" || ext == ".fuz";
}

// Reduces a path to the part Skyrim's Data folder would see, so an override
// built from "D:\MO2\mods\Some Mod\Sound\FX\x.wav" lands at "Sound/FX/x.wav".
std::string DataRelativePath(const std::string& path)
{
    std::string norm = path;
    std::replace(norm.begin(), norm.end(), '\\', '/');

    // Archive entries arrive as "Some.bsa::sound/fx/x.wav" - drop the prefix.
    const auto sep = norm.find("::");
    if (sep != std::string::npos) {
        norm = norm.substr(sep + 2);
    }

    std::string lower = norm;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    static const char* tops[] = { "sound/", "music/", "video/" };
    std::size_t best = std::string::npos;
    for (const char* top : tops) {
        std::size_t at = std::string::npos;
        if (lower.rfind(top, 0) == 0) {
            at = 0;
        } else {
            const auto found = lower.find(std::string{ "/" } + top);
            if (found != std::string::npos) {
                at = found + 1;
            }
        }
        if (at != std::string::npos && (best == std::string::npos || at < best)) {
            best = at;
        }
    }

    if (best != std::string::npos) {
        return norm.substr(best);
    }
    return norm;
}

class OverrideWriter {
public:
    OverrideWriter(fs::path root, Output& out) : root_(std::move(root)), out_(out) {}

    bool Enabled() const { return !root_.empty(); }

    void Write(const std::string& displayPath, const std::vector<std::uint8_t>& data,
               const std::vector<std::string>& actions, bool placeholder, Stats& stats)
    {
        const auto rel = DataRelativePath(displayPath);
        const auto target = root_ / fs::path{ rel };

        auto [it, inserted] = written_.try_emplace(rel, displayPath);
        if (!inserted) {
            out_.Line(std::format("    note: {} was already written from {} - keeping the first "
                                  "version and skipping this one", rel, it->second));
            return;
        }

        std::error_code ec;
        fs::create_directories(target.parent_path(), ec);

        std::ofstream f{ target, std::ios::binary | std::ios::trunc };
        if (!f) {
            out_.Line(std::format("    !! could not write {}", target.string()));
            return;
        }
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));

        ++stats.repaired;
        if (placeholder) {
            ++stats.placeholders;
        }
        out_.Line(std::format("    FIXED -> {}", rel));
        for (const auto& a : actions) {
            out_.Line(std::format("      - {}", a));
        }
    }

    void WriteManifest(const Stats& stats)
    {
        if (root_.empty()) {
            return;
        }
        std::error_code ec;
        fs::create_directories(root_, ec);
        std::ofstream f{ root_ / "XAudioScan_Override_README.txt", std::ios::trunc };
        if (!f) {
            return;
        }
        f << "Override folder generated by XAudioScan\n"
          << "=======================================\n\n"
          << stats.repaired << " files were rebuilt";
        if (stats.placeholders > 0) {
            f << ", of which " << stats.placeholders << " are silent placeholders";
        }
        f << ".\n\n"
          << "HOW TO USE\n"
          << "  1. Zip this folder. Sound\\ and Music\\ should sit at the root of the zip.\n"
          << "  2. Install the zip with Mod Organizer 2 or Vortex like any other mod.\n"
          << "  3. Place it LAST in your load order so it wins every conflict.\n\n"
          << "Loose files always beat files packed inside a BSA, so this also overrides\n"
          << "broken audio that lives inside an archive.\n\n"
          << "WHAT WAS DONE\n"
          << "  Headers were rebuilt and sample data was converted between linear PCM\n"
          << "  formats. Nothing was re-encoded through a lossy codec.\n\n"
          << "  Files listed as silent placeholders could not be recovered at all. They\n"
          << "  play silence instead of crashing. Getting a real replacement from the mod\n"
          << "  author is still the better fix.\n\n"
          << "  Keep the scan report next to this folder so you know what changed.\n";
    }

private:
    fs::path                           root_;
    Output&                            out_;
    std::map<std::string, std::string> written_;
};

void HandleAsset(const Blob& blob, const std::string& display, std::string_view ext,
                 Output& out, const Options& opts, Stats& stats, OverrideWriter& fixer)
{
    auto report = InspectBlob(blob, display, ext);

    if (report.Clean()) {
        if (opts.listAll) {
            out.Line(std::format("[ok]         {}", display));
        }
        return;
    }
    if (report.severity == Severity::Warning && !opts.showWarnings) {
        return;
    }

    if (report.Fatal()) {
        ++stats.fatal;
        out.Line(std::format("[WILL CRASH] {}", display));
    } else {
        ++stats.warnings;
        out.Line(std::format("[SUSPICIOUS] {}", display));
    }
    for (const auto& f : report.findings) {
        out.Line(std::format("    why: {}", f.reason));
        out.Line(std::format("    fix: {}", f.fix));
    }

    if (fixer.Enabled()) {
        auto repair = RepairAsset(blob, display, ext, opts.repair);
        if (repair.changed && !repair.data.empty()) {
            fixer.Write(display, repair.data, repair.actions, repair.isPlaceholder, stats);
        } else if (repair.unfixable) {
            ++stats.unfixable;
            out.Line("    NOT FIXED - needs a real audio tool");
            for (const auto& a : repair.actions) {
                out.Line(std::format("      - {}", a));
            }
        }
    }

    out.Line("");
    out.Flush();
}

void ScanLooseFile(const fs::path& path, const fs::path& root, Output& out,
                   const Options& opts, Stats& stats, OverrideWriter& fixer)
{
    const auto ext = LowerExt(path);
    if (!IsAudioExt(ext)) {
        return;
    }
    ++stats.scanned;

    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec) {
        return;
    }

    Blob blob;
    blob.trueSize = size;
    const auto toRead = static_cast<std::size_t>((std::min)(size, opts.window));
    blob.complete = (toRead == size);
    blob.bytes.resize(toRead);

    if (toRead > 0) {
        std::ifstream f{ path, std::ios::binary };
        if (!f) {
            return;
        }
        f.read(reinterpret_cast<char*>(blob.bytes.data()), static_cast<std::streamsize>(toRead));
        blob.bytes.resize(static_cast<std::size_t>(f.gcount()));
    }

    auto rel = fs::relative(path, root, ec);
    const auto display = ec ? path.string() : rel.string();

    HandleAsset(blob, display, ext, out, opts, stats, fixer);
}

void ScanArchive(const fs::path& path, Output& out, const Options& opts, Stats& stats,
                 OverrideWriter& fixer)
{
    auto bsa = ReadBsaIndex(path);
    ++stats.archives;

    if (!bsa.ok) {
        out.Line(std::format("[archive]    {} - could not read index: {}",
                             path.filename().string(), bsa.error));
        out.Line("");
        return;
    }

    std::ifstream f{ path, std::ios::binary };
    if (!f) {
        return;
    }

    std::uint64_t audioCount = 0;
    for (const auto& e : bsa.entries) {
        const auto ext = LowerExt(fs::path{ e.path });
        if (!IsAudioExt(ext)) {
            continue;
        }
        ++audioCount;
        ++stats.scanned;

        const auto display = std::format("{}::{}", path.filename().string(), e.path);

        std::vector<std::uint8_t> raw;
        std::string error;
        if (!ExtractEntry(f, bsa, e, raw, error)) {
            if (e.compressed) {
                ++stats.decompressFailed;
            }
            ++stats.fatal;
            out.Line(std::format("[WILL CRASH] {}", display));
            out.Line(std::format("    why: Could not read this entry out of the archive: {}.", error));
            out.Line("    fix: The archive itself may be damaged. Try opening it in BSA Browser.");
            out.Line("");
            continue;
        }

        if (e.compressed) {
            ++stats.decompressed;
        }

        Blob blob;
        blob.trueSize = raw.size();
        blob.bytes = std::move(raw);
        blob.complete = true;

        HandleAsset(blob, display, ext, out, opts, stats, fixer);
    }

    out.Line(std::format("[archive]    {} - v{}, {} audio entries of {} total",
                         path.filename().string(), bsa.version, audioCount, bsa.entries.size()));
    out.Flush();
}

void ScanRoot(const fs::path& root, Output& out, const Options& opts, Stats& stats,
              OverrideWriter& fixer)
{
    std::error_code ec;

    if (fs::is_regular_file(root, ec)) {
        const auto ext = LowerExt(root);
        if (ext == ".bsa" && opts.scanBsa) {
            ScanArchive(root, out, opts, stats, fixer);
        } else if (IsAudioExt(ext)) {
            ScanLooseFile(root, root.parent_path(), out, opts, stats, fixer);
        }
        return;
    }

    if (!fs::is_directory(root, ec)) {
        out.Line(std::format("!! Not a file or directory: {}", root.string()));
        return;
    }

    fs::recursive_directory_iterator it{ root, fs::directory_options::skip_permission_denied, ec };
    const fs::recursive_directory_iterator end;

    for (; it != end; it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        const auto& entry = *it;
        if (!entry.is_regular_file(ec) || ec) {
            ec.clear();
            continue;
        }

        const auto ext = LowerExt(entry.path());
        if (ext == ".bsa") {
            if (opts.scanBsa) {
                ScanArchive(entry.path(), out, opts, stats, fixer);
            }
        } else if (opts.scanLoose) {
            ScanLooseFile(entry.path(), root, out, opts, stats, fixer);
        }
    }
}


// =====================================================================
//  Interactive mode (used when the exe is launched with no arguments)
// =====================================================================

std::string TrimPath(std::string s)
{
    // Windows "Copy as path" wraps the path in quotes, and drag-and-drop
    // onto a console leaves trailing whitespace.
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '"')) {
        s.erase(s.begin());
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '"' ||
                          s.back() == '\r' || s.back() == '\n')) {
        s.pop_back();
    }
    return s;
}

std::string Ask(const std::string& question, const std::string& fallback)
{
    if (fallback.empty()) {
        std::cout << question << "\n> ";
    } else {
        std::cout << question << "\n[" << fallback << "]\n> ";
    }
    std::string line;
    std::getline(std::cin, line);
    line = TrimPath(line);
    return line.empty() ? fallback : line;
}

bool AskYesNo(const std::string& question, bool fallback)
{
    std::cout << question << (fallback ? " [Y/n] " : " [y/N] ");
    std::string line;
    std::getline(std::cin, line);
    line = TrimPath(line);
    if (line.empty()) {
        return fallback;
    }
    const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(line[0])));
    return c == 'y';
}

// Returns false if the user backed out.
bool RunInteractive(Options& opts)
{
    std::cout << "XAudioScan - Skyrim SE audio checker\n"
              << "====================================\n\n"
              << "Tip: you can drag a folder onto this window instead of typing the path.\n\n";

    for (;;) {
        const auto path = Ask("Which folder do you want to scan?\n"
                              "  (your Data folder, or Mod Organizer's mods folder)",
                              "");
        if (path.empty()) {
            std::cout << "No path given - nothing to do.\n";
            return false;
        }

        std::error_code ec;
        if (!fs::exists(path, ec)) {
            std::cout << "\nThat path does not exist. Try again.\n\n";
            continue;
        }
        opts.roots.emplace_back(path);
        break;
    }

    std::cout << "\n";
    if (AskYesNo("Build an override folder with repaired copies?", true)) {
        for (;;) {
            const auto dir = Ask("\nWhere should the repaired files go?\n"
                                 "  (a new empty folder - you will zip this and install it "
                                 "as a mod)",
                                 (fs::current_path() / "XAudioScan_Override").string());
            if (dir.empty()) {
                break;
            }

            std::error_code ec;
            if (fs::exists(dir, ec) && !fs::is_empty(dir, ec)) {
                std::cout << "\nThat folder already has files in it. Existing files with the\n"
                             "same names will be overwritten.\n";
                if (!AskYesNo("Use it anyway?", false)) {
                    continue;
                }
            }

            fs::create_directories(dir, ec);
            if (ec) {
                std::cout << "\nCould not create that folder: " << ec.message() << "\n\n";
                continue;
            }
            opts.fixDir = dir;
            break;
        }

        if (!opts.fixDir.empty()) {
            std::cout << "\n";
            opts.repair.monoFx = AskYesNo(
                "Downmix stereo files under Sound\\FX to mono?\n"
                "  (Skyrim positions these in 3D, which wants mono. Safe, but it does\n"
                "   change the audio.)", false);
            opts.repair.placeholders = AskYesNo(
                "\nReplace unrecoverable files with silence?\n"
                "  (Stops the crash, but you lose that sound entirely. Off means those\n"
                "   files are only listed, not fixed.)", false);
        }
    }

    std::cout << "\n";
    opts.showWarnings = AskYesNo("Include 'suspicious' files as well as definite failures?", true);

    std::cout << "\n----------------------------------------------------------------\n\n";
    return true;
}

// =====================================================================
//  Entry point
// =====================================================================

void PrintUsage()
{
    std::cout << R"(XAudioScan - finds and repairs Skyrim audio that XAudio2 2.7 cannot play

Usage:
  XAudioScan.exe [options] <path> [<path> ...]

Run with no arguments to be prompted for everything instead.

Targets Skyrim Special Edition. A path can be a folder (scanned
recursively), a single .bsa, or a single audio file. Point it at your Data
folder, or at Mod Organizer's mods folder to check every mod at once.
Compressed BSA entries are decompressed in memory. Skyrim LE archives
(BSA v103/v104) are reported and skipped.

Scanning:
  --no-bsa          Skip .bsa archives, scan loose files only
  --no-loose        Skip loose files, scan archives only
  --fatal-only      Report only files that will definitely fail
  --list-all        Also list files that pass
  --out <file>      Report path (default: XAudioScan_Report.txt)
  --window <bytes>  Max bytes read per loose file (default: 16777216)

Repair:
  --fix <folder>    Write repaired copies into <folder>, laid out like Data\
                    so it can be zipped and installed as an override mod
  --mono-fx         Also downmix stereo files under Sound\FX to mono
  --placeholder     For assets that cannot be recovered, emit a short silent
                    file instead. Silence beats a crash, but you lose the
                    sound - prefer a real replacement from the mod author

  --help            This text

Exit code is 1 if anything fatal was found, otherwise 0.

Examples:
  XAudioScan.exe "C:\Steam\steamapps\common\Skyrim Special Edition\Data"
  XAudioScan.exe --fatal-only "D:\MO2\mods"
  XAudioScan.exe --fix "D:\AudioFix" "D:\MO2\mods"
)";
}

int main(int argc, char* argv[])
{
    Options opts;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h" || arg == "/?") {
            PrintUsage();
            return 0;
        } else if (arg == "--no-bsa") {
            opts.scanBsa = false;
        } else if (arg == "--no-loose") {
            opts.scanLoose = false;
        } else if (arg == "--fatal-only") {
            opts.showWarnings = false;
        } else if (arg == "--list-all") {
            opts.listAll = true;
        } else if (arg == "--mono-fx") {
            opts.repair.monoFx = true;
        } else if (arg == "--placeholder") {
            opts.repair.placeholders = true;
        } else if (arg == "--out" && i + 1 < argc) {
            opts.outFile = argv[++i];
        } else if (arg == "--fix" && i + 1 < argc) {
            opts.fixDir = argv[++i];
        } else if (arg == "--window" && i + 1 < argc) {
            opts.window = std::strtoull(argv[++i], nullptr, 10);
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n\n";
            PrintUsage();
            return 2;
        } else {
            opts.roots.emplace_back(arg);
        }
    }

    const bool interactive = (argc == 1);
    if (interactive) {
        if (!RunInteractive(opts)) {
            return 2;
        }
    }

    if (opts.roots.empty()) {
        PrintUsage();
        return 2;
    }

    Output out{ opts.outFile };
    if (!out.Ok()) {
        std::cerr << "Could not open report file: " << opts.outFile.string() << "\n";
        return 2;
    }

    OverrideWriter fixer{ opts.fixDir, out };

    out.Line("XAudioScan report");
    out.Line("[WILL CRASH] means a hard XAudio2 2.7 constraint is violated.");
    out.Line("[SUSPICIOUS] means it is legal but a known source of trouble.");
    if (fixer.Enabled()) {
        out.Line(std::format("Repairs will be written to {}", opts.fixDir.string()));
    }
    out.Line("----------------------------------------------------------------");
    out.Line("");

    const auto start = std::chrono::steady_clock::now();
    Stats stats;

    for (const auto& root : opts.roots) {
        out.Line(std::format("Scanning {}", root.string()));
        out.Line("");
        ScanRoot(root, out, opts, stats, fixer);
    }

    fixer.WriteManifest(stats);

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start).count();

    out.Line("----------------------------------------------------------------");
    out.Line(std::format("Scanned {} audio assets across {} archives in {} ms.",
                         stats.scanned, stats.archives, ms));
    out.Line(std::format("{} will crash, {} suspicious.", stats.fatal, stats.warnings));
    if (stats.decompressed > 0 || stats.decompressFailed > 0) {
        out.Line(std::format("Decompressed {} archived entries ({} failed).",
                             stats.decompressed, stats.decompressFailed));
    }
    if (fixer.Enabled()) {
        out.Line(std::format("Repaired {} files ({} silent placeholders), {} could not be fixed.",
                             stats.repaired, stats.placeholders, stats.unfixable));
        out.Line(std::format("Override folder: {}", opts.fixDir.string()));
        out.Line("Zip it and install it last in your load order.");
    }
    out.Line(std::format("Report written to {}", opts.outFile.string()));

    if (interactive) {
        std::cout << "\nPress Enter to close.";
        std::string dummy;
        std::getline(std::cin, dummy);
    }

    return stats.fatal > 0 ? 1 : 0;
}
