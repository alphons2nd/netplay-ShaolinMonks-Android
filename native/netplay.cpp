// Co-op over the network by lockstep. Both phones run the whole game and trade only the pads: the host is player 1
// (port 0), the guest player 2 (port 1). Every gameplay frame (the hook in src/game/game.cpp) each side takes its pad,
// files it kInputDelay frames ahead, sends it and waits for the friend's pad of the same frame, so both games read the
// same two pads on the same frame. That only keeps them together if the game is deterministic from there, so a hash of
// the game's memory is traded as well and a difference is logged (the first sign that an RNG or a clock is not synced).
//
// UDP carries the frames: every packet repeats the pads the friend has not acknowledged, so a lost packet costs
// nothing. A "gap" (no gameplay frame for a second: a menu, a load) drops back to the phone's own pad, and the next
// gameplay frame starts a new epoch: a barrier both sides pass together, frame 0 again, the host's chosen guest memory
// copied over (Options::netplay_sync, for an RNG state). TCP on the same port copies the host's saves to the guest when
// it joins.
#include "netplay.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "app/app.h"
#include "common/options.h"
#include "core/input.h"
#include "core/log.h"
#include "kernel/kernel.h"

namespace netplay {

namespace {

using Clock = std::chrono::steady_clock;
namespace fs = std::filesystem;

constexpr uint32_t kMagic = 0x504E4D53;      // "SMNP"
constexpr uint32_t kSaveMagic = 0x56534D53;  // "SMSV"
constexpr uint8_t kVersion = 1;
enum Type : uint8_t { kHello = 1, kWelcome, kInput, kSync, kPing, kPong, kBye, kPad };

constexpr uint32_t kRing = 1024;      // frames kept, far more than the delay and the retransmit window
constexpr uint32_t kMaxSend = 32;     // frames in a packet
constexpr uint32_t kHashEvery = 60;   // frames between two state hashes
constexpr uint32_t kHashSlots = 64;
constexpr int kGapMs = 1000;          // no gameplay frame for this long: back to the phone's own pad
constexpr int kDeadMs = 6000;         // no packet for this long: the link is gone
constexpr size_t kPayloadMax = 1100;  // the barrier's guest memory, in one packet
// guest memory the hash covers without any setting: the image's data and bss, up to the page of 0x5CAB98
constexpr uint32_t kHashLo = 0x4A0000, kHashHi = 0x5CB000;
constexpr uint32_t kGuestLo = 0x10000, kGuestEnd = 0x04000000;  // what a setting may name: the console's 64 MB
constexpr uint64_t kSaveCap = 512ull << 20;

#pragma pack(push, 1)
struct WirePad {
    uint16_t buttons;
    uint8_t analog[8];
    int16_t stick[4];
};
#pragma pack(pop)
static_assert(sizeof(WirePad) == 18);

struct Region {
    uint32_t addr, len;
};

struct Writer {
    std::vector<uint8_t> b;
    void raw(const void* p, size_t n) {
        const uint8_t* s = static_cast<const uint8_t*>(p);
        b.insert(b.end(), s, s + n);
    }
    void u8(uint8_t v) { b.push_back(v); }
    void u16(uint16_t v) { raw(&v, 2); }
    void u32(uint32_t v) { raw(&v, 4); }
};

struct Reader {
    const uint8_t* p;
    size_t n;
    bool ok = true;
    bool take(void* out, size_t k) {
        if (!ok || n < k) return ok = false;
        std::memcpy(out, p, k);
        p += k;
        n -= k;
        return true;
    }
    uint8_t u8() {
        uint8_t v = 0;
        take(&v, 1);
        return v;
    }
    uint16_t u16() {
        uint16_t v = 0;
        take(&v, 2);
        return v;
    }
    uint32_t u32() {
        uint32_t v = 0;
        take(&v, 4);
        return v;
    }
};

struct Header {
    uint8_t type = 0;
    uint32_t session = 0, epoch = 0;
};

// ---- state. g_mtx guards everything below it that is not atomic; g_latch only the pads Filter reads.
std::mutex g_mtx;
std::condition_variable g_cv;
std::atomic<State> g_state{State::Off};
std::atomic<bool> g_quit{false};
std::atomic<uint32_t> g_gen{0};  // one more at each Host or Join: a late thread of an old session does nothing
std::thread g_thread;
int g_udp = -1, g_tcp = -1;
sockaddr_in g_peer{};
std::atomic<bool> g_host{false};
uint32_t g_session = 0;
uint32_t g_delay = 3;
uint16_t g_port = 7777;
Clock::time_point g_last_rx;
std::string g_error;      // why the last session ended
std::string g_addrs;      // the host's own addresses, for the panel
std::string g_target;     // the guest's host address
std::string g_note;       // the save copy's progress
std::atomic<bool> g_save_ready{true};  // the guest's save copy is done (or none was asked)
std::atomic<uint32_t> g_rtt{0};
std::atomic<bool> g_desync{false};
std::atomic<int64_t> g_last_step_ms{0};
std::atomic<bool> g_barrier_flag{false};
std::atomic<int64_t> g_wait_since{0};
uint64_t g_stat_frames = 0, g_stat_wait_us = 0, g_stat_max_us = 0, g_stat_late = 0;  // under g_mtx  // ms, the friend's frame has not come since

// lockstep
bool g_lock_on = false;
bool g_barrier = false;
uint32_t g_epoch = 0, g_peer_epoch = 0, g_frame = 0;
bool g_peer_here = false;   // the friend's packet of this epoch was seen
bool g_sync_got = false;    // and, on the guest, the host's payload
std::vector<uint8_t> g_payload;
WirePad g_local[kRing], g_remote[kRing];
uint32_t g_local_next = 0;   // my frames [0, g_local_next) are filed
uint32_t g_remote_next = 0;  // the friend's frames [0, g_remote_next) are here
uint32_t g_remote_ack = 0;   // the friend holds my frames [0, g_remote_ack)
uint32_t g_lhash_frame[kHashSlots], g_lhash[kHashSlots], g_rhash_frame[kHashSlots], g_rhash[kHashSlots];
uint32_t g_send_hash_frame = UINT32_MAX, g_send_hash = 0;
std::vector<uint32_t> g_pages;  // page hashes of the latest hashed frame
uint32_t g_pages_frame = 0;

std::mutex g_latch;
input::Pad g_raw;               // the phone's own port 0, as Filter last saw it
input::Pad g_slot[2];           // what the two ports read while playing
WirePad g_live;                 // the friend's pad as it is now, outside lockstep (menus, loads)
int64_t g_live_ms = 0;

int64_t NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
}

WirePad ToWire(const input::Pad& p) {
    WirePad w{};
    w.buttons = p.buttons;
    std::memcpy(w.analog, p.analog, 8);
    w.stick[0] = p.lx;
    w.stick[1] = p.ly;
    w.stick[2] = p.rx;
    w.stick[3] = p.ry;
    return w;
}

input::Pad FromWire(const WirePad& w) {
    input::Pad p;
    p.connected = true;
    p.buttons = w.buttons;
    std::memcpy(p.analog, w.analog, 8);
    p.lx = w.stick[0];
    p.ly = w.stick[1];
    p.rx = w.stick[2];
    p.ry = w.stick[3];
    return p;
}

// "0x5C0000:256" or "5C0000:256" (hex or 0x or decimal by strtoul's base 0, plain digits then decimal)
bool ParseRegion(const std::string& s, Region& r) {
    size_t colon = s.find(':');
    if (colon == std::string::npos) return false;
    char* end = nullptr;
    unsigned long addr = std::strtoul(s.c_str(), &end, 0);
    if (end == s.c_str()) return false;
    unsigned long len = std::strtoul(s.c_str() + colon + 1, &end, 0);
    if (len == 0 || addr < kGuestLo || addr + len > kGuestEnd) return false;
    r = {uint32_t(addr), uint32_t(len)};
    return true;
}

std::vector<Region> Regions(const std::vector<std::string>& list) {
    std::vector<Region> out;
    for (const std::string& s : list) {
        Region r;
        if (ParseRegion(s, r)) out.push_back(r);
        else LOGR("netplay: region \"%s\" ignored: wants ADDRESS:LENGTH inside the console's memory", s.c_str());
    }
    return out;
}

// ---- state hash
uint32_t HashBytes(const uint8_t* p, size_t n) {
    uint64_t h = 0xcbf29ce484222325ull;
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t w;
        std::memcpy(&w, p + i, 8);
        h = (h ^ w) * 0x100000001b3ull;
        h ^= h >> 29;
    }
    for (; i < n; i++) h = (h ^ p[i]) * 0x100000001b3ull;
    return uint32_t(h ^ (h >> 32));
}

// the state hash of this frame: the named regions, else every page of the default range (kept for the diagnosis)
// netplay_hash names the regions; "auto" is the image's data and bss, which holds clocks and buffers that differ between
// two phones whatever the game does, so it is for finding the page where the games part, not for a normal session
bool HashAuto() {
    const auto& l = game::Opt().netplay_hash;
    return std::find(l.begin(), l.end(), "auto") != l.end();
}

bool HashOn() { return !game::Opt().netplay_hash.empty(); }

uint32_t HashGuest() {
    std::vector<Region> list = HashAuto() ? std::vector<Region>{} : Regions(game::Opt().netplay_hash);
    uint32_t h = 0x811C9DC5;
    if (!list.empty()) {
        for (const Region& r : list) h = (h ^ HashBytes(static_cast<const uint8_t*>(kernel::HostPtr(r.addr)), r.len)) * 16777619u;
        g_pages.clear();
        return h;
    }
    g_pages.clear();
    for (uint32_t a = kHashLo; a < kHashHi; a += 0x1000) {
        uint32_t p = HashBytes(static_cast<const uint8_t*>(kernel::HostPtr(a)), 0x1000);
        g_pages.push_back(p);
        h = (h ^ p) * 16777619u;
    }
    return h;
}

// under g_mtx: the first difference is logged with this phone's page hashes; the friend's log has its own, and a
// page that differs between the two is where the games parted
void CheckHash(uint32_t frame) {
    uint32_t s = (frame / kHashEvery) % kHashSlots;
    if (g_lhash_frame[s] != frame || g_rhash_frame[s] != frame || g_lhash[s] == g_rhash[s]) return;
    if (g_desync.exchange(true)) return;
    LOGR("netplay: DESYNC at frame %u (epoch %u): mine %08x, friend's %08x", frame, g_epoch, g_lhash[s], g_rhash[s]);
    if (g_pages_frame == frame && !g_pages.empty()) {
        for (size_t i = 0; i < g_pages.size(); i += 8) {
            char line[160];
            int n = std::snprintf(line, sizeof line, "netplay: pages %06x:", unsigned(kHashLo + i * 0x1000));
            for (size_t j = i; j < std::min(i + 8, g_pages.size()); j++)
                n += std::snprintf(line + n, sizeof line - size_t(n), " %08x", g_pages[j]);
            LOGR("%s", line);
        }
    }
}

// ---- sockets
bool SameAddr(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

void Send(const Writer& w) {
    if (g_udp >= 0) sendto(g_udp, w.b.data(), w.b.size(), 0, reinterpret_cast<const sockaddr*>(&g_peer), sizeof g_peer);
}

Writer Begin(Type t, uint32_t epoch) {
    Writer w;
    w.u32(kMagic);
    w.u8(t);
    w.u32(g_session);
    w.u32(epoch);
    return w;
}

void SendHello() {
    Writer w = Begin(kHello, 0);
    w.u8(kVersion);
    Send(w);
}

void SendWelcome() {
    Writer w = Begin(kWelcome, 0);
    w.u8(kVersion);
    w.u8(uint8_t(g_delay));
    Send(w);
}

void SendPing() {
    Writer w = Begin(kPing, g_epoch);
    w.u32(uint32_t(NowMs()));
    Send(w);
}

void SendBye() {
    Writer w = Begin(kBye, g_epoch);
    Send(w);
}

// under g_mtx. The guest's SYNC asks; the host's answers and carries the memory to copy.
void SendSync() {
    Writer w = Begin(kSync, g_epoch);
    uint16_t len = g_host ? uint16_t(g_payload.size()) : 0;
    w.u16(len);
    if (len) w.raw(g_payload.data(), len);
    Send(w);
}

// under g_mtx: every frame of mine the friend has not acknowledged, and the latest hash
void SendInput() {
    Writer w = Begin(kInput, g_epoch);
    w.u32(g_remote_next);
    uint32_t first = std::max(g_remote_ack, g_local_next > kMaxSend ? g_local_next - kMaxSend : 0u);
    uint32_t count = g_local_next > first ? g_local_next - first : 0;
    w.u32(first);
    w.u8(uint8_t(count));
    for (uint32_t i = 0; i < count; i++) w.raw(&g_local[(first + i) % kRing], sizeof(WirePad));
    w.u32(g_send_hash_frame);
    w.u32(g_send_hash);
    Send(w);
}

// under g_mtx: the session is over; a thread of the session's ends the loop, the panel's Stop joins it
void Fail(const std::string& why) {
    if (g_state.load() == State::Off) return;
    LOGR("netplay: %s", why.c_str());
    g_error = why;
    g_state.store(State::Off);
    g_lock_on = false;
    g_barrier = false;
    g_barrier_flag = false;
    g_quit = true;
    g_cv.notify_all();
}

// ---- saves: the host's hdd folder over TCP
bool SafeRelative(const std::string& s) {
    if (s.empty() || s.size() > 400 || s[0] == '/' || s.find('\\') != std::string::npos || s.find('\0') != std::string::npos)
        return false;
    fs::path p(s);
    for (const auto& part : p)
        if (part == ".." || part == "." || part.empty()) return false;
    return true;
}

bool SendAll(int fd, const void* data, size_t n) {
    const char* p = static_cast<const char*>(data);
    while (n) {
        ssize_t k = send(fd, p, n, MSG_NOSIGNAL);
        if (k <= 0) return false;
        p += k;
        n -= size_t(k);
    }
    return true;
}

bool RecvAll(int fd, void* data, size_t n) {
    char* p = static_cast<char*>(data);
    while (n) {
        ssize_t k = recv(fd, p, n, 0);
        if (k <= 0) return false;
        p += k;
        n -= size_t(k);
    }
    return true;
}

void SetTimeouts(int fd, int seconds) {
    timeval tv{seconds, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

void ServeSave(int fd, bool share) {
    SetTimeouts(fd, 15);
    uint32_t magic = kSaveMagic;
    std::vector<std::pair<std::string, uint64_t>> files;
    if (share) {
        std::error_code ec;
        fs::path root = app::ExeDir() / "hdd";
        uint64_t total = 0;
        for (fs::recursive_directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            uint64_t size = it->file_size(ec);
            if (ec || total + size > kSaveCap) continue;
            total += size;
            files.emplace_back(fs::relative(it->path(), root, ec).generic_string(), size);
        }
    }
    uint32_t count = uint32_t(files.size());
    bool ok = SendAll(fd, &magic, 4) && SendAll(fd, &count, 4);
    std::vector<char> buf(1 << 16);
    for (size_t i = 0; ok && i < files.size(); i++) {
        uint16_t len = uint16_t(files[i].first.size());
        uint64_t size = files[i].second;
        std::ifstream in(app::ExeDir() / "hdd" / files[i].first, std::ios::binary);
        ok = SendAll(fd, &len, 2) && SendAll(fd, files[i].first.data(), len) && SendAll(fd, &size, 8);
        while (ok && size) {
            in.read(buf.data(), std::streamsize(std::min<uint64_t>(size, buf.size())));
            size_t got = size_t(in.gcount());
            if (!got) {
                ok = false;  // the file shrank under us: the guest sees the stream end and drops the copy
                break;
            }
            ok = SendAll(fd, buf.data(), got);
            size -= got;
        }
    }
    LOGR("netplay: host saves sent to the friend: %s (%u files)", ok ? "done" : "failed", unsigned(files.size()));
    close(fd);
}

void FetchSave(uint32_t gen, sockaddr_in host) {
    auto done = [&](const char* note) {
        if (g_gen.load() != gen) return;
        std::lock_guard lock(g_mtx);
        g_note = note;
        g_save_ready = true;
        g_cv.notify_all();
    };
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return done("save copy failed: no socket");
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    connect(fd, reinterpret_cast<sockaddr*>(&host), sizeof host);
    pollfd pfd{fd, POLLOUT, 0};
    int err = 0;
    socklen_t el = sizeof err;
    if (poll(&pfd, 1, 5000) <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
        close(fd);
        return done("save copy failed: the host did not answer");
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    SetTimeouts(fd, 15);
    fs::path root = app::ExeDir();
    fs::path incoming = root / "hdd.netplay-incoming";
    std::error_code ec;
    fs::remove_all(incoming, ec);
    uint32_t magic = 0, count = 0;
    bool ok = RecvAll(fd, &magic, 4) && magic == kSaveMagic && RecvAll(fd, &count, 4) && count < 100000;
    uint64_t total = 0;
    std::vector<char> buf(1 << 16);
    for (uint32_t i = 0; ok && i < count; i++) {
        uint16_t len = 0;
        uint64_t size = 0;
        std::string rel;
        ok = RecvAll(fd, &len, 2) && len < 400;
        if (ok) {
            rel.resize(len);
            ok = RecvAll(fd, rel.data(), len) && RecvAll(fd, &size, 8) && SafeRelative(rel) && total + size <= kSaveCap;
        }
        if (!ok) break;
        total += size;
        fs::path out = incoming / rel;
        fs::create_directories(out.parent_path(), ec);
        std::ofstream file(out, std::ios::binary);
        ok = bool(file);
        while (ok && size) {
            size_t chunk = size_t(std::min<uint64_t>(size, buf.size()));
            ok = RecvAll(fd, buf.data(), chunk);
            if (ok) file.write(buf.data(), std::streamsize(chunk));
            size -= chunk;
        }
    }
    close(fd);
    if (g_gen.load() != gen) {
        fs::remove_all(incoming, ec);
        return;
    }
    if (!ok) {
        fs::remove_all(incoming, ec);
        LOGR("netplay: the host's saves did not arrive whole, the phone's own are kept");
        return done("save copy failed: the transfer broke, your saves are untouched");
    }
    if (count == 0) {
        fs::remove_all(incoming, ec);
        return done("the host shares no saves");
    }
    // the phone's own folder is kept beside, for the last copy only
    fs::path hdd = root / "hdd", backup = root / "hdd.netplay-backup";
    fs::remove_all(backup, ec);
    fs::rename(hdd, backup, ec);
    if (ec) {
        fs::remove_all(incoming, ec);
        return done("save copy failed: could not move your saves aside, nothing changed");
    }
    fs::rename(incoming, hdd, ec);
    if (ec) {
        std::error_code undo;
        fs::rename(backup, hdd, undo);
        return done("save copy failed: nothing changed");
    }
    LOGR("netplay: host saves copied (%u files); the phone's own are in hdd.netplay-backup", count);
    done("host saves copied; yours are in hdd.netplay-backup");
}

// ---- packets, g_mtx held
void OnInput(Reader& r, const Header& h) {
    if (h.epoch > g_peer_epoch) g_peer_epoch = h.epoch;
    if (h.epoch != g_epoch) {
        g_cv.notify_all();
        return;
    }
    g_peer_here = true;
    uint32_t ack = r.u32(), first = r.u32();
    uint32_t count = r.u8();
    if (!r.ok) return;
    g_remote_ack = std::max(g_remote_ack, std::min(ack, g_local_next));
    for (uint32_t i = 0; i < count; i++) {
        WirePad w;
        if (!r.take(&w, sizeof w)) return;
        uint32_t frame = first + i;
        if (frame == g_remote_next) {
            g_remote[frame % kRing] = w;
            g_remote_next++;
        }
    }
    uint32_t hf = r.u32(), hv = r.u32();
    if (r.ok && hf != UINT32_MAX && hf % kHashEvery == 0) {
        uint32_t s = (hf / kHashEvery) % kHashSlots;
        g_rhash_frame[s] = hf;
        g_rhash[s] = hv;
        CheckHash(hf);
    }
    g_cv.notify_all();
}

void OnSync(Reader& r, const Header& h) {
    if (h.epoch > g_peer_epoch) g_peer_epoch = h.epoch;
    if (h.epoch == g_epoch) {
        g_peer_here = true;
        if (!g_host) {
            uint16_t len = r.u16();
            if (r.ok && len <= kPayloadMax && r.n >= len) {
                g_payload.assign(r.p, r.p + len);
                g_sync_got = true;
            }
        }
        // the guest keeps asking until it has the payload: the host answers each time, even past its own barrier
        if (g_host) SendSync();
    }
    g_cv.notify_all();
}

void OnPacket(const uint8_t* data, size_t len, const sockaddr_in& from) {
    Reader r{data, len};
    if (r.u32() != kMagic) return;
    Header h;
    h.type = r.u8();
    h.session = r.u32();
    h.epoch = r.u32();
    if (!r.ok) return;
    std::lock_guard lock(g_mtx);
    State st = g_state.load();
    auto now = Clock::now();
    if (h.type == kHello && g_host) {
        if (r.u8() != kVersion) return;
        if (st == State::Hosting) {
            g_peer = from;
            g_session = std::random_device{}() | 1u;
            g_state = State::Connected;
            g_last_rx = now;
            LOGR("netplay: friend joined from %s:%u", inet_ntoa(from.sin_addr), unsigned(ntohs(from.sin_port)));
            SendWelcome();
            g_cv.notify_all();
        } else if ((st == State::Connected || st == State::Playing) && SameAddr(from, g_peer)) {
            SendWelcome();  // the first one was lost
        }
        return;
    }
    if (h.type == kWelcome && !g_host && st == State::Joining && SameAddr(from, g_peer)) {
        if (r.u8() != kVersion) return Fail("the host runs another version of the netplay");
        g_session = h.session;
        g_delay = std::clamp<uint32_t>(r.u8(), 1, 12);
        g_state = State::Connected;
        g_last_rx = now;
        LOGR("netplay: joined, input delay %u frames", g_delay);
        if (game::Opt().netplay_copy_save) {
            g_save_ready = false;
            g_note = "copying the host's saves";
            std::thread(FetchSave, g_gen.load(), g_peer).detach();
        }
        g_cv.notify_all();
        return;
    }
    if ((st != State::Connected && st != State::Playing) || !SameAddr(from, g_peer) || h.session != g_session) return;
    g_last_rx = now;
    switch (h.type) {
        case kInput: OnInput(r, h); break;
        case kSync: OnSync(r, h); break;
        case kPing: {
            uint32_t t = r.u32();
            Writer w = Begin(kPong, g_epoch);
            w.u32(t);
            Send(w);
            break;
        }
        case kPong: {
            uint32_t t = r.u32();
            if (r.ok) g_rtt = uint32_t(NowMs()) - t;
            break;
        }
        case kBye: Fail("your friend left"); break;
        case kPad: {
            WirePad w;
            if (r.take(&w, sizeof w)) {
                std::lock_guard latch(g_latch);
                g_live = w;
                g_live_ms = NowMs();
            }
            break;
        }
        default: break;
    }
}

void NetLoop() {
    auto last_hello = Clock::now() - std::chrono::seconds(1), last_ping = last_hello, last_sync = last_hello,
         last_input = last_hello, last_pad = last_hello;
    uint8_t buf[2048];
    while (!g_quit) {
        pollfd fds[2] = {{g_udp, POLLIN, 0}, {g_tcp, POLLIN, 0}};
        poll(fds, g_tcp >= 0 ? 2 : 1, 4);
        for (;;) {
            sockaddr_in from{};
            socklen_t fl = sizeof from;
            ssize_t n = recvfrom(g_udp, buf, sizeof buf, 0, reinterpret_cast<sockaddr*>(&from), &fl);
            if (n < 0) break;
            OnPacket(buf, size_t(n), from);
        }
        if (g_tcp >= 0 && (fds[1].revents & POLLIN)) {
            sockaddr_in from{};
            socklen_t fl = sizeof from;
            int fd = accept(g_tcp, reinterpret_cast<sockaddr*>(&from), &fl);
            if (fd >= 0) {
                bool mine;
                {
                    std::lock_guard lock(g_mtx);
                    mine = g_state.load() != State::Hosting && from.sin_addr.s_addr == g_peer.sin_addr.s_addr;
                }
                if (mine) std::thread(ServeSave, fd, game::Opt().netplay_copy_save).detach();
                else close(fd);
            }
        }
        auto now = Clock::now();
        auto since = [&](Clock::time_point t) { return std::chrono::duration_cast<std::chrono::milliseconds>(now - t).count(); };
        std::lock_guard lock(g_mtx);
        State st = g_state.load();
        if (st == State::Joining && since(last_hello) >= 300) {
            last_hello = now;
            SendHello();
        } else if (st == State::Connected || st == State::Playing) {
            if (since(g_last_rx) > kDeadMs) {
                Fail("the connection to your friend was lost");
                break;
            }
            // outside lockstep both games read the same two pads, the host's as player 1 and the guest's as player 2, as
            // each phone's own pad now reaches the other: menus follow whoever presses, and the guest can join with Start
            if (since(last_pad) >= 8) {
                last_pad = now;
                WirePad mine;
                {
                    std::lock_guard latch(g_latch);
                    mine = ToWire(g_raw);
                }
                Writer w = Begin(kPad, g_epoch);
                w.raw(&mine, sizeof mine);
                Send(w);
            }
            if (since(last_ping) >= 500) {
                last_ping = now;
                SendPing();
            }
            if (g_barrier && since(last_sync) >= 50) {
                last_sync = now;
                SendSync();
            } else if (g_lock_on && since(last_input) >= 8) {
                last_input = now;
                SendInput();
            }
        }
    }
    std::lock_guard lock(g_mtx);
    if (g_udp >= 0) close(g_udp);
    if (g_tcp >= 0) close(g_tcp);
    g_udp = g_tcp = -1;
}

std::string LocalAddresses() {
    std::string out;
    ifaddrs* list = nullptr;
    if (getifaddrs(&list) != 0) return out;
    for (ifaddrs* a = list; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET || !(a->ifa_flags & IFF_UP) || (a->ifa_flags & IFF_LOOPBACK))
            continue;
        char text[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(a->ifa_addr)->sin_addr, text, sizeof text);
        if (!out.empty()) out += ", ";
        out += text;
    }
    freeifaddrs(list);
    return out;
}

// under g_mtx, game thread: the guest memory the host chose, in the payload
void BuildPayload() {
    g_payload.clear();
    Writer w;
    std::vector<Region> list = Regions(game::Opt().netplay_sync);
    w.u8(0);
    uint8_t n = 0;
    for (const Region& r : list) {
        if (w.b.size() + 8 + r.len > kPayloadMax) {
            LOGR("netplay: sync region %06x+%u does not fit one packet, skipped", r.addr, r.len);
            continue;
        }
        w.u32(r.addr);
        w.u32(r.len);
        w.raw(kernel::HostPtr(r.addr), r.len);
        n++;
    }
    w.b[0] = n;
    g_payload = std::move(w.b);
}

void ApplyPayload() {
    Reader r{g_payload.data(), g_payload.size()};
    uint8_t n = r.u8();
    for (uint8_t i = 0; r.ok && i < n; i++) {
        uint32_t addr = r.u32(), len = r.u32();
        if (!r.ok || len > r.n || addr < kGuestLo || uint64_t(addr) + len > kGuestEnd) break;
        std::memcpy(kernel::HostPtr(addr), r.p, len);
        r.p += len;
        r.n -= len;
    }
}

// under g_mtx: a new epoch: frame 0 on both sides after both have arrived. false when the session ended.
bool Barrier(std::unique_lock<std::mutex>& lk) {
    auto begin = [] {
        g_epoch = std::max(g_epoch + 1, g_peer_epoch);
        g_peer_here = g_sync_got = false;
        g_frame = 0;
        g_local_next = g_remote_next = g_remote_ack = g_delay;
        for (uint32_t i = 0; i < g_delay; i++) g_local[i] = g_remote[i] = WirePad{};
        g_send_hash_frame = UINT32_MAX;
        std::fill(std::begin(g_lhash_frame), std::end(g_lhash_frame), UINT32_MAX);
        std::fill(std::begin(g_rhash_frame), std::end(g_rhash_frame), UINT32_MAX);
        if (g_host) BuildPayload();
        else g_payload.clear();
        g_barrier = true;
        g_barrier_flag = true;
    };
    g_state = State::Connected;
    g_lock_on = false;
    begin();
    LOGR("netplay: epoch %u: waiting for the friend to reach gameplay", g_epoch);
    SendSync();
    for (;;) {
        if (g_state.load() == State::Off) return false;
        if (g_peer_epoch > g_epoch) begin();
        if (g_peer_here && (g_host || g_sync_got)) break;
        g_cv.wait_for(lk, std::chrono::milliseconds(20));
    }
    if (!g_host) ApplyPayload();
    g_barrier = false;
    g_barrier_flag = false;
    g_lock_on = true;
    g_state = State::Playing;
    g_last_step_ms = NowMs();
    LOGR("netplay: epoch %u: both at gameplay, lockstep on (%s, %u frames of delay)", g_epoch,
         g_host ? "player 1" : "player 2", g_delay);
    return true;
}

bool Start(bool host, const std::string& target) {
    Stop();
    std::lock_guard lock(g_mtx);
    g_gen++;
    g_error.clear();
    g_note.clear();
    g_quit = false;
    g_host = host;
    g_epoch = g_peer_epoch = g_frame = 0;
    g_lock_on = g_barrier = false;
    g_barrier_flag = false;
    g_desync = false;
    g_save_ready = true;
    g_rtt = 0;
    g_last_step_ms = 0;
    g_session = 0;
    g_delay = std::clamp<uint32_t>(game::Opt().netplay_delay, 1, 12);
    g_port = uint16_t(std::clamp<uint32_t>(game::Opt().netplay_port, 1024, 65535));
    g_peer = {};
    g_peer.sin_family = AF_INET;
    g_peer.sin_port = htons(g_port);
    g_target = target;
    if (!host) {
        std::string ip = target;
        // "address:port"
        size_t colon = ip.rfind(':');
        if (colon != std::string::npos && ip.find(':') == colon) {
            g_peer.sin_port = htons(uint16_t(std::strtoul(ip.c_str() + colon + 1, nullptr, 10)));
            ip.resize(colon);
        }
        if (inet_pton(AF_INET, ip.c_str(), &g_peer.sin_addr) != 1) {
            addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            if (getaddrinfo(ip.c_str(), nullptr, &hints, &res) != 0 || !res) {
                g_error = "that address is not valid";
                return false;
            }
            g_peer.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
            freeaddrinfo(res);
        }
        if (g_peer.sin_port == 0) g_peer.sin_port = htons(g_port);
    }
    g_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp < 0) {
        g_error = "no socket";
        return false;
    }
    fcntl(g_udp, F_SETFL, fcntl(g_udp, F_GETFL) | O_NONBLOCK);
    int one = 1;
    setsockopt(g_udp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in any{};
    any.sin_family = AF_INET;
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    any.sin_port = host ? htons(g_port) : 0;
    if (bind(g_udp, reinterpret_cast<sockaddr*>(&any), sizeof any) != 0) {
        g_error = host ? "the port is taken" : "no socket";
        close(g_udp);
        g_udp = -1;
        return false;
    }
    if (host) {
        g_addrs = LocalAddresses();
        g_tcp = socket(AF_INET, SOCK_STREAM, 0);
        if (g_tcp >= 0) {
            fcntl(g_tcp, F_SETFL, fcntl(g_tcp, F_GETFL) | O_NONBLOCK);
            setsockopt(g_tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
            if (bind(g_tcp, reinterpret_cast<sockaddr*>(&any), sizeof any) != 0 || listen(g_tcp, 2) != 0) {
                LOGR("netplay: no TCP on port %u, the save copy is off", unsigned(g_port));
                close(g_tcp);
                g_tcp = -1;
            }
        }
    }
    g_last_rx = Clock::now();
    g_state = host ? State::Hosting : State::Joining;
    g_thread = std::thread(NetLoop);
    LOGR("netplay: %s on port %u", host ? "hosting" : "joining", unsigned(g_port));
    return true;
}

}  // namespace

void Host() { Start(true, ""); }

void Join(const std::string& address) { Start(false, address); }

void Stop() {
    {
        std::lock_guard lock(g_mtx);
        if (g_state.load() == State::Connected || g_state.load() == State::Playing) SendBye();
        if (g_state.load() != State::Off) g_error.clear();
        g_state = State::Off;
        g_lock_on = g_barrier = false;
        g_barrier_flag = false;
        g_quit = true;
        g_cv.notify_all();
    }
    if (g_thread.joinable() && g_thread.get_id() != std::this_thread::get_id()) g_thread.join();
}

State GetState() { return g_state.load(std::memory_order_relaxed); }

bool InSync() { return !g_desync.load(std::memory_order_relaxed); }

std::string Status() {
    std::lock_guard lock(g_mtx);
    char text[256];
    switch (g_state.load()) {
        case State::Off: return g_error;
        case State::Hosting:
            std::snprintf(text, sizeof text, "HOSTING ON %s PORT %u, WAITING FOR YOUR FRIEND", g_addrs.empty() ? "?" : g_addrs.c_str(),
                          unsigned(g_port));
            return text;
        case State::Joining: return "JOINING " + g_target;
        case State::Connected:
            if (!g_save_ready) return "COPYING THE HOST'S SAVES";
            if (g_barrier) return "WAITING FOR YOUR FRIEND TO REACH GAMEPLAY";
            return "CONNECTED, START THE SAME CO-OP GAME ON BOTH PHONES";
        case State::Playing:
            if (g_wait_since.load() && NowMs() - g_wait_since.load() > 750) return "WAITING FOR YOUR FRIEND";
            std::snprintf(text, sizeof text, "PLAYER %d, PING %u MS, DELAY %u, %s", g_host ? 1 : 2, unsigned(g_rtt.load()),
                          unsigned(g_delay), g_desync ? "OUT OF SYNC" : "IN SYNC");
            return text;
    }
    return "";
}

void Filter(int port, input::Pad& pad) {
    if (port == 0) {
        std::lock_guard lock(g_latch);
        g_raw = pad;
    }
    State st = g_state.load(std::memory_order_relaxed);
    if (st != State::Connected && st != State::Playing) return;
    if (port != 0 && port != 1) return;
    bool playing = st == State::Playing && NowMs() - g_last_step_ms.load(std::memory_order_relaxed) < kGapMs;
    std::lock_guard lock(g_latch);
    if (playing) {
        pad = g_slot[port];
        return;
    }
    // not in lockstep: the host's live pad is player 1 and the guest's live pad player 2, on both phones
    bool host = g_host.load();
    input::Pad remote;
    remote.connected = true;
    if (NowMs() - g_live_ms < 300) remote = FromWire(g_live);
    if (host) {
        if (port == 1) pad = remote;
    } else {
        pad = port == 0 ? remote : g_raw;
        pad.connected = true;
    }
}

void Rumble(int port, uint16_t& left, uint16_t& right) {
    if (g_state.load(std::memory_order_relaxed) != State::Playing) return;
    // the friend's motors are not on this phone. The guest's own are on port 1, which the phone has no pad for.
    if (g_host.load() && port == 0) return;
    left = 0;
    right = 0;
}

void Step() {
    State st = g_state.load(std::memory_order_acquire);
    if ((st != State::Connected && st != State::Playing) || !g_save_ready.load()) return;
    input::Poll(0);  // the phone's own pad now, kept by Filter
    std::unique_lock lock(g_mtx);
    // no gameplay frame for a while, though the game was running (not paused in the background): it left gameplay,
    // for a menu or a load, and the epoch ends. Both phones leave at the same frame, so they meet at a new barrier.
    static uint32_t seen_pauses = 0;
    uint32_t pauses = game::g_focus_pauses.load();
    bool was_paused = pauses != seen_pauses;
    seen_pauses = pauses;
    if (g_lock_on && !was_paused && NowMs() - g_last_step_ms.load() > kGapMs) {
        LOGR("netplay: no gameplay frame for %lld ms, leaving epoch %u", static_cast<long long>(NowMs() - g_last_step_ms.load()),
             g_epoch);
        g_lock_on = false;
    }
    for (;;) {
        State now_state = g_state.load();
        if (now_state != State::Connected && now_state != State::Playing) return;
        if (!g_lock_on && !Barrier(lock)) return;
        const uint32_t f = g_frame;
        {
            std::lock_guard latch(g_latch);
            g_local[(f + g_delay) % kRing] = ToWire(g_raw);
        }
        g_local_next = f + g_delay + 1;
        if (f % kHashEvery == 0 && HashOn()) {
            uint32_t h = HashGuest();
            uint32_t s = (f / kHashEvery) % kHashSlots;
            g_lhash_frame[s] = f;
            g_lhash[s] = h;
            g_pages_frame = f;
            g_send_hash_frame = f;
            g_send_hash = h;
            CheckHash(f);
        }
        SendInput();
        auto wait_start = Clock::now();
        // A frame that is slow to come is waited for, however long the link lives (a phone in the background, a bad
        // patch of Wi-Fi): leaving the epoch here would leave one phone up to the delay's frames ahead of the other,
        // and the games would differ for good. Only a friend who began a new epoch (it left gameplay) ends the wait.
        bool resync = false;
        while (g_remote_next <= f) {
            if (g_state.load() == State::Off) return;
            if (g_peer_epoch > g_epoch) {
                resync = true;
                break;
            }
            if (!g_wait_since.load()) g_wait_since = NowMs();
            g_cv.wait_for(lock, std::chrono::milliseconds(4));
        }
        g_wait_since = 0;
        {
            uint64_t us = uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - wait_start).count());
            g_stat_frames++;
            g_stat_wait_us += us;
            g_stat_max_us = std::max(g_stat_max_us, us);
            if (us > 4000) g_stat_late++;
            if (g_stat_frames >= 600) {
                LOGR("netplay: 600 frames, waited %llu us each on average, %llu over 4 ms, longest %llu ms, ping %u ms, delay %u",
                     static_cast<unsigned long long>(g_stat_wait_us / g_stat_frames), static_cast<unsigned long long>(g_stat_late),
                     static_cast<unsigned long long>(g_stat_max_us / 1000), unsigned(g_rtt.load()), g_delay);
                g_stat_frames = g_stat_wait_us = g_stat_max_us = g_stat_late = 0;
            }
        }
        if (resync) {
            LOGR("netplay: the friend left gameplay at frame %u, leaving epoch %u", f, g_epoch);
            g_lock_on = false;
            continue;
        }
        WirePad mine = g_local[f % kRing], theirs = g_remote[f % kRing];
        {
            std::lock_guard latch(g_latch);
            g_slot[0] = FromWire(g_host ? mine : theirs);
            g_slot[1] = FromWire(g_host ? theirs : mine);
        }
        g_frame = f + 1;
        g_last_step_ms = NowMs();
        return;
    }
}

}  // namespace netplay
