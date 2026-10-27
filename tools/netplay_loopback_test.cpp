// Loopback test of native/netplay.cpp, no phone or game needed (Linux or WSL): two processes, each a fake game thread
// calling netplay::Step() once a frame with a scripted pad, with packet loss, a leave from gameplay and a forced desync.
//
//   g++ -std=c++20 -O1 -pthread -Inative -Inative/compat -Isrc -Isdk/runtime -Isdk/harness/compat \
//       tools/netplay_loopback_test.cpp -o /tmp/np_test
//   mkdir -p /tmp/np/h/hdd /tmp/np/g/hdd
//   /tmp/np_test h /tmp/np/h 47001 0.1 600 1 > h.out 2> h.err &   # role, folder, port, loss (0 to 1), frames, mode
//   /tmp/np_test g /tmp/np/g 47001 0.1 600 1 > g.out 2> g.err
//
// Mode 0 plays on, 1 has the guest leave gameplay for 1.8 s (a new epoch), 2 has it stall 3 s in the background (the
// same epoch goes on). Each line of the .out files is one frame: its number, port 0's buttons, left stick x and A, then
// port 1's. Both files must hold the same pads for the same frames of an epoch; the .err files have the log.
// two processes on loopback, each a fake game thread that calls netplay::Step() once a frame
#include <sys/mman.h>
#include <sys/socket.h>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <thread>

static double g_loss = 0;
static ssize_t lossy_sendto(int fd, const void* b, size_t n, int fl, const sockaddr* a, socklen_t l) {
    static thread_local std::mt19937 rng(std::random_device{}());
    if (std::uniform_real_distribution<>(0, 1)(rng) < g_loss) return ssize_t(n);
    return ::sendto(fd, b, n, fl, a, l);
}
#define sendto lossy_sendto
#include "netplay.cpp"
#undef sendto

namespace kernel {
uint8_t* g_base = nullptr;
}
namespace game {
Options& Opt() {
    static Options o;
    return o;
}
}  // namespace game
namespace app {
std::filesystem::path ExeDir() { return std::getenv("NP_DIR"); }
}  // namespace app
namespace logx {
void Write(Level, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::fprintf(stderr, "[%s] ", std::getenv("NP_ROLE"));
    std::vfprintf(stderr, fmt, ap);
    std::fprintf(stderr, "\n");
    va_end(ap);
}
}  // namespace logx

static std::atomic<uint32_t> g_tick{0};
static bool g_host_side = false;

namespace input {
Pad Poll(int port) {
    Pad p;
    p.connected = true;
    if (port == 0) {
        uint32_t t = g_tick;
        // after frame 300 each side holds one constant pad, to see the end state of a resync
        if (t >= 300) {
            p.buttons = g_host_side ? 0x11 : 0x22;
        } else {
            p.buttons = uint16_t((t * 7 + (g_host_side ? 0 : 100)) & 0xFFF);
            p.lx = int16_t(t * (g_host_side ? 13 : 29));
            p.analog[0] = uint8_t(t);
        }
    }
    netplay::Filter(port, p);
    return p;
}
}  // namespace input

int main(int argc, char** argv) {
    if (argc < 6) return 2;
    g_host_side = argv[1][0] == 'h';
    setenv("NP_ROLE", g_host_side ? "HOST " : "GUEST", 1);
    setenv("NP_DIR", argv[2], 1);
    game::Opt().netplay_port = uint32_t(std::atoi(argv[3]));
    g_loss = std::atof(argv[4]);
    int frames = std::atoi(argv[5]);
    int gap = argc > 6 ? std::atoi(argv[6]) : 0;
    game::Opt().netplay_delay = 3;
    game::Opt().netplay_sync = {"0x100000:16"};
    game::Opt().netplay_hash = {"0x100000:16"};
    kernel::g_base = static_cast<uint8_t*>(mmap(nullptr, 0x04000000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0));
    if (g_host_side) std::memcpy(kernel::HostPtr(0x100000), "HOSTRNGSTATE0123", 16);
    if (g_host_side) netplay::Host();
    else {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        netplay::Join("127.0.0.1");
    }
    for (int i = 0; i < 200 && netplay::GetState() != netplay::State::Connected; i++)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));  // the save copy
    std::fprintf(stderr, "[%s] status: %s\n", std::getenv("NP_ROLE"), netplay::Status().c_str());
    for (int i = 0; i < frames; i++) {
        g_tick = uint32_t(i);
        if (gap == 2 && !g_host_side && i == 200) {
            std::this_thread::sleep_for(std::chrono::milliseconds(3000));  // the app in the background
            game::g_focus_pauses++;
        }
        if (gap == 1 && !g_host_side && i >= 200 && i < 290) {
            // the guest is in a menu for a while: no gameplay frames
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        if (i == 450 && !g_host_side) static_cast<uint8_t*>(kernel::HostPtr(0x100000))[3] ^= 0xFF;  // the games part here
        netplay::Step();
        input::Pad p0 = input::Poll(0), p1 = input::Poll(1);
        std::printf("%d %03x %d %02x | %03x %d %02x\n", i, p0.buttons, p0.lx, p0.analog[0], p1.buttons, p1.lx, p1.analog[0]);
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    std::fprintf(stderr, "[%s] end: %s, rng bytes \"%.16s\", in sync %d\n", std::getenv("NP_ROLE"), netplay::Status().c_str(),
                 reinterpret_cast<char*>(kernel::HostPtr(0x100000)), int(netplay::InSync()));
    netplay::Stop();
    return 0;
}
