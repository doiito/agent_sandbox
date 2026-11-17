/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_SANDBOX_VIRTIO_VSOCK_HH
#define OSV_SANDBOX_VIRTIO_VSOCK_HH

#include "drivers/virtio.hh"
#include "drivers/vsock-protocol.hh"
#include <osv/clock.hh>
#include <osv/condvar.h>
#include <deque>
#include <map>
#include <memory>
#include <tuple>

namespace virtio {
class vsock : public virtio_driver {
public:
    explicit vsock(virtio_device& dev);
    ~vsock() override;
    std::string get_name() const override { return "virtio-vsock"; }
    static hw_driver* probe(hw_device* dev);
    int listen(uint32_t port, unsigned backlog);
    int accept(int handle, uint32_t timeout_ms);
    int connect(uint64_t cid, uint32_t port, uint32_t timeout_ms);
    int64_t recv(int handle, void* data, size_t size, uint32_t timeout_ms);
    int64_t send(int handle, const void* data, size_t size, uint32_t timeout_ms);
    int shutdown(int handle, uint32_t flags);
    int close(int handle);
    uint64_t cid();
protected:
    u64 get_driver_features() override;
private:
    using clock = osv::clock::uptime;
    using key = std::tuple<uint64_t, uint32_t, uint32_t>;
    enum class phase { connecting, established, closing, closed };
    struct connection {
        phase state = phase::connecting;
        key tuple;
        osv_vsock_protocol::byte_ring rx;
        osv_vsock_protocol::credit_window credit;
        uint32_t forwarded = 0, local_shutdown = 0, peer_shutdown = 0;
        bool credit_requested = false;
        int error = 0;
        clock::time_point close_deadline = clock::time_point::max();
        explicit connection(key tuple) : tuple(tuple) {}
    };
    struct listener {
        uint32_t port;
        unsigned backlog;
        bool closed = false;
        std::deque<std::shared_ptr<connection>> pending;
        listener(uint32_t port, unsigned backlog) : port(port), backlog(backlog) {}
    };
    struct packet {
        std::array<uint8_t, osv_vsock_protocol::header_size+osv_vsock_protocol::max_payload> bytes{};
        size_t length = 0;
        osv_vsock_protocol::header header;
        std::weak_ptr<connection> owner;
        bool has_owner = false;
    };
    struct irq_state {
        virtio_device* dev;
        std::atomic<bool> active{true};
        sched::thread_handle worker;
        explicit irq_state(virtio_device* dev) : dev(dev) {}
    };
    static constexpr unsigned max_flows = 32, max_listeners = 8;
    static constexpr unsigned max_control = 64, max_data = 128;
    mutex _lock;
    condvar _changed;
    std::map<int, std::shared_ptr<connection>> _handles;
    std::map<int, std::shared_ptr<listener>> _listeners;
    std::map<key, std::shared_ptr<connection>> _flows;
    std::map<uint32_t, int> _ports;
    int _next_handle = 1;
    uint32_t _next_port = 49152;
    uint64_t _cid = 0;
    bool _failed = false, _resetting = false;
    std::atomic<bool> _stop{false}, _pending{false};
    std::deque<std::unique_ptr<packet>> _control, _data;
    std::vector<std::unique_ptr<packet>> _receive_buffers;
    std::vector<std::unique_ptr<std::array<uint8_t, 4>>> _event_buffers;
    unsigned _tx_inflight = 0;
    std::vector<packet*> _inflight;
    vring* _rx = nullptr;
    vring* _tx = nullptr;
    vring* _events = nullptr;
    std::unique_ptr<sched::thread> _worker;
    std::shared_ptr<irq_state> _irq;
    void worker();
    bool completed() const;
    uint64_t read_cid();
    void post_receive(packet* buffer);
    void post_event(std::array<uint8_t, 4>* event);
    void process_packet(const uint8_t* bytes, size_t length);
    void transport_reset();
    bool enqueue(osv_vsock_protocol::header header, const void* payload = nullptr,
        const std::shared_ptr<connection>& owner = {});
    bool control(const std::shared_ptr<connection>& c, uint16_t op, uint32_t flags = 0);
    void reset_reply(const osv_vsock_protocol::header& incoming);
    void retire(const std::shared_ptr<connection>& c, int error);
    void fail(const std::shared_ptr<connection>& c, int error);
    void prune_listener(listener& listener);
    osv_vsock_protocol::header outgoing(const connection& c, uint16_t op) const;
    void wake_worker();
    int allocate_handle();
    bool unavailable() const { return _stop.load() || _failed; }
};
}
#endif
