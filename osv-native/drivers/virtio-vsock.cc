/* SPDX-License-Identifier: BSD-3-Clause */
#include "drivers/virtio-vsock.hh"
#include "drivers/virtio-mmio.hh"
#include <osv/drivers_config.h>
#include <osv/vsock.h>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <mutex>
#include <stdexcept>

namespace wire = osv_vsock_protocol;
namespace {
mutex api_lock;
condvar api_changed;
virtio::vsock* api_device = nullptr;
unsigned api_users = 0;
struct api_reference {
    virtio::vsock* device;
    api_reference() { WITH_LOCK(api_lock) { device=api_device; if (device) ++api_users; } }
    ~api_reference() { if (device) { WITH_LOCK(api_lock) { --api_users; api_changed.wake_all(); } } }
};
template<class Function> int64_t call_api(Function function) {
    api_reference ref;
    if (!ref.device) return -ENODEV;
    try { return function(*ref.device); }
    catch (const std::bad_alloc&) { return -ENOMEM; }
    catch (...) { return -EIO; }
}
}

namespace virtio {
u64 vsock::get_driver_features() {
    // Direct SG descriptors only: no per-packet indirect allocation.
    return (1ULL << VIRTIO_F_VERSION_1) | (1ULL << VIRTIO_RING_F_EVENT_IDX);
}

vsock::vsock(virtio_device& dev) : virtio_driver(dev) {
    if (!dev.is_modern() || !dynamic_cast<mmio_device*>(&dev)) throw std::runtime_error("vsock requires modern MMIO");
    setup_features();
    _cid = read_cid();
    if (_cid <= 2 || _cid > UINT32_MAX) throw std::runtime_error("invalid guest CID");
    probe_virt_queues();
    if (_num_queues != 3) throw std::runtime_error("vsock requires RX/TX/event queues");
    _rx=get_virt_queue(0); _tx=get_virt_queue(1); _events=get_virt_queue(2);
    if (_rx->size()<8 || _tx->size()<8 || _events->size()<1) throw std::runtime_error("vsock queue too small");
    _inflight.reserve(_tx->size());
    _worker.reset(sched::thread::make([this] { worker(); }, sched::thread::attr().name("virtio-vsock").stack(64*1024)));
    _irq=std::make_shared<irq_state>(&dev);
    _irq->worker.reset(*_worker);
    const auto irq=_irq;
    auto interrupt=[irq] {
        if (irq->active.load(std::memory_order_acquire) && irq->dev->read_and_ack_isr())
            irq->worker.wake_from_kernel_or_with_irq_disabled();
    };
    interrupt_factory factory;
#if CONF_drivers_mmio
#ifdef __aarch64__
    factory.create_spi_edge_interrupt=[irq,interrupt] {
        return new spi_interrupt(gic::irq_type::IRQ_TYPE_EDGE, irq->dev->get_irq(),
            [irq] { return irq->active.load() && irq->dev->read_and_ack_isr(); },
            [irq] { irq->worker.wake_from_kernel_or_with_irq_disabled(); });
    };
#else
    factory.create_gsi_edge_interrupt=[irq,interrupt] {
        return new gsi_edge_interrupt(irq->dev->get_irq(), interrupt);
    };
#endif
#endif
    // No PCI callback: this initial profile is MMIO-only, including teardown.
    dev.register_interrupt(factory);
    for (unsigned i=0;i<std::min<unsigned>(32,_rx->size()/3);++i) {
        _receive_buffers.emplace_back(new packet);
        post_receive(_receive_buffers.back().get());
    }
    for (unsigned i=0;i<std::min<unsigned>(8,_events->size());++i) {
        _event_buffers.emplace_back(new std::array<uint8_t,4>{});
        post_event(_event_buffers.back().get());
    }
    add_dev_status(VIRTIO_CONFIG_S_DRIVER_OK);
    _rx->kick(); _events->kick();
    _worker->start();
    WITH_LOCK(api_lock) {
        assert(!api_device);
        api_device=this;
    }
}

vsock::~vsock() {
    WITH_LOCK(api_lock) { if (api_device==this) api_device=nullptr; }
    WITH_LOCK(_lock) {
        _stop.store(true);
        _irq->active.store(false, std::memory_order_release);
        reset_device();
        if (get_dev_status()!=0) abort(); // do not release memory still owned by DMA
        for (auto& item:_flows) { item.second->state=phase::closed; item.second->error=ECANCELED; }
        for (auto& item:_listeners) item.second->closed=true;
        _changed.wake_all();
    }
    _worker->wake();
    _worker->join();
    _irq->worker.clear();
    WITH_LOCK(api_lock) { api_changed.wait_until(api_lock, [] { return api_users==0; }); }
    // Device reset makes outstanding TX cookies safe to release even without
    // a used entry. RX/event buffers remain alive until this destructor ends.
    for (auto* packet:_inflight) delete packet;
    _inflight.clear();
}

hw_driver* vsock::probe(hw_device* dev) {
    WITH_LOCK(api_lock) { if (api_device) return nullptr; }
    if (!dynamic_cast<mmio_device*>(dev)) return nullptr;
    return virtio::probe<vsock,19>(dev);
}
uint64_t vsock::read_cid() {
    // Firecracker exposes the 64-bit CID as one MMIO register and rejects
    // eight individual byte reads made by virtio_conf_read().
    auto* mmio=dynamic_cast<mmio_device*>(&_dev);
    if (!mmio) return 0;
    for (unsigned i=0;i<4;++i) {
        auto first=mmio->read_config64(0);
        auto second=mmio->read_config64(0);
        if (first==second) return first;
    }
    return 0;
}
uint64_t vsock::cid() { WITH_LOCK(_lock) { return unavailable()?0:_cid; } }
int vsock::allocate_handle() { return _next_handle<INT_MAX?_next_handle++:-EMFILE; }
void vsock::wake_worker() { _pending.store(true,std::memory_order_release); _worker->wake(); }
void vsock::post_receive(packet* buffer) {
    _rx->init_sg(); _rx->add_in_sg(buffer->bytes.data(),buffer->bytes.size());
    if (!_rx->add_buf(buffer)) abort(); // fixed pool fits even with three SGs per buffer
}
void vsock::post_event(std::array<uint8_t,4>* event) {
    _events->init_sg(); _events->add_in_sg(event->data(),event->size());
    if (!_events->add_buf(event)) abort();
}
wire::header vsock::outgoing(const connection& c,uint16_t op) const {
    wire::header h;
    h.src_cid=_cid; h.dst_cid=std::get<0>(c.tuple);
    h.src_port=std::get<2>(c.tuple); h.dst_port=std::get<1>(c.tuple);
    h.op=op; h.fwd_count=c.forwarded;
    return h;
}
bool vsock::enqueue(wire::header h,const void* payload,const std::shared_ptr<connection>& owner) {
    const bool ordered=h.op==wire::data || h.op==wire::shutdown;
    auto& queue=ordered?_data:_control;
    if (queue.size()>=(ordered?max_data+2*max_flows:max_control)) return false;
    std::unique_ptr<packet> p(new packet);
    p->header=h; p->owner=owner; p->has_owner=bool(owner);
    wire::encode(h,p->bytes.data()); p->length=wire::header_size+h.length;
    if (h.length) std::memcpy(p->bytes.data()+wire::header_size,payload,h.length);
    queue.push_back(std::move(p));
    return true;
}
bool vsock::control(const std::shared_ptr<connection>& c,uint16_t op,uint32_t flags) {
    if (op==wire::credit_update || op==wire::credit_request) {
        for (auto& p:_control) if (p->header.op==op && p->owner.lock()==c) return true;
    }
    auto h=outgoing(*c,op); h.flags=flags;
    return enqueue(h,nullptr,c);
}
void vsock::reset_reply(const wire::header& incoming) {
    if (incoming.op==wire::reset) return;
    auto h=incoming;
    std::swap(h.src_cid,h.dst_cid); std::swap(h.src_port,h.dst_port);
    h.length=0; h.flags=0; h.op=wire::reset; h.buf_alloc=0; h.fwd_count=0;
    (void)enqueue(h);
}
void vsock::prune_listener(listener& l) {
    auto& q=l.pending;
    q.erase(std::remove_if(q.begin(),q.end(),[](const std::shared_ptr<connection>& c) { return c->state==phase::closed; }),q.end());
}
void vsock::retire(const std::shared_ptr<connection>& c,int error) {
    c->state=phase::closed; c->error=error;
    if (error) c->rx.clear();
    auto it=_flows.find(c->tuple);
    if (it!=_flows.end() && it->second==c) _flows.erase(it);
    for (auto& item:_listeners) prune_listener(*item.second);
    _changed.wake_all();
}
void vsock::fail(const std::shared_ptr<connection>& c,int error) {
    (void)control(c,wire::reset);
    retire(c,error);
}

int vsock::listen(uint32_t port,unsigned backlog) {
    std::lock_guard<mutex> guard(_lock);
    if (unavailable()) return -ENODEV;
    if (!port || port==UINT32_MAX || !backlog || backlog>max_flows) return -EINVAL;
    if (_ports.count(port)) return -EADDRINUSE;
    if (_listeners.size()>=max_listeners) return -ENOBUFS;
    int handle=allocate_handle(); if (handle<0) return handle;
    auto l=std::make_shared<listener>(port,backlog);
    _listeners[handle]=l; _ports[port]=handle;
    return handle;
}
int vsock::accept(int handle,uint32_t timeout) {
    if (timeout>300000) return -EINVAL;
    std::lock_guard<mutex> guard(_lock);
    auto it=_listeners.find(handle); if (it==_listeners.end()) return -EBADF;
    auto l=it->second;
    const auto deadline=clock::now()+std::chrono::milliseconds(timeout);
    for (;;) {
        if (unavailable() || l->closed) return -ENODEV;
        if (_resetting) return -ECONNRESET;
        prune_listener(*l);
        if (!l->pending.empty()) {
            if (_handles.size()>=max_flows) return -EMFILE;
            int accepted=allocate_handle(); if (accepted<0) return accepted;
            _handles[accepted]=l->pending.front(); l->pending.pop_front();
            return accepted;
        }
        if (!timeout) return -EAGAIN;
        if (clock::now()>=deadline) return -ETIMEDOUT;
        _changed.wait(&_lock,deadline);
    }
}
int vsock::connect(uint64_t peer,uint32_t port,uint32_t timeout) {
    if (timeout>300000 || !port || port==UINT32_MAX) return -EINVAL;
    if (peer!=wire::host_cid) return -EAFNOSUPPORT;
    std::lock_guard<mutex> guard(_lock);
    if (unavailable()) return -ENODEV;
    if (_resetting) return -ECONNRESET;
    if (_flows.size()>=max_flows || _handles.size()>=max_flows) return -ENOBUFS;
    while (_next_port!=UINT32_MAX && _ports.count(_next_port)) ++_next_port;
    if (_next_port==UINT32_MAX) return -EADDRNOTAVAIL;
    int handle=allocate_handle(); if (handle<0) return handle;
    auto c=std::make_shared<connection>(key(peer,port,_next_port++));
    _flows[c->tuple]=c; _handles[handle]=c;
    if (!control(c,wire::request)) { retire(c,ENOBUFS); _handles.erase(handle); return -ENOBUFS; }
    wake_worker();
    const auto deadline=clock::now()+std::chrono::milliseconds(timeout);
    while (c->state==phase::connecting && !unavailable()) {
        if (!timeout || clock::now()>=deadline) {
            fail(c,ETIMEDOUT); _handles.erase(handle); wake_worker();
            return timeout?-ETIMEDOUT:-EAGAIN;
        }
        _changed.wait(&_lock,deadline);
    }
    if (c->state!=phase::established || unavailable()) {
        int error=c->error?c->error:ENODEV; _handles.erase(handle); return -error;
    }
    return handle;
}

int64_t vsock::recv(int handle,void* data,size_t size,uint32_t timeout) {
    if (timeout>300000 || (!data && size)) return -EINVAL;
    std::lock_guard<mutex> guard(_lock);
    auto it=_handles.find(handle); if (it==_handles.end()) return -EBADF;
    auto c=it->second;
    const auto deadline=clock::now()+std::chrono::milliseconds(timeout);
    for (;;) {
        if (unavailable()) return -ENODEV;
        if (c->error) return -c->error;
        if (!size || (c->local_shutdown&wire::no_receive)) return 0;
        if (c->rx.size()) {
            size_t count=c->rx.pop(static_cast<uint8_t*>(data),size);
            c->forwarded+=uint32_t(count);
            if (!control(c,wire::credit_update)) fail(c,ENOBUFS);
            if (!c->rx.size() && c->peer_shutdown==3) { (void)control(c,wire::reset); retire(c,0); }
            wake_worker();
            return count;
        }
        if (c->state==phase::closed || c->peer_shutdown&wire::no_send) return 0;
        if (c->state!=phase::established) return -ENOTCONN;
        if (!timeout) return -EAGAIN;
        if (clock::now()>=deadline) return -ETIMEDOUT;
        _changed.wait(&_lock,deadline);
    }
}
int64_t vsock::send(int handle,const void* data,size_t size,uint32_t timeout) {
    if (timeout>300000 || (!data && size)) return -EINVAL;
    std::lock_guard<mutex> guard(_lock);
    auto it=_handles.find(handle); if (it==_handles.end()) return -EBADF;
    auto c=it->second;
    const auto deadline=clock::now()+std::chrono::milliseconds(timeout);
    for (;;) {
        if (unavailable()) return -ENODEV;
        if (c->error) return -c->error;
        if (c->state!=phase::established || (c->local_shutdown&wire::no_send) || (c->peer_shutdown&wire::no_receive)) return -EPIPE;
        if (!size) return 0;
        auto count=std::min<size_t>({size,wire::max_payload,c->credit.available()});
        if (count && _data.size()<max_data) {
            auto h=outgoing(*c,wire::data); h.length=count;
            if (enqueue(h,data,c)) {
                if (!c->credit.reserve(count)) abort();
                wake_worker(); return count;
            }
        }
        if (!count && !c->credit_requested) {
            if (!control(c,wire::credit_request)) { fail(c,ENOBUFS); wake_worker(); return -ENOBUFS; }
            c->credit_requested=true; wake_worker();
        }
        if (!timeout) return -EAGAIN;
        if (clock::now()>=deadline) return -ETIMEDOUT;
        _changed.wait(&_lock,deadline);
    }
}

int vsock::shutdown(int handle,uint32_t flags) {
    if (!flags || flags&~uint32_t(3)) return -EINVAL;
    std::lock_guard<mutex> guard(_lock);
    if (unavailable()) return -ENODEV;
    auto it=_handles.find(handle); if (it==_handles.end()) return -EBADF;
    auto c=it->second;
    if (c->error) return -c->error;
    if ((c->local_shutdown&flags)==flags) return 0;
    c->local_shutdown|=flags;
    if (flags&wire::no_receive) { c->forwarded+=c->rx.size(); c->rx.clear(); }
    if (!control(c,wire::shutdown,c->local_shutdown)) { fail(c,ENOBUFS); wake_worker(); return -ENOBUFS; }
    _changed.wake_all(); wake_worker();
    return 0;
}
int vsock::close(int handle) {
    std::lock_guard<mutex> guard(_lock);
    if (unavailable()) return -ENODEV;
    auto listener_it=_listeners.find(handle);
    if (listener_it!=_listeners.end()) {
        auto l=listener_it->second; l->closed=true;
        auto pending=l->pending; // retire prunes pending lists
        for (auto& c:pending) fail(c,ECANCELED);
        _ports.erase(l->port); _listeners.erase(listener_it);
        _changed.wake_all(); wake_worker(); return 0;
    }
    auto it=_handles.find(handle); if (it==_handles.end()) return -EBADF;
    auto c=it->second;
    _handles.erase(it);
    if (c->state!=phase::closed) {
        const bool already_shutdown=c->local_shutdown==3;
        c->local_shutdown=3;
        if (!already_shutdown && !control(c,wire::shutdown,3)) fail(c,ENOBUFS);
        else { c->state=phase::closing; c->close_deadline=clock::now()+std::chrono::seconds(1); }
    }
    _changed.wake_all(); wake_worker(); return 0;
}

void vsock::process_packet(const uint8_t* bytes,size_t length) {
    wire::header h;
    if (!wire::decode(bytes,length,h)) return;
    if (h.dst_cid!=_cid || h.src_cid!=wire::host_cid || !h.src_port || !h.dst_port) return;
    const key tuple(h.src_cid,h.src_port,h.dst_port);
    auto it=_flows.find(tuple);
    if (!wire::valid_stream(h)) {
        reset_reply(h); if (it!=_flows.end()) retire(it->second,EPROTO); return;
    }
    if (_resetting) { reset_reply(h); return; }
    if (h.op==wire::request) {
        if (it!=_flows.end()) { fail(it->second,EPROTO); return; }
        auto port=_ports.find(h.dst_port);
        if (port==_ports.end() || _flows.size()>=max_flows) { reset_reply(h); return; }
        auto l=_listeners.at(port->second); prune_listener(*l);
        if (l->pending.size()>=l->backlog) { reset_reply(h); return; }
        auto c=std::make_shared<connection>(tuple);
        if (!c->credit.update(h.buf_alloc,h.fwd_count)) { reset_reply(h); return; }
        c->state=phase::established;
        if (!control(c,wire::response)) { reset_reply(h); return; }
        _flows[tuple]=c; l->pending.push_back(c); _changed.wake_all(); return;
    }
    if (it==_flows.end()) { reset_reply(h); return; }
    auto c=it->second;
    if (h.op==wire::reset) {
        retire(c,c->state==phase::closing?0:
            c->state==phase::connecting?ECONNREFUSED:ECONNRESET);
        return;
    }
    if (!c->credit.update(h.buf_alloc,h.fwd_count)) { fail(c,EPROTO); return; }
    c->credit_requested=false;
    if (h.op==wire::response) {
        if (c->state!=phase::connecting) { fail(c,EPROTO); return; }
        c->state=phase::established;
    } else if (c->state==phase::connecting) {
        fail(c,EPROTO); return;
    } else if (h.op==wire::data) {
        if (c->peer_shutdown&wire::no_send) { fail(c,EPROTO); return; }
        if (c->local_shutdown&wire::no_receive) c->forwarded+=h.length;
        else if (!c->rx.push(bytes+wire::header_size,h.length)) { fail(c,ENOBUFS); return; }
    } else if (h.op==wire::shutdown) {
        c->peer_shutdown|=h.flags;
        if (c->peer_shutdown==3 && !c->rx.size()) { (void)control(c,wire::reset); retire(c,0); }
    } else if (h.op==wire::credit_request) {
        if (!control(c,wire::credit_update)) { fail(c,ENOBUFS); return; }
    }
    _changed.wake_all();
}

void vsock::transport_reset() {
    for (auto& item:_flows) { item.second->state=phase::closed; item.second->error=ECONNRESET; item.second->rx.clear(); }
    _flows.clear();
    for (auto& item:_listeners) item.second->pending.clear();
    _control.clear(); _data.clear();
    _cid=read_cid(); _failed=_cid<=2 || _cid>UINT32_MAX;
    _resetting=_tx_inflight!=0;
    _changed.wake_all();
}
bool vsock::completed() const { return _rx->used_ring_not_empty() || _tx->used_ring_not_empty() || _events->used_ring_not_empty(); }

void vsock::worker() {
    for (;;) {
        auto deadline=clock::time_point::max();
        {
            std::lock_guard<mutex> guard(_lock);
            if (_stop.load()) break;
            _rx->disable_interrupts(); _tx->disable_interrupts(); _events->disable_interrupts();
            while (_tx->used_ring_not_empty()) {
                u32 length; auto* p=static_cast<packet*>(_tx->get_buf_elem(&length));
                _tx->get_buf_finalize();
                auto owned=std::find(_inflight.begin(),_inflight.end(),p);
                if (owned==_inflight.end()) abort();
                _inflight.erase(owned); delete p; --_tx_inflight; _changed.wake_all();
            }
            if (_resetting && !_tx_inflight) { _resetting=false; _changed.wake_all(); }
            while (_events->used_ring_not_empty()) {
                u32 length; auto* event=static_cast<std::array<uint8_t,4>*>(_events->get_buf_elem(&length));
                if (length==4 && wire::load_le(event->data(),4)==0) transport_reset();
                _events->get_buf_finalize(); post_event(event);
            }
            while (_rx->used_ring_not_empty()) {
                u32 length; auto* p=static_cast<packet*>(_rx->get_buf_elem(&length));
                if (length<=p->bytes.size()) process_packet(p->bytes.data(),length);
                _rx->get_buf_finalize(); post_receive(p);
            }
            _rx->kick(); _events->kick();
            for (auto it=_flows.begin();it!=_flows.end();) {
                auto c=it->second; ++it;
                if (c->state==phase::closing) {
                    if (clock::now()>=c->close_deadline) fail(c,ETIMEDOUT);
                    else deadline=std::min(deadline,c->close_deadline);
                }
            }
            while (!_control.empty() || !_data.empty()) {
                auto& queue=_control.empty()?_data:_control;
                auto* p=queue.front().get();
                if (p->has_owner) {
                    auto owner=p->owner.lock();
                    if (p->header.op!=wire::reset && (!owner || owner->state==phase::closed ||
                        (p->header.op==wire::data && owner->peer_shutdown&wire::no_receive))) {
                        queue.pop_front(); continue;
                    }
                    // Control prioritization must never make fwd_cnt go
                    // backwards when an older data packet is published.
                    if (owner) { p->header.fwd_count=owner->forwarded; wire::encode(p->header,p->bytes.data()); }
                }
                _tx->init_sg(); _tx->add_out_sg(p->bytes.data(),p->length);
                if (!_tx->add_buf(p)) break;
                _inflight.push_back(p); // capacity reserved before DRIVER_OK
                queue.front().release(); queue.pop_front(); ++_tx_inflight;
            }
            _tx->kick();
            _pending.store(false,std::memory_order_release);
            // Enable all queues before rechecking: do not lose a completion
            // between observing an empty used ring and going to sleep.
            _rx->enable_interrupts(); _tx->enable_interrupts(); _events->enable_interrupts();
        }
        auto ready=[this] { return _stop.load() || _pending.load(std::memory_order_acquire) || completed(); };
        if (deadline==clock::time_point::max()) sched::thread::wait_until(ready);
        else {
            sched::timer timer(*sched::thread::current()); timer.set(deadline);
            sched::thread::wait_for(ready,timer);
        }
    }
}
}

extern "C" {
int osv_vsock_listen(uint32_t port,unsigned backlog) { return call_api([=](virtio::vsock& d) { return d.listen(port,backlog); }); }
int osv_vsock_accept(int handle,uint32_t timeout) { return call_api([=](virtio::vsock& d) { return d.accept(handle,timeout); }); }
int osv_vsock_connect(uint64_t cid,uint32_t port,uint32_t timeout) { return call_api([=](virtio::vsock& d) { return d.connect(cid,port,timeout); }); }
int64_t osv_vsock_recv(int handle,void* data,size_t size,uint32_t timeout) { return call_api([=](virtio::vsock& d) { return d.recv(handle,data,size,timeout); }); }
int64_t osv_vsock_send(int handle,const void* data,size_t size,uint32_t timeout) { return call_api([=](virtio::vsock& d) { return d.send(handle,data,size,timeout); }); }
int osv_vsock_shutdown(int handle,uint32_t flags) { return call_api([=](virtio::vsock& d) { return d.shutdown(handle,flags); }); }
int osv_vsock_close(int handle) { return call_api([=](virtio::vsock& d) { return d.close(handle); }); }
uint64_t osv_vsock_cid() { api_reference ref; return ref.device?ref.device->cid():0; }
}
