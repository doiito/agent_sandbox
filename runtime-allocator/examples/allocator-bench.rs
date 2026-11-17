//! Raw, bounded allocator comparisons; not full API startup SLO evidence.
use std::hint::black_box;
use std::time::Instant;

fn resident_kib(key: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let (name, rest) = line.split_once(':')?;
        (name == key).then(|| rest.split_whitespace().next()?.parse().ok())?
    })
}

fn churn(iterations: usize) {
    for index in 0..iterations {
        let mut bytes = Vec::with_capacity(16 + (index * 31 % 2048));
        bytes.push(index as u8);
        black_box(&bytes);
    }
}

fn mixed(iterations: usize) {
    let mut slots: Vec<Vec<u8>> = (0..128).map(|_| Vec::new()).collect();
    for index in 0..iterations {
        let mut bytes = Vec::with_capacity(32 + (index * 131 % 16384));
        bytes.push(index as u8);
        black_box(&bytes);
        slots[index % 128] = bytes;
    }
    black_box(slots);
}

fn handoff(iterations: usize) {
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(32);
    let worker = std::thread::spawn(move || {
        let mut total = 0_usize;
        for bytes in receiver {
            total = total.wrapping_add(bytes[0] as usize);
            black_box(&bytes);
        }
        total
    });
    for index in 0..iterations {
        let mut bytes = Vec::with_capacity(32 + index * 17 % 4096);
        bytes.push(index as u8);
        sender.send(bytes).unwrap();
    }
    drop(sender);
    black_box(worker.join().unwrap());
}

fn main() {
    let identity = osv_runtime_allocator::initialize();
    let mut arguments = std::env::args().skip(1);
    let profile = arguments.next().unwrap_or_else(|| "churn".into());
    let samples: usize = arguments.next().as_deref().unwrap_or("24").parse().unwrap();
    let iterations: usize = arguments
        .next()
        .as_deref()
        .unwrap_or("32768")
        .parse()
        .unwrap();
    assert!((1..=1000).contains(&samples) && (1..=1_000_000).contains(&iterations));
    assert!(arguments.next().is_none());
    let work: fn(usize) = match profile.as_str() {
        "churn" => churn,
        "mixed" => mixed,
        "handoff" => handoff,
        _ => panic!("unknown allocation profile"),
    };
    for _ in 0..4 {
        work(iterations);
    }
    for sample in 0..samples {
        let begin = Instant::now();
        work(iterations);
        let duration = begin.elapsed().as_nanos();
        let rss = resident_kib("VmRSS").map_or_else(|| "null".into(), |v| v.to_string());
        let peak = resident_kib("VmHWM").map_or_else(|| "null".into(), |v| v.to_string());
        println!(
            "{{\"protocol\":\"osv-allocator-benchmark/v1\",\"allocator\":\"{}\",\"c_version\":{},\"secure_level\":{},\"architecture\":\"{}\",\"profile\":\"{}\",\"sample\":{},\"iterations\":{},\"duration_ns\":{},\"rss_kib\":{},\"peak_rss_kib\":{},\"api_slo_evidence\":false}}",
            identity.name,
            identity.c_version,
            identity.secure_level,
            std::env::consts::ARCH,
            profile,
            sample,
            iterations,
            duration,
            rss,
            peak
        );
    }
}
