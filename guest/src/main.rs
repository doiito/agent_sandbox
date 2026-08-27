//! Minimal OSv-compatible, single-process Agent executor.
//!
//! This is the guest protocol reference implementation. Production tools are
//! linked into this process as Rust modules; spawning Linux child processes is
//! intentionally outside the contract because OSv does not implement fork().

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

const PROTOCOL: &str = "osv-agent/v1";
const RESULT_PREFIX: &str = "OSV_AGENT_RESULT ";
fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let mut job_id = String::from("unknown");
    let mut poweroff = false;
    let mut command = None;
    let mut command_args = Vec::new();

    while let Some(arg) = args.next() {
        if arg == "--poweroff-after-result" && command.is_none() {
            poweroff = true;
        } else if arg == "--sandbox-job-id" && command.is_none() {
            match args.next() {
                Some(value) if valid_job_id(&value) => job_id = value,
                _ => {
                    return finish(
                        emit_error(&job_id, "invalid or missing sandbox job id", 64),
                        poweroff,
                    );
                }
            }
        } else if command.is_none() {
            command = Some(arg);
        } else {
            command_args.push(arg);
        }
    }

    let command = command.unwrap_or_else(|| "probe".to_owned());
    let exit = match command.as_str() {
        "probe" => emit_result(&job_id, "probe", "{\"ready\":true}"),
        "echo" => {
            let mut data = String::from("{\"args\":[");
            for (index, arg) in command_args.iter().enumerate() {
                if index != 0 {
                    data.push(',');
                }
                push_json_string(&mut data, arg);
            }
            data.push_str("]}");
            emit_result(&job_id, "echo", &data)
        }
        "hold" => {
            let milliseconds = command_args
                .first()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1000)
                .min(5000);
            std::thread::sleep(Duration::from_millis(milliseconds));
            emit_result(
                &job_id,
                "hold",
                &format!("{{\"milliseconds\":{milliseconds}}}"),
            )
        }
        "isolation-probe" => emit_result(&job_id, "isolation-probe", &isolation_probe()),
        _ => emit_error(&job_id, "unsupported in-process tool", 64),
    };
    finish(exit, poweroff)
}

fn isolation_probe() -> String {
    let probe_path = "/sandbox-write-probe";
    let root_write_blocked = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(probe_path)
        .is_err();
    if !root_write_blocked {
        let _ = fs::remove_file(probe_path);
    }

    let metadata = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80);
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let timeout = Duration::from_millis(30);
    let metadata_connect_blocked = TcpStream::connect_timeout(&metadata, timeout).is_err();
    let loopback_connect_blocked = TcpStream::connect_timeout(&loopback, timeout).is_err();

    let mut devices = fs::read_dir("/dev")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    devices.sort_unstable();
    let mut device_json = String::from("[");
    for (index, device) in devices.iter().enumerate() {
        if index != 0 {
            device_json.push(',');
        }
        push_json_string(&mut device_json, device);
    }
    device_json.push(']');

    format!(
        "{{\"root_write_blocked\":{root_write_blocked},\"metadata_connect_blocked\":{metadata_connect_blocked},\"loopback_connect_blocked\":{loopback_connect_blocked},\"dev_entries\":{device_json}}}"
    )
}

fn finish(exit: ExitCode, poweroff: bool) -> ExitCode {
    if poweroff {
        terminate_guest();
    }
    exit
}

#[cfg(target_arch = "x86_64")]
fn terminate_guest() -> ! {
    // This mirrors OSv's x64 non-ACPI poweroff path. Firecracker recognizes
    // the 8042 reset write as a shutdown request. QEMU microvm does not, so a
    // deliberately invalid IDT and INT3 provide the same triple-fault fallback
    // used by OSv itself; QEMU's -no-reboot then terminates the VMM.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x64_u16,
            in("al") 0xfe_u8,
            options(nomem, nostack, preserves_flags)
        );
        let invalid_idt = [0_u8; 10];
        core::arch::asm!(
            "lidt [{address}]",
            address = in(reg) invalid_idt.as_ptr(),
            options(readonly, nostack, preserves_flags)
        );
        core::arch::asm!("int3", options(noreturn));
    }
}

fn emit_result(job_id: &str, operation: &str, data: &str) -> ExitCode {
    let mut line = String::from(RESULT_PREFIX);
    line.push_str("{\"protocol\":\"");
    line.push_str(PROTOCOL);
    line.push_str("\",\"job_id\":");
    push_json_string(&mut line, job_id);
    line.push_str(",\"ok\":true,\"operation\":");
    push_json_string(&mut line, operation);
    line.push_str(",\"data\":");
    line.push_str(data);
    line.push('}');
    println!("{line}");
    let _ = io::stdout().flush();
    ExitCode::SUCCESS
}

fn emit_error(job_id: &str, message: &str, code: u8) -> ExitCode {
    let mut line = String::from(RESULT_PREFIX);
    line.push_str("{\"protocol\":\"");
    line.push_str(PROTOCOL);
    line.push_str("\",\"job_id\":");
    push_json_string(&mut line, job_id);
    line.push_str(",\"ok\":false,\"error\":");
    push_json_string(&mut line, message);
    line.push('}');
    eprintln!("{line}");
    let _ = io::stderr().flush();
    ExitCode::from(code)
}

fn valid_job_id(value: &str) -> bool {
    value.len() == 24 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c < '\u{20}' => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", c as u32);
            }
            c => output.push(c),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_generated_job_ids() {
        assert!(valid_job_id("0123456789abcdefABCDEF01"));
        assert!(!valid_job_id("../../escape"));
    }

    #[test]
    fn escapes_json_without_dependencies() {
        let mut got = String::new();
        push_json_string(&mut got, "a\"b\\c\n");
        assert_eq!(got, "\"a\\\"b\\\\c\\n\"");
    }
}
