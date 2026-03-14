// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::record::{perf_binary, PERF_SCHED_SCRIPT_FIELDS, PERF_SCRIPT_FIELDS};
use anyhow::{bail, Context as _, Result};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Parser)]
pub struct ProcessOpts {
    /// Path to profile file (tar.gz) or directory
    #[clap(short = 'f', long)]
    pub file: PathBuf,

    /// Print extra information during processing
    #[clap(short, long)]
    pub verbose: bool,
}

/// Represents a single perf script sample record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfScriptRecord {
    pub comm: String,
    pub tid: u32,
    pub pid: u32,
    pub time: String,
    pub addr: String,
    pub cgroup: String,
    pub ip: String,
    pub sym: String,
    pub dso: String,
    pub phys_addr: String,
    pub data_page_size: u64,
}

/// Represents a single sched trace record from perf script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfSchedScriptRecord {
    pub comm: String,
    pub pid: i32,
    pub tid: i32,
    pub cpu: u32,
    pub time: f64,
    pub event: String,
    pub trace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Map<String, Value>>,
}

pub fn cmd_process(opts: ProcessOpts) -> Result<()> {
    let profile_dir = prepare_profile_dir(&opts.file)?;

    let output_dir = create_output_dir(&profile_dir)?;
    println!("Output directory: {}", output_dir.display());

    match run_processing(&profile_dir, &output_dir, opts.verbose) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_dir_all(&output_dir);
            Err(e)
        }
    }
}

fn run_processing(profile_dir: &Path, output_dir: &Path, verbose: bool) -> Result<()> {
    let perf_script_src = profile_dir.join("perf.script");
    let perf_script_dst = output_dir.join("perf.script");
    let perf_jsonl_dst = output_dir.join("perf.jsonl");
    let sched_perf_data_src = profile_dir.join("perf.sched.data");
    let sched_perf_script_src = profile_dir.join("perf.sched.script");
    let sched_perf_script_dst = output_dir.join("perf.sched.script");
    let sched_perf_jsonl_dst = output_dir.join("perf.sched.jsonl");

    if !perf_script_src.exists() {
        println!("Generating perf.script from perf.data...");
        generate_perf_script(
            &profile_dir.join("perf.data"),
            &perf_script_src,
            PERF_SCRIPT_FIELDS,
        )?;
    }

    println!("Copying perf.script...");
    fs::copy(&perf_script_src, &perf_script_dst).context("failed to copy perf.script")?;

    println!("Parsing perf.script to generate perf.jsonl...");
    parse_perf_script_to_jsonl(&perf_script_dst, &perf_jsonl_dst, verbose)?;

    if sched_perf_script_src.exists() || sched_perf_data_src.exists() {
        if !sched_perf_script_src.exists() {
            println!("Generating perf.sched.script from perf.sched.data...");
            generate_perf_script(
                &sched_perf_data_src,
                &sched_perf_script_src,
                PERF_SCHED_SCRIPT_FIELDS,
            )?;
        }

        println!("Copying perf.sched.script...");
        fs::copy(&sched_perf_script_src, &sched_perf_script_dst)
            .context("failed to copy perf.sched.script")?;

        println!("Parsing perf.sched.script to generate perf.sched.jsonl...");
        parse_sched_perf_script_to_jsonl(&sched_perf_script_dst, &sched_perf_jsonl_dst, verbose)?;
    }

    print_profile_contents(output_dir)?;
    Ok(())
}

fn prepare_profile_dir(path: &Path) -> Result<PathBuf> {
    if path.is_dir() {
        return Ok(path.to_path_buf());
    }

    let path_str = path.to_string_lossy();
    if !path_str.ends_with(".tar.gz") {
        bail!("'{}' is not a directory or tar.gz archive", path.display());
    }

    let dir_name = path_str.trim_end_matches(".tar.gz");
    let output_dir = PathBuf::from(dir_name);

    if output_dir.exists() {
        return Ok(output_dir);
    }

    let status = Command::new("tar")
        .args(["-xzf", &path_str, "-C", "."])
        .status()
        .context("failed to run tar")?;

    if !status.success() {
        bail!("tar extraction failed with status: {}", status);
    }

    if !output_dir.exists() {
        bail!(
            "expected directory '{}' not found after extraction",
            output_dir.display()
        );
    }

    Ok(output_dir)
}

fn create_output_dir(profile_dir: &Path) -> Result<PathBuf> {
    let output_dir = PathBuf::from(format!("{}.out", profile_dir.display()));

    if output_dir.exists() {
        bail!("output directory '{}' already exists", output_dir.display());
    }

    fs::create_dir_all(&output_dir).context("failed to create output directory")?;

    Ok(output_dir)
}

fn generate_perf_script(
    perf_data_path: &Path,
    perf_script_path: &Path,
    fields: &str,
) -> Result<()> {
    if !perf_data_path.exists() {
        bail!("perf data file '{}' not found", perf_data_path.display());
    }

    let output = Command::new(perf_binary())
        .args([
            "script",
            "-F",
            fields,
            "-i",
            perf_data_path.to_str().context("invalid perf.data path")?,
        ])
        .output()
        .context("failed to run perf script")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("perf script failed: {}", stderr);
    }

    fs::write(&perf_script_path, &output.stdout).context("failed to write perf.script")?;

    Ok(())
}

fn sched_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(?P<comm>.*?)\s+(?P<pid>-?\d+)/(?P<tid>-?\d+)\s+\[(?P<cpu>\d+)\]\s+(?P<time>\d+\.\d+):\s+(?P<event>[^:]+:[^:]+):\s*(?P<trace>.*)$",
        )
        .unwrap()
    })
}

fn sched_switch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<prev_comm>.+?):(?P<prev_pid>-?\d+)\s+\[(?P<prev_prio>-?\d+)\]\s+(?P<prev_state>.+?)\s+==>\s+(?P<next_comm>.+?):(?P<next_pid>-?\d+)\s+\[(?P<next_prio>-?\d+)\]$",
        )
        .unwrap()
    })
}

fn kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(\w+)=([^\s\]]+)").unwrap())
}

fn action_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[action=([^\]]+)\]").unwrap())
}

fn parse_page_size(s: &str) -> u64 {
    let s = s.trim();
    if s == "N/A" || s.is_empty() {
        return 0;
    }
    let s_upper = s.to_uppercase();
    if let Some(num_str) = s_upper.strip_suffix('K') {
        num_str.parse::<u64>().unwrap_or(0) * 1024
    } else if let Some(num_str) = s_upper.strip_suffix('M') {
        num_str.parse::<u64>().unwrap_or(0) * 1024 * 1024
    } else if let Some(num_str) = s_upper.strip_suffix('G') {
        num_str.parse::<u64>().unwrap_or(0) * 1024 * 1024 * 1024
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

fn parse_perf_script_line(line: &str) -> Option<PerfScriptRecord> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 8 {
        return None;
    }

    let mut tid_pid_idx = None;
    for (i, part) in parts.iter().enumerate() {
        if part.contains('/') {
            let sub_parts: Vec<&str> = part.split('/').collect();
            if sub_parts.len() == 2
                && sub_parts[0].parse::<u32>().is_ok()
                && sub_parts[1].parse::<u32>().is_ok()
            {
                tid_pid_idx = Some(i);
                break;
            }
        }
    }

    let tid_pid_idx = tid_pid_idx?;

    let comm = parts[..tid_pid_idx].join(" ");

    let tid_pid: Vec<&str> = parts[tid_pid_idx].split('/').collect();
    let tid = tid_pid[0].parse::<u32>().ok()?;
    let pid = tid_pid[1].parse::<u32>().ok()?;

    let remaining = &parts[tid_pid_idx + 1..];

    if remaining.len() < 4 {
        return None;
    }

    let time = remaining[0].trim_end_matches(':').to_string();
    let addr = remaining[1].to_string();
    let cgroup = remaining[2].to_string();
    let ip = remaining[3].to_string();

    let after_ip = &remaining[4..];
    let after_ip_str = after_ip.join(" ");

    let (sym, dso, phys_addr, data_page_size) = if let Some(paren_end) = after_ip_str.rfind(')') {
        if let Some(paren_start) = after_ip_str[..paren_end].rfind('(') {
            let sym = after_ip_str[..paren_start].trim().to_string();
            let dso = after_ip_str[paren_start + 1..paren_end].to_string();
            let after_dso: Vec<&str> = after_ip_str[paren_end + 1..].split_whitespace().collect();
            let phys_addr = after_dso.first().map(|s| s.to_string()).unwrap_or_default();
            let data_page_size = parse_page_size(after_dso.get(1).unwrap_or(&"0"));
            (sym, dso, phys_addr, data_page_size)
        } else {
            (after_ip_str, String::new(), String::new(), 0)
        }
    } else {
        (String::new(), String::new(), String::new(), 0)
    };

    Some(PerfScriptRecord {
        comm,
        tid,
        pid,
        time,
        addr,
        cgroup,
        ip,
        sym,
        dso,
        phys_addr,
        data_page_size,
    })
}

fn maybe_int_value(value: &str) -> Value {
    match value.parse::<i64>() {
        Ok(num) => Value::Number(Number::from(num)),
        Err(_) => Value::String(value.to_string()),
    }
}

fn parse_sched_fields(event: &str, trace: &str) -> Option<Map<String, Value>> {
    let mut fields = Map::new();

    if event == "sched:sched_switch" {
        let captures = sched_switch_re().captures(trace)?;
        let prev_comm = captures.name("prev_comm")?.as_str();
        let prev_pid = captures.name("prev_pid")?.as_str().parse::<i64>().ok()?;
        let prev_prio = captures.name("prev_prio")?.as_str().parse::<i64>().ok()?;
        let prev_state = captures.name("prev_state")?.as_str();
        let next_comm = captures.name("next_comm")?.as_str();
        let next_pid = captures.name("next_pid")?.as_str().parse::<i64>().ok()?;
        let next_prio = captures.name("next_prio")?.as_str().parse::<i64>().ok()?;

        fields.insert(
            "prev_comm".to_string(),
            Value::String(prev_comm.to_string()),
        );
        fields.insert(
            "prev_pid".to_string(),
            Value::Number(Number::from(prev_pid)),
        );
        fields.insert(
            "prev_prio".to_string(),
            Value::Number(Number::from(prev_prio)),
        );
        fields.insert(
            "prev_state".to_string(),
            Value::String(prev_state.to_string()),
        );
        fields.insert(
            "next_comm".to_string(),
            Value::String(next_comm.to_string()),
        );
        fields.insert(
            "next_pid".to_string(),
            Value::Number(Number::from(next_pid)),
        );
        fields.insert(
            "next_prio".to_string(),
            Value::Number(Number::from(next_prio)),
        );
        fields.insert(
            "cpu_idle".to_string(),
            Value::Bool(next_pid == 0 || next_comm.starts_with("swapper")),
        );
        fields.insert(
            "prev_idle".to_string(),
            Value::Bool(prev_pid == 0 || prev_comm.starts_with("swapper")),
        );
        return Some(fields);
    }

    for captures in kv_re().captures_iter(trace) {
        fields.insert(
            captures[1].to_string(),
            maybe_int_value(captures.get(2).unwrap().as_str()),
        );
    }

    if let Some(captures) = action_re().captures(trace) {
        fields.insert("action".to_string(), Value::String(captures[1].to_string()));
    }

    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}

fn parse_sched_perf_script_line(line: &str) -> Option<PerfSchedScriptRecord> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let captures = sched_line_re().captures(line)?;
    let comm = captures.name("comm")?.as_str().trim().to_string();
    let pid = captures.name("pid")?.as_str().parse::<i32>().ok()?;
    let tid = captures.name("tid")?.as_str().parse::<i32>().ok()?;
    let cpu = captures.name("cpu")?.as_str().parse::<u32>().ok()?;
    let time = captures.name("time")?.as_str().parse::<f64>().ok()?;
    let event = captures.name("event")?.as_str().trim().to_string();
    let trace = captures.name("trace")?.as_str().trim().to_string();
    let fields = parse_sched_fields(&event, &trace);

    Some(PerfSchedScriptRecord {
        comm,
        pid,
        tid,
        cpu,
        time,
        event,
        trace,
        fields,
    })
}

fn parse_perf_script_to_jsonl(
    perf_script_path: &Path,
    output_path: &Path,
    verbose: bool,
) -> Result<()> {
    let file = File::open(perf_script_path).context("failed to open perf.script")?;
    let reader = BufReader::new(file);

    let output_file = File::create(output_path).context("failed to create perf.jsonl")?;
    let mut writer = BufWriter::new(output_file);

    let mut count = 0;
    let mut skipped = 0;
    let mut errors = 0;

    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        match parse_perf_script_line(&line) {
            Some(record) => {
                if record.phys_addr == "0" || record.phys_addr.is_empty() {
                    skipped += 1;
                    if verbose {
                        eprintln!("skipped (no phys_addr): {}", line);
                    }
                    continue;
                }
                if record.comm == "perf" || record.comm == "swapper" {
                    skipped += 1;
                    if verbose {
                        eprintln!("skipped (filtered comm): {}", line);
                    }
                    continue;
                }
                let json = serde_json::to_string(&record).context("failed to serialize record")?;
                writeln!(writer, "{}", json)?;
                count += 1;
            }
            None => {
                if !line.trim().is_empty() {
                    errors += 1;
                    if verbose {
                        eprintln!("unparseable: {}", line);
                    }
                }
            }
        }
    }

    writer.flush()?;

    let total = count + skipped + errors;
    println!(
        "Parsed {} of {} records ({} skipped, {} unparseable)",
        count, total, skipped, errors
    );

    Ok(())
}

fn parse_sched_perf_script_to_jsonl(
    perf_script_path: &Path,
    output_path: &Path,
    verbose: bool,
) -> Result<()> {
    let file = File::open(perf_script_path).context("failed to open perf.sched.script")?;
    let reader = BufReader::new(file);

    let output_file = File::create(output_path).context("failed to create perf.sched.jsonl")?;
    let mut writer = BufWriter::new(output_file);

    let mut count = 0;
    let mut errors = 0;

    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        match parse_sched_perf_script_line(&line) {
            Some(record) => {
                let json = serde_json::to_string(&record).context("failed to serialize record")?;
                writeln!(writer, "{}", json)?;
                count += 1;
            }
            None => {
                if !line.trim().is_empty() {
                    errors += 1;
                    if verbose {
                        eprintln!("unparseable sched line: {}", line);
                    }
                }
            }
        }
    }

    writer.flush()?;

    let total = count + errors;
    println!(
        "Parsed {} of {} sched trace records ({} unparseable)",
        count, total, errors
    );

    Ok(())
}

fn print_profile_contents(profile_dir: &Path) -> Result<()> {
    println!("Output contents:");

    let entries: Vec<_> = std::fs::read_dir(profile_dir)
        .context("failed to read profile directory")?
        .filter_map(|e| e.ok())
        .collect();

    if entries.is_empty() {
        println!("  (empty)");
        return Ok(());
    }

    for entry in entries {
        let metadata = entry.metadata().ok();
        let size = metadata.map(|m| m.len()).unwrap_or(0);
        println!("  {} ({} bytes)", entry.file_name().to_string_lossy(), size);
    }

    Ok(())
}
