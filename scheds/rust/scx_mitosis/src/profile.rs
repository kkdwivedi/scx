// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Profile-driven cell and subcell configuration for scx_mitosis.
//!
//! Parses a JSON profile that defines cells (with optional CgroupRegex templates)
//! and subcells (with task-matching rules). Subcells are first-class BPF
//! abstractions with dedicated DSQs, per-subcell vtime, and cpumask-based
//! CPU partitioning.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use regex::Regex;
use scx_utils::Cpumask;
use serde::Deserialize;
use tracing::{debug, info};

use crate::cell_manager::CpuAssignment;

const MAX_TOTAL_SUBCELLS: usize = crate::bpf_intf::consts_MAX_TOTAL_SUBCELLS as usize;
const MAX_CELLS: usize = crate::bpf_intf::consts_MAX_CELLS as usize;
const MAX_MATCH_STR: usize = crate::bpf_intf::consts_MAX_MATCH_STR as usize;
const MAX_SUBCELL_MATCH_ORS: usize = crate::bpf_intf::consts_MAX_SUBCELL_MATCH_ORS as usize;
const MAX_SUBCELL_MATCH_ANDS: usize = crate::bpf_intf::consts_MAX_SUBCELL_MATCH_ANDS as usize;

// ============ Profile JSON schema ============

/// A single task-matching rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum TaskMatch {
    CgroupContains(String),
    CgroupRegex(String),
    CommPrefix(String),
}

/// A subcell specification within a cell.
#[derive(Debug, Clone, Deserialize)]
pub struct SubcellSpec {
    pub name: String,
    /// OR-of-ANDs matching. Outer vec = OR groups, inner vec = AND rules.
    pub matches: Vec<Vec<TaskMatch>>,
}

/// A cell specification in the profile.
#[derive(Debug, Clone, Deserialize)]
pub struct CellSpec {
    pub name: String,
    /// Template match for discovering cgroups (CgroupRegex or CgroupPrefix etc.)
    #[serde(rename = "match")]
    pub template_match: Option<TaskMatch>,
    /// Static cell-level matches (for task routing without cgroup ownership)
    pub matches: Option<Vec<Vec<TaskMatch>>>,
    /// Subcell definitions within this cell
    pub subcells: Option<Vec<SubcellSpec>>,
}

/// The top-level profile document.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub cells: Vec<CellSpec>,
}

// ============ Resolved structures ============

/// A resolved subcell with a global ID assigned.
#[derive(Debug)]
pub struct ResolvedSubcell {
    pub name: String,
    pub global_subcell_id: u32,
    pub matches: Vec<Vec<TaskMatch>>,
    pub cpumask: Option<Cpumask>,
}

/// A resolved cell with its cgroup binding and subcells.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ResolvedCell {
    pub name: String,
    pub cell_id: u32,
    pub cgid: Option<u64>,
    pub cgroup_path: Option<PathBuf>,
    pub cpuset: Option<Cpumask>,
    pub matches: Vec<Vec<TaskMatch>>,
    pub subcells: Vec<ResolvedSubcell>,
    pub template_source: Option<String>,
}

// ============ ProfileManager ============

pub struct ProfileManager {
    spec: Profile,
    pub resolved_cells: Vec<ResolvedCell>,
    next_cell_id: u32,
    free_cell_ids: Vec<u32>,
    next_subcell_id: u32,
    all_cpus: Cpumask,
}

impl ProfileManager {
    /// Parse a profile from a JSON file and resolve cells.
    pub fn from_file(
        path: &str,
        all_cpus: Cpumask,
    ) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read profile: {}", path))?;
        let spec: Profile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse profile JSON: {}", path))?;

        let mut mgr = Self {
            spec,
            resolved_cells: Vec::new(),
            next_cell_id: 1, // cell 0 is root
            free_cell_ids: Vec::new(),
            next_subcell_id: 1, // subcell 0 means "no subcell"
            all_cpus,
        };

        // Always create cell 0 (root)
        mgr.resolved_cells.push(ResolvedCell {
            name: "root".to_string(),
            cell_id: 0,
            cgid: None,
            cgroup_path: None,
            cpuset: None,
            matches: Vec::new(),
            subcells: Vec::new(),
            template_source: None,
        });

        mgr.resolve_cells()?;

        Ok(mgr)
    }

    fn allocate_cell_id(&mut self) -> Result<u32> {
        if let Some(id) = self.free_cell_ids.pop() {
            return Ok(id);
        }
        if self.next_cell_id >= MAX_CELLS as u32 {
            bail!("Cell ID space exhausted");
        }
        let id = self.next_cell_id;
        self.next_cell_id += 1;
        Ok(id)
    }

    fn allocate_subcell_id(&mut self) -> Result<u32> {
        if self.next_subcell_id >= MAX_TOTAL_SUBCELLS as u32 {
            bail!("Subcell ID space exhausted (max={})", MAX_TOTAL_SUBCELLS);
        }
        let id = self.next_subcell_id;
        self.next_subcell_id += 1;
        Ok(id)
    }

    /// Resolve all cells from the profile spec.
    fn resolve_cells(&mut self) -> Result<()> {
        let specs = self.spec.cells.clone();
        for cell_spec in &specs {
            match &cell_spec.template_match {
                Some(TaskMatch::CgroupRegex(pattern)) => {
                    self.expand_cgroup_regex(cell_spec, pattern)?;
                }
                Some(TaskMatch::CgroupContains(substring)) => {
                    self.expand_cgroup_contains(cell_spec, substring)?;
                }
                None => {
                    // Static cell (no cgroup template)
                    self.resolve_static_cell(cell_spec)?;
                }
                _ => {
                    bail!(
                        "Unsupported template match type for cell '{}': only CgroupRegex and CgroupContains are supported",
                        cell_spec.name
                    );
                }
            }
        }
        Ok(())
    }

    /// Resolve a static cell (no cgroup template).
    fn resolve_static_cell(&mut self, spec: &CellSpec) -> Result<()> {
        let cell_id = self.allocate_cell_id()?;
        let subcells = self.resolve_subcells(cell_id, spec)?;

        self.resolved_cells.push(ResolvedCell {
            name: spec.name.clone(),
            cell_id,
            cgid: None,
            cgroup_path: None,
            cpuset: None,
            matches: spec.matches.clone().unwrap_or_default(),
            subcells,
            template_source: None,
        });

        info!("Resolved static cell '{}' -> cell_id={}", spec.name, cell_id);
        Ok(())
    }

    /// Expand CgroupRegex template: walk /sys/fs/cgroup and create cells for matching cgroups.
    fn expand_cgroup_regex(&mut self, spec: &CellSpec, pattern: &str) -> Result<()> {
        let re = Regex::new(pattern)
            .with_context(|| format!("Invalid regex '{}' in cell '{}'", pattern, spec.name))?;

        let cgroup_root = PathBuf::from("/sys/fs/cgroup");
        self.walk_cgroups_matching(&cgroup_root, spec, &re)?;

        Ok(())
    }

    fn walk_cgroups_matching(
        &mut self,
        dir: &Path,
        spec: &CellSpec,
        re: &Regex,
    ) -> Result<()> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_dir() {
                continue;
            }
            let path = entry.path();
            let rel_path = path
                .strip_prefix("/sys/fs/cgroup")
                .unwrap_or(&path)
                .to_string_lossy();

            if re.is_match(&rel_path) {
                self.create_cell_for_cgroup(spec, &path)?;
            }

            // Recurse into subdirectories
            self.walk_cgroups_matching(&path, spec, re)?;
        }
        Ok(())
    }

    /// Expand CgroupContains template.
    fn expand_cgroup_contains(&mut self, spec: &CellSpec, substring: &str) -> Result<()> {
        let cgroup_root = PathBuf::from("/sys/fs/cgroup");
        self.walk_cgroups_containing(&cgroup_root, spec, substring)?;
        Ok(())
    }

    fn walk_cgroups_containing(
        &mut self,
        dir: &Path,
        spec: &CellSpec,
        substring: &str,
    ) -> Result<()> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(substring) {
                self.create_cell_for_cgroup(spec, &path)?;
            }
            self.walk_cgroups_containing(&path, spec, substring)?;
        }
        Ok(())
    }

    fn create_cell_for_cgroup(&mut self, spec: &CellSpec, path: &Path) -> Result<()> {
        let cgid = path.metadata()?.ino();

        // Skip if we already have a cell for this cgroup
        if self
            .resolved_cells
            .iter()
            .any(|c| c.cgid == Some(cgid))
        {
            return Ok(());
        }

        let cell_id = self.allocate_cell_id()?;
        let cpuset = read_cpuset(path)?;
        let subcells = self.resolve_subcells(cell_id, spec)?;

        let cell_name = format!(
            "{}[{}]",
            spec.name,
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "?".to_string())
        );

        info!(
            "Template '{}' matched cgroup {} -> cell_id={}, subcells={}",
            spec.name,
            path.display(),
            cell_id,
            subcells.len()
        );

        self.resolved_cells.push(ResolvedCell {
            name: cell_name,
            cell_id,
            cgid: Some(cgid),
            cgroup_path: Some(path.to_path_buf()),
            cpuset,
            matches: spec.matches.clone().unwrap_or_default(),
            subcells,
            template_source: Some(spec.name.clone()),
        });

        Ok(())
    }

    /// Resolve subcell specs for a cell, allocating global subcell IDs.
    fn resolve_subcells(&mut self, cell_id: u32, spec: &CellSpec) -> Result<Vec<ResolvedSubcell>> {
        let subcell_specs = match &spec.subcells {
            Some(specs) => specs,
            None => return Ok(Vec::new()),
        };

        let mut resolved = Vec::new();
        for sc_spec in subcell_specs {
            let sc_id = self.allocate_subcell_id()?;
            resolved.push(ResolvedSubcell {
                name: sc_spec.name.clone(),
                global_subcell_id: sc_id,
                matches: sc_spec.matches.clone(),
                cpumask: None,
            });
            debug!(
                "  Subcell '{}' -> global_id={} (cell {})",
                sc_spec.name, sc_id, cell_id
            );
        }
        Ok(resolved)
    }

    /// Returns all cell assignments as (cgid, cell_id) pairs for BPF configuration.
    pub fn get_cell_assignments(&self) -> Vec<(u64, u32)> {
        self.resolved_cells
            .iter()
            .filter(|c| c.cell_id != 0 && c.cgid.is_some())
            .map(|c| (c.cgid.unwrap(), c.cell_id))
            .collect()
    }

    /// Compute CPU assignments for all resolved cells.
    /// Uses equal weight distribution among all cells.
    pub fn compute_cpu_assignments(&self, compute_borrowable: bool) -> Result<Vec<CpuAssignment>> {
        let num_cells = self.resolved_cells.len();
        if num_cells == 0 {
            bail!("No cells resolved");
        }

        let total_cpus = self.all_cpus.weight();
        if total_cpus < num_cells {
            bail!(
                "Not enough CPUs ({}) for {} cells",
                total_cpus,
                num_cells
            );
        }

        // Simple equal distribution among all cells
        let cells_with_weights: Vec<(u32, f64)> = self
            .resolved_cells
            .iter()
            .map(|c| (c.cell_id, 1.0))
            .collect();

        let targets = crate::cell_manager::compute_targets_pub(total_cpus, &cells_with_weights)?;

        // Assign actual CPUs sequentially
        let mut assignments = Vec::new();
        let all_cpus: Vec<usize> = self.all_cpus.iter().collect();
        let mut cpu_iter = all_cpus.iter().copied();

        // Sort by cell_id for deterministic assignment
        let mut sorted_targets: Vec<(u32, usize)> = targets.into_iter().collect();
        sorted_targets.sort_by_key(|(cell_id, _)| *cell_id);

        for (cell_id, count) in sorted_targets {
            let mut primary = Cpumask::new();
            for _ in 0..count {
                if let Some(cpu) = cpu_iter.next() {
                    primary.set_cpu(cpu).ok();
                }
            }

            let borrowable = if compute_borrowable {
                Some(self.all_cpus.and(&primary.not()))
            } else {
                None
            };

            assignments.push(CpuAssignment {
                cell_id,
                primary,
                borrowable,
            });
        }

        Ok(assignments)
    }

    /// Compute subcell CPU assignments within each cell.
    /// Divides each cell's CPUs equally among its subcells.
    pub fn compute_subcell_cpu_assignments(
        &mut self,
        cpu_assignments: &[CpuAssignment],
    ) -> Result<()> {
        for cell in &mut self.resolved_cells {
            if cell.subcells.is_empty() {
                continue;
            }

            let cell_assignment = cpu_assignments
                .iter()
                .find(|a| a.cell_id == cell.cell_id);
            let cell_mask = match cell_assignment {
                Some(a) => &a.primary,
                None => continue,
            };

            let cell_cpus: Vec<usize> = cell_mask.iter().collect();
            let num_subcells = cell.subcells.len();
            if num_subcells == 0 || cell_cpus.is_empty() {
                continue;
            }

            // Equal division of CPUs among subcells
            let per_subcell = cell_cpus.len() / num_subcells;
            let remainder = cell_cpus.len() % num_subcells;
            let mut offset = 0;

            for (i, sc) in cell.subcells.iter_mut().enumerate() {
                let extra = if i < remainder { 1 } else { 0 };
                let count = per_subcell + extra;
                let mut mask = Cpumask::new();
                for j in 0..count {
                    if offset + j < cell_cpus.len() {
                        mask.set_cpu(cell_cpus[offset + j]).ok();
                    }
                }
                offset += count;
                sc.cpumask = Some(mask);
                debug!(
                    "Subcell '{}' (id={}) gets {} CPUs",
                    sc.name, sc.global_subcell_id, count
                );
            }
        }
        Ok(())
    }

    /// Check if subcells are configured in any cell.
    pub fn has_subcells(&self) -> bool {
        self.resolved_cells.iter().any(|c| !c.subcells.is_empty())
    }

    /// Populate BPF BSS subcell_specs before BPF load.
    pub fn populate_bpf_subcell_specs(&self, skel: &mut crate::BpfSkel) -> Result<()> {
        let bss = skel
            .maps
            .bss_data
            .as_mut()
            .expect("bss_data must be available");

        let mut spec_idx: u32 = 0;

        for cell in &self.resolved_cells {
            for sc in &cell.subcells {
                if spec_idx as usize >= MAX_TOTAL_SUBCELLS {
                    bail!("Too many subcell specs (max={})", MAX_TOTAL_SUBCELLS);
                }

                let bpf_spec = &mut bss.subcell_specs[spec_idx as usize];
                bpf_spec.parent_cell = cell.cell_id;
                bpf_spec.subcell_id = sc.global_subcell_id;

                // Populate match set
                let nr_groups = sc.matches.len().min(MAX_SUBCELL_MATCH_ORS);
                bpf_spec.matches.nr_groups = nr_groups as u32;

                for (gi, group) in sc.matches.iter().enumerate().take(nr_groups) {
                    let nr_rules = group.len().min(MAX_SUBCELL_MATCH_ANDS);
                    bpf_spec.matches.groups[gi].nr_rules = nr_rules as u32;

                    for (ri, rule) in group.iter().enumerate().take(nr_rules) {
                        let bpf_match = &mut bpf_spec.matches.groups[gi].rules[ri];
                        match rule {
                            TaskMatch::CommPrefix(s) => {
                                bpf_match.kind =
                                    crate::bpf_intf::subcell_match_kind_SUBCELL_MATCH_COMM_PREFIX;
                                copy_str_to_match(&mut bpf_match.str, s);
                            }
                            _ => {
                                // CgroupContains/CgroupRegex are for cell-level
                                // template expansion only, not BPF task matching
                            }
                        }
                    }
                }

                spec_idx += 1;
            }
        }

        bss.nr_subcell_specs = spec_idx;
        info!("Populated {} subcell specs in BPF BSS", spec_idx);

        Ok(())
    }

    /// Build the subcell_config BSS struct for apply_cell_config.
    pub fn build_subcell_config(&self, skel: &mut crate::BpfSkel) -> Result<()> {
        let bss = skel
            .maps
            .bss_data
            .as_mut()
            .expect("bss_data must be available");

        let config = &mut bss.subcell_config;

        // Zero out
        unsafe {
            std::ptr::write_bytes(
                config as *mut _ as *mut u8,
                0,
                std::mem::size_of_val(config),
            );
        }

        let mut idx: u32 = 0;
        for cell in &self.resolved_cells {
            for sc in &cell.subcells {
                if idx as usize >= MAX_TOTAL_SUBCELLS {
                    bail!("Too many subcells for config");
                }

                config.assignments[idx as usize].subcell_id = sc.global_subcell_id;
                config.assignments[idx as usize].parent_cell = cell.cell_id;

                // Write cpumask
                if let Some(ref mask) = sc.cpumask {
                    crate::write_cpumask_to_config(
                        mask,
                        &mut config.cpumasks[idx as usize].mask,
                    );
                }

                idx += 1;
            }
        }
        config.num_subcells = idx;

        debug!("Built subcell_config with {} subcells", idx);
        Ok(())
    }

    /// Format the profile configuration for logging.
    pub fn format_config(&self, cpu_assignments: &[CpuAssignment]) -> String {
        let mut parts = Vec::new();
        let mut sorted: Vec<_> = cpu_assignments.iter().collect();
        sorted.sort_by_key(|a| a.cell_id);

        for assignment in sorted {
            let cpulist = assignment.primary.to_cpulist();
            let cell = self
                .resolved_cells
                .iter()
                .find(|c| c.cell_id == assignment.cell_id);

            let name = cell.map(|c| c.name.as_str()).unwrap_or("?");
            let sc_info = cell
                .map(|c| {
                    if c.subcells.is_empty() {
                        String::new()
                    } else {
                        let sc_names: Vec<_> = c.subcells.iter().map(|s| s.name.as_str()).collect();
                        format!(" sc=[{}]", sc_names.join(","))
                    }
                })
                .unwrap_or_default();

            parts.push(format!("[{}({}): {}{}]", assignment.cell_id, name, cpulist, sc_info));
        }
        parts.join(" ")
    }
}

/// Copy a string into a fixed-size BPF match buffer, truncating if needed.
fn copy_str_to_match(dest: &mut [i8; MAX_MATCH_STR], src: &str) {
    let bytes = src.as_bytes();
    let copy_len = bytes.len().min(MAX_MATCH_STR - 1);
    for i in 0..copy_len {
        dest[i] = bytes[i] as i8;
    }
    // Null-terminate
    if copy_len < MAX_MATCH_STR {
        dest[copy_len] = 0;
    }
}

/// Read cpuset.cpus from a cgroup path. Returns None if empty or unavailable.
fn read_cpuset(cgroup_path: &Path) -> Result<Option<Cpumask>> {
    let cpuset_path = cgroup_path.join("cpuset.cpus");
    match std::fs::read_to_string(&cpuset_path) {
        Ok(content) => {
            let content = content.trim();
            if content.is_empty() {
                Ok(None)
            } else {
                let mask = Cpumask::from_cpulist(content).with_context(|| {
                    format!(
                        "Failed to parse cpuset '{}' from {}",
                        content,
                        cpuset_path.display()
                    )
                })?;
                Ok(Some(mask))
            }
        }
        Err(_) => Ok(None),
    }
}
