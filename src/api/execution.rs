//! Shared execution budgets and background-job lifecycle primitives.
//!
//! Analysis engines opt into these types incrementally. Keeping cancellation
//! and progress out of the MCP transport lets the TUI, CLI, and MCP drive the
//! same long-running operation later.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSpec {
    pub maximum_work_units: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStop {
    WorkLimit,
    Timeout,
    Cancelled,
}

pub struct ExecutionBudget {
    spec: BudgetSpec,
    started: Instant,
    consumed: u64,
    cancellation: CancellationToken,
}

impl ExecutionBudget {
    pub fn new(spec: BudgetSpec, cancellation: CancellationToken) -> Self {
        Self {
            spec,
            started: Instant::now(),
            consumed: 0,
            cancellation,
        }
    }

    /// Account for deterministic work and check all stop conditions. Engines
    /// call this at bounded intervals, not once after expensive work finishes.
    pub fn checkpoint(&mut self, work_units: u64) -> Result<(), BudgetStop> {
        if self.cancellation.is_cancelled() {
            return Err(BudgetStop::Cancelled);
        }
        self.consumed = self.consumed.saturating_add(work_units);
        if self.consumed > self.spec.maximum_work_units {
            return Err(BudgetStop::WorkLimit);
        }
        if self.started.elapsed() > Duration::from_millis(self.spec.timeout_ms) {
            return Err(BudgetStop::Timeout);
        }
        Ok(())
    }

    pub fn consumed(&self) -> u64 {
        self.consumed
    }
}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    CancellationRequested,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobProgress {
    pub completed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: JobId,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_sha256: Option<String>,
    pub status: JobStatus,
    pub progress: JobProgress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct JobEntry {
    record: JobRecord,
    cancellation: CancellationToken,
}

pub struct JobRegistry {
    entries: BTreeMap<JobId, JobEntry>,
    order: VecDeque<JobId>,
    next_id: u64,
    retained_terminal_jobs: usize,
}

impl JobRegistry {
    pub fn new(retained_terminal_jobs: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            next_id: 1,
            retained_terminal_jobs: retained_terminal_jobs.max(1),
        }
    }

    pub fn submit(
        &mut self,
        operation: impl Into<String>,
        target_sha256: Option<String>,
    ) -> (JobId, CancellationToken) {
        self.prune_terminal();
        let id = JobId(format!("job-{:016x}", self.next_id));
        self.next_id = self.next_id.saturating_add(1);
        let cancellation = CancellationToken::default();
        let record = JobRecord {
            id: id.clone(),
            operation: operation.into(),
            target_sha256,
            status: JobStatus::Queued,
            progress: JobProgress {
                completed: 0,
                total: None,
                message: None,
            },
            result_id: None,
            error: None,
        };
        self.order.push_back(id.clone());
        self.entries.insert(
            id.clone(),
            JobEntry {
                record,
                cancellation: cancellation.clone(),
            },
        );
        (id, cancellation)
    }

    pub fn start(&mut self, id: &JobId, total: Option<u64>) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        if entry.record.status != JobStatus::Queued {
            return false;
        }
        if entry.cancellation.is_cancelled() {
            entry.record.status = JobStatus::Cancelled;
            return false;
        }
        entry.record.status = JobStatus::Running;
        entry.record.progress.total = total;
        true
    }

    pub fn progress(&mut self, id: &JobId, completed: u64, message: Option<String>) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        if !matches!(
            entry.record.status,
            JobStatus::Running | JobStatus::CancellationRequested
        ) {
            return false;
        }
        entry.record.progress.completed = completed;
        entry.record.progress.message = message;
        true
    }

    pub fn request_cancel(&mut self, id: &JobId) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        match entry.record.status {
            JobStatus::Queued => entry.record.status = JobStatus::Cancelled,
            JobStatus::Running => entry.record.status = JobStatus::CancellationRequested,
            JobStatus::CancellationRequested => {}
            status if status.is_terminal() => return false,
            _ => return false,
        }
        entry.cancellation.cancel();
        true
    }

    pub fn finish(&mut self, id: &JobId, result_id: Option<String>) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        if !matches!(
            entry.record.status,
            JobStatus::Running | JobStatus::CancellationRequested
        ) {
            return false;
        }
        if entry.cancellation.is_cancelled() {
            entry.record.status = JobStatus::Cancelled;
        } else {
            entry.record.status = JobStatus::Succeeded;
            entry.record.result_id = result_id;
        }
        true
    }

    pub fn fail(&mut self, id: &JobId, error: impl Into<String>) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        if entry.record.status.is_terminal() {
            return false;
        }
        entry.record.status = JobStatus::Failed;
        entry.record.error = Some(error.into());
        true
    }

    pub fn get(&self, id: &JobId) -> Option<&JobRecord> {
        self.entries.get(id).map(|entry| &entry.record)
    }

    pub fn list(&self) -> Vec<JobRecord> {
        self.order
            .iter()
            .rev()
            .filter_map(|id| self.get(id).cloned())
            .collect()
    }

    fn prune_terminal(&mut self) {
        let mut terminal = self
            .entries
            .values()
            .filter(|entry| entry.record.status.is_terminal())
            .count();
        while terminal >= self.retained_terminal_jobs {
            let Some(position) = self.order.iter().position(|id| {
                self.entries
                    .get(id)
                    .is_some_and(|entry| entry.record.status.is_terminal())
            }) else {
                break;
            };
            let id = self.order.remove(position).expect("position exists");
            self.entries.remove(&id);
            terminal -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_observes_work_and_cancellation() {
        let cancellation = CancellationToken::default();
        let mut budget = ExecutionBudget::new(
            BudgetSpec {
                maximum_work_units: 2,
                timeout_ms: 10_000,
            },
            cancellation.clone(),
        );
        assert_eq!(budget.checkpoint(2), Ok(()));
        assert_eq!(budget.checkpoint(1), Err(BudgetStop::WorkLimit));
        cancellation.cancel();
        assert_eq!(budget.checkpoint(0), Err(BudgetStop::Cancelled));
    }

    #[test]
    fn jobs_report_progress_results_and_cooperative_cancellation() {
        let mut jobs = JobRegistry::new(2);
        let (first, token) = jobs.submit("decompile_all", Some("abc".into()));
        assert!(jobs.start(&first, Some(10)));
        assert!(jobs.progress(&first, 4, Some("lifting".into())));
        assert!(jobs.request_cancel(&first));
        assert!(token.is_cancelled());
        assert!(jobs.finish(&first, None));
        assert_eq!(jobs.get(&first).unwrap().status, JobStatus::Cancelled);

        let (second, _) = jobs.submit("index", None);
        assert!(jobs.start(&second, None));
        assert!(jobs.finish(&second, Some("result-1".into())));
        assert_eq!(jobs.get(&second).unwrap().status, JobStatus::Succeeded);
        assert_eq!(
            jobs.get(&second).unwrap().result_id.as_deref(),
            Some("result-1")
        );
    }
}
