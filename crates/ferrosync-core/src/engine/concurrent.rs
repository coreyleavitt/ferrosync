//! Concurrent file transfer pipeline.
//!
//! Provides a semaphore-bounded concurrent file processing engine that
//! can run multiple file transfers in parallel while preserving result
//! ordering. When concurrency is 1, files are processed inline without
//! spawning overhead.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::filelist::entry::FileEntry;

// ---------------------------------------------------------------------------
// TransferPool (original API, retained for backward compatibility)
// ---------------------------------------------------------------------------

/// A bounded concurrent executor for file transfer tasks.
///
/// Limits the number of in-flight transfers to avoid overwhelming
/// the remote server or local I/O subsystem.
pub struct TransferPool {
    /// Maximum concurrent transfers.
    max_concurrent: usize,
}

impl TransferPool {
    /// Create a new transfer pool with the given concurrency limit.
    ///
    /// The limit is clamped to [1, 64].
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            max_concurrent: max_concurrent.clamp(1, 64),
        }
    }

    /// Returns the configured concurrency limit.
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Execute a batch of futures with bounded concurrency.
    ///
    /// Returns results in the order the futures complete (not submission order).
    pub async fn execute<T, F>(&self, tasks: Vec<F>) -> Vec<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut handles = Vec::with_capacity(tasks.len());

        for task in tasks {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let handle = tokio::spawn(async move {
                let result = task.await;
                drop(permit);
                result
            });
            handles.push(handle);
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => {
                    tracing::error!(error = %e, "transfer task panicked");
                }
            }
        }

        results
    }
}

// ---------------------------------------------------------------------------
// Phase 6: Concurrent file pipeline types
// ---------------------------------------------------------------------------

/// The operation to perform on a file.
#[derive(Debug, Clone)]
pub enum FileOperation {
    /// Transfer the file (new or changed).
    Transfer,
    /// Skip the file (already up to date).
    Skip,
    /// Delete an extraneous file on the receiver.
    Delete,
}

/// A unit of work for the concurrent pipeline.
#[derive(Debug, Clone)]
pub struct FileTask {
    /// Position in the original file list, used to preserve result ordering.
    pub index: usize,
    /// File entry metadata from the file list.
    pub entry: FileEntry,
    /// What operation to perform.
    pub operation: FileOperation,
    /// Resolved source path (if applicable).
    pub source_path: Option<PathBuf>,
    /// Resolved destination path (if applicable).
    pub dest_path: Option<PathBuf>,
}

/// Result of processing a single file task.
#[derive(Debug, Clone)]
pub struct TaskResult {
    /// Index from the original file list, for ordered collection.
    pub index: usize,
    /// Number of bytes transferred (literal data).
    pub bytes_transferred: u64,
    /// Whether the file was actually transferred (vs skipped/deleted).
    pub transferred: bool,
    /// Error message if the task failed, `None` on success.
    pub error: Option<String>,
}

/// Concurrent transfer pipeline.
///
/// Limits the number of in-flight file operations using a semaphore.
/// Tasks are dispatched through a bounded channel to provide
/// back-pressure when the worker pool is saturated.
pub struct ConcurrentPipeline {
    /// Maximum number of concurrent file operations.
    concurrency: usize,
}

impl ConcurrentPipeline {
    /// Create a new pipeline with the given concurrency level.
    ///
    /// The concurrency is clamped to the range 1..=64.
    pub fn new(concurrency: usize) -> Self {
        Self {
            concurrency: concurrency.clamp(1, 64),
        }
    }

    /// Returns the configured concurrency level.
    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// Returns `true` if this pipeline will process files sequentially.
    pub fn is_sequential(&self) -> bool {
        self.concurrency == 1
    }
}

/// Process a function over each task, returning results in original order.
///
/// The `process_fn` is called for each task. When `concurrency == 1`,
/// tasks are processed inline without spawning. Otherwise, up to
/// `concurrency` tasks run concurrently via `tokio::spawn`, with a
/// bounded channel providing back-pressure.
///
/// Results are always returned in the same order as the input tasks,
/// regardless of completion order.
pub async fn run_concurrent_transfers<F, Fut>(
    tasks: Vec<FileTask>,
    concurrency: usize,
    process_fn: F,
) -> Result<Vec<TaskResult>, crate::FerrosyncError>
where
    F: Fn(FileTask) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = TaskResult> + Send + 'static,
{
    let concurrency = concurrency.clamp(1, 64);

    if tasks.is_empty() {
        return Ok(Vec::new());
    }

    // Sequential fast path: no spawning overhead.
    if concurrency == 1 {
        let mut results = Vec::with_capacity(tasks.len());
        for task in tasks {
            results.push(process_fn(task).await);
        }
        return Ok(results);
    }

    // Concurrent path: bounded channel + semaphore.
    let total = tasks.len();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let process_fn = Arc::new(process_fn);
    let channel_capacity = concurrency * 2;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<FileTask>(channel_capacity);

    // Pre-allocate results storage indexed by task position.
    let results: Arc<tokio::sync::Mutex<Vec<Option<TaskResult>>>> =
        Arc::new(tokio::sync::Mutex::new(vec![None; total]));

    // Consumer: reads tasks from the channel, spawns bounded workers.
    let consumer_results = Arc::clone(&results);
    let consumer_sem = Arc::clone(&semaphore);
    let consumer_fn = Arc::clone(&process_fn);

    let consumer_handle = tokio::spawn(async move {
        let mut handles = Vec::new();

        while let Some(task) = rx.recv().await {
            let permit = consumer_sem
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore closed unexpectedly");
            let fn_clone = Arc::clone(&consumer_fn);
            let res_clone = Arc::clone(&consumer_results);
            let idx = task.index;

            let handle = tokio::spawn(async move {
                let result = fn_clone(task).await;
                let mut guard = res_clone.lock().await;
                guard[idx] = Some(result);
                drop(permit);
            });

            handles.push(handle);
        }

        // Wait for all spawned worker tasks to complete.
        for handle in handles {
            let _ = handle.await;
        }
    });

    // Producer: feed tasks into the bounded channel.
    for task in tasks {
        tx.send(task).await.map_err(|_| {
            crate::FerrosyncError::Fs(crate::error::FsError::Io {
                path: PathBuf::from("<concurrent-pipeline>"),
                source: Arc::new(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "concurrent pipeline consumer dropped",
                )),
            })
        })?;
    }

    // Close the channel so the consumer loop terminates.
    drop(tx);

    // Wait for consumer to finish.
    consumer_handle.await.map_err(|e| {
        crate::FerrosyncError::Fs(crate::error::FsError::Io {
            path: PathBuf::from("<concurrent-pipeline>"),
            source: Arc::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("concurrent pipeline join error: {e}"),
            )),
        })
    })?;

    // Collect results in order.
    let guard = results.lock().await;
    let ordered: Vec<TaskResult> = guard
        .iter()
        .enumerate()
        .map(|(i, slot)| {
            slot.clone().unwrap_or(TaskResult {
                index: i,
                bytes_transferred: 0,
                transferred: false,
                error: Some("task result missing".to_string()),
            })
        })
        .collect();

    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -----------------------------------------------------------------------
    // TransferPool tests (retained from original)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pool_clamps_concurrency() {
        let pool = TransferPool::new(0);
        assert_eq!(pool.max_concurrent(), 1);

        let pool = TransferPool::new(100);
        assert_eq!(pool.max_concurrent(), 64);

        let pool = TransferPool::new(4);
        assert_eq!(pool.max_concurrent(), 4);
    }

    #[tokio::test]
    async fn test_pool_executes_all_tasks() {
        let pool = TransferPool::new(2);
        let tasks: Vec<_> = (0..10).map(|i| async move { i * 2 }).collect();

        let results = pool.execute(tasks).await;
        assert_eq!(results.len(), 10);

        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 2, 4, 6, 8, 10, 12, 14, 16, 18]);
    }

    #[tokio::test]
    async fn test_pool_respects_concurrency_limit() {
        let pool = TransferPool::new(2);
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));

        let tasks: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = (0..10)
            .map(|_| {
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                Box::pin(async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                }) as Pin<Box<dyn Future<Output = ()> + Send>>
            })
            .collect();

        pool.execute(tasks).await;

        let observed_max = max_active.load(Ordering::SeqCst);
        assert!(
            observed_max <= 2,
            "max concurrency was {observed_max}, expected <= 2"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 6: ConcurrentPipeline and run_concurrent_transfers tests
    // -----------------------------------------------------------------------

    fn make_test_entry(name: &str) -> FileEntry {
        FileEntry {
            name: name.as_bytes().to_vec(),
            len: 100,
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn make_tasks(count: usize) -> Vec<FileTask> {
        (0..count)
            .map(|i| FileTask {
                index: i,
                entry: make_test_entry(&format!("file_{i}.txt")),
                operation: FileOperation::Transfer,
                source_path: None,
                dest_path: None,
            })
            .collect()
    }

    #[tokio::test]
    async fn sequential_matches_inline() {
        let tasks = make_tasks(5);
        let results = run_concurrent_transfers(tasks, 1, |task| async move {
            TaskResult {
                index: task.index,
                bytes_transferred: task.entry.len as u64,
                transferred: true,
                error: None,
            }
        })
        .await
        .unwrap();

        assert_eq!(results.len(), 5);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.index, i);
            assert!(r.transferred);
            assert_eq!(r.bytes_transferred, 100);
            assert!(r.error.is_none());
        }
    }

    #[tokio::test]
    async fn concurrent_processes_all_files() {
        let tasks = make_tasks(20);
        let results = run_concurrent_transfers(tasks, 4, |task| async move {
            tokio::task::yield_now().await;
            TaskResult {
                index: task.index,
                bytes_transferred: task.entry.len as u64,
                transferred: true,
                error: None,
            }
        })
        .await
        .unwrap();

        assert_eq!(results.len(), 20);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.index, i, "results must be in original order");
            assert!(r.transferred);
        }
    }

    #[tokio::test]
    async fn results_ordered_despite_varied_durations() {
        let tasks = make_tasks(8);
        let results = run_concurrent_transfers(tasks, 4, |task| async move {
            // Later indices sleep less, finishing first.
            let delay = (8 - task.index) as u64;
            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
            TaskResult {
                index: task.index,
                bytes_transferred: task.index as u64,
                transferred: true,
                error: None,
            }
        })
        .await
        .unwrap();

        assert_eq!(results.len(), 8);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.index, i);
            assert_eq!(r.bytes_transferred, i as u64);
        }
    }

    #[tokio::test]
    async fn semaphore_limits_concurrency() {
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let current = Arc::new(AtomicUsize::new(0));
        let max_clone = Arc::clone(&max_concurrent);
        let cur_clone = Arc::clone(&current);

        let tasks = make_tasks(16);
        let concurrency_limit = 4;

        let _ = run_concurrent_transfers(tasks, concurrency_limit, move |task| {
            let max_c = Arc::clone(&max_clone);
            let cur_c = Arc::clone(&cur_clone);
            async move {
                let prev = cur_c.fetch_add(1, Ordering::SeqCst);
                let running = prev + 1;
                max_c.fetch_max(running, Ordering::SeqCst);

                // Simulate work so concurrent tasks overlap.
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                cur_c.fetch_sub(1, Ordering::SeqCst);

                TaskResult {
                    index: task.index,
                    bytes_transferred: 0,
                    transferred: true,
                    error: None,
                }
            }
        })
        .await
        .unwrap();

        let observed_max = max_concurrent.load(Ordering::SeqCst);
        assert!(
            observed_max <= concurrency_limit,
            "observed {observed_max} concurrent tasks, limit was {concurrency_limit}"
        );
        assert!(
            observed_max > 1,
            "expected some concurrent execution, but max was {observed_max}"
        );
    }

    #[tokio::test]
    async fn bounded_channel_provides_backpressure() {
        let tasks = make_tasks(20);
        let started = Arc::new(AtomicUsize::new(0));
        let started_clone = Arc::clone(&started);

        let results = run_concurrent_transfers(tasks, 2, move |task| {
            let s = Arc::clone(&started_clone);
            async move {
                s.fetch_add(1, Ordering::SeqCst);
                // Slow worker to create back-pressure.
                tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
                TaskResult {
                    index: task.index,
                    bytes_transferred: 0,
                    transferred: true,
                    error: None,
                }
            }
        })
        .await
        .unwrap();

        // All tasks must still complete.
        assert_eq!(results.len(), 20);
        assert_eq!(started.load(Ordering::SeqCst), 20);
    }

    #[tokio::test]
    async fn empty_task_list() {
        let results = run_concurrent_transfers(vec![], 4, |task| async move {
            TaskResult {
                index: task.index,
                bytes_transferred: 0,
                transferred: false,
                error: None,
            }
        })
        .await
        .unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn pipeline_construction() {
        let p = ConcurrentPipeline::new(4);
        assert_eq!(p.concurrency(), 4);
        assert!(!p.is_sequential());

        let p = ConcurrentPipeline::new(1);
        assert_eq!(p.concurrency(), 1);
        assert!(p.is_sequential());
    }

    #[test]
    fn pipeline_clamps_range() {
        let p = ConcurrentPipeline::new(0);
        assert_eq!(p.concurrency(), 1);

        let p = ConcurrentPipeline::new(100);
        assert_eq!(p.concurrency(), 64);
    }

    #[test]
    fn options_concurrent_default() {
        let opts = crate::options::TransferOptions::default();
        assert_eq!(opts.concurrent(), 1);
    }

    #[test]
    fn options_concurrent_builder() {
        let opts = crate::options::TransferOptions::builder()
            .concurrent(8)
            .build();
        assert_eq!(opts.concurrent(), 8);
    }

    #[test]
    fn options_concurrent_clamped() {
        let opts = crate::options::TransferOptions::builder()
            .concurrent(0)
            .build();
        assert_eq!(opts.concurrent(), 1);

        let opts = crate::options::TransferOptions::builder()
            .concurrent(999)
            .build();
        assert_eq!(opts.concurrent(), 64);
    }
}
