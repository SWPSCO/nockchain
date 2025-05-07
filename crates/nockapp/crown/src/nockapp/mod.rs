// pub(crate) mod actors;
pub mod driver;
pub mod error;
pub(crate) mod metrics;
pub mod test;
pub mod wire;

pub use error::NockAppError;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures::FutureExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc, Mutex, OwnedMutexGuard};
use tokio::time::{interval, Duration, Interval};
use tokio::{fs, select};
use tokio_util::task::TaskTracker;
use tracing::{debug, error, instrument, trace};

use crate::kernel::form::Kernel;
use crate::noun::slab::NounSlab;

use driver::{IOAction, IODriverFn, NockAppHandle, PokeResult};
use metrics::*;
use wire::WireRepr;

type NockAppResult = Result<(), NockAppError>;

pub struct NockApp {
    /// Nock kernel
    pub(crate) kernel: Kernel,
    /// Current join handles for IO drivers (parallel to `drivers`)
    pub(crate) tasks: tokio_util::task::TaskTracker,
    /// Exit signal sender
    exit_send: mpsc::Sender<usize>,
    /// Exit signal receiver
    exit_recv: mpsc::Receiver<usize>,
    /// Exit status
    exit_status: AtomicBool,
    /// Save event num sender
    watch_send: Arc<Mutex<tokio::sync::watch::Sender<u64>>>,
    /// Save event num receiver
    watch_recv: tokio::sync::watch::Receiver<u64>,
    /// IO action channel
    action_channel: mpsc::Receiver<IOAction>,
    /// IO action channel sender
    action_channel_sender: mpsc::Sender<IOAction>,
    /// Effect broadcast channel
    effect_broadcast: broadcast::Sender<NounSlab>,
    /// Save interval
    save_interval: Interval,
    /// Mutex to ensure only one save at a time
    pub(crate) save_mutex: Arc<Mutex<()>>,
    /// Shutdown oneshot sender
    shutdown_send: Option<tokio::sync::oneshot::Sender<NockAppResult>>,
    /// Shutdown oneshot receiver
    shutdown_recv: tokio::sync::oneshot::Receiver<NockAppResult>,
    // cancel_token: tokio_util::sync::CancellationToken,
    pub npc_socket_path: Option<PathBuf>,
    metrics: NockAppMetrics,
}

pub enum NockAppRun {
    Pending,
    Done,
}

impl NockApp {
    /// This constructs a Tokio interval, even though it doesn't look like it, a Tokio runtime is _required_.
    pub async fn new(kernel: Kernel, save_interval_duration: Duration) -> Self {
        // important: we are tracking this separately here because
        // what matters is the last poke *we* received an ack for. Using
        // the Arc in the serf would result in a race condition!

        let (action_channel_sender, action_channel) = mpsc::channel(100);
        let (effect_broadcast, _) = broadcast::channel(100);
        // let tasks = Arc::new(Mutex::new(TaskJoinSet::new()));
        // let tasks = TaskJoinSet::new();
        // let tasks = Arc::new(TaskJoinSet::new());
        let tasks = TaskTracker::new();
        let (exit_send, exit_recv) = mpsc::channel(1);
        let mut save_interval = interval(save_interval_duration);
        save_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip); // important so we don't stack ticks when lagging
        let save_mutex = Arc::new(Mutex::new(()));
        let (watch_send, watch_recv) =
            tokio::sync::watch::channel(kernel.serf.event_number.load(Ordering::SeqCst));
        let watch_send = Arc::new(Mutex::new(watch_send.clone()));
        let exit_status = AtomicBool::new(false);
        let (shutdown_send, shutdown_recv) = tokio::sync::oneshot::channel();
        // let cancel_token = tokio_util::sync::CancellationToken::new();
        let metrics = NockAppMetrics::register(gnort::global_metrics_registry())
            .expect("Failed to register metrics!");
        Self {
            kernel,
            tasks,
            exit_send,
            exit_recv,
            exit_status,
            watch_send,
            watch_recv,
            action_channel,
            action_channel_sender,
            effect_broadcast,
            save_interval,
            save_mutex,
            shutdown_send: Some(shutdown_send),
            shutdown_recv,
            // cancel_token,
            npc_socket_path: None,
            metrics,
        }
    }

    pub fn get_handle(&self) -> NockAppHandle {
        NockAppHandle {
            io_sender: self.action_channel_sender.clone(),
            effect_sender: self.effect_broadcast.clone(),
            effect_receiver: Mutex::new(self.effect_broadcast.subscribe()),
            exit: self.exit_send.clone(),
        }
    }

    /// Assume at-least-once processing and track the state necessary to know whether
    /// all critical IO actions have been performed correctly or not from the jammed state.
    #[tracing::instrument(skip(self, driver))]
    pub async fn add_io_driver(&mut self, driver: IODriverFn) {
        let io_sender = self.action_channel_sender.clone();
        let effect_sender = self.effect_broadcast.clone();
        let effect_receiver = Mutex::new(self.effect_broadcast.subscribe());
        let exit = self.exit_send.clone();
        let fut = driver(NockAppHandle {
            io_sender,
            effect_sender,
            effect_receiver,
            exit,
        });
        // TODO: Stop using the task tracker for user code?
        self.tasks.spawn(fut);
    }

    /// Purely for testing purposes (injecting delays) for now.
    #[instrument(skip(self, f, save_permit))]
    pub(crate) async fn save_f(
        &mut self,
        f: impl std::future::Future<Output = ()> + Send + 'static,
        save_permit: OwnedMutexGuard<()>,
    ) -> Result<tokio::task::JoinHandle<NockAppResult>, NockAppError> {
        let toggle = self.kernel.serf.buffer_toggle.clone();
        let jam_paths = self.kernel.serf.jam_paths.clone();
        let checkpoint = self.kernel.checkpoint().await?;
        let bytes = checkpoint.encode()?;
        let send_lock = self.watch_send.clone();

        let join_handle = self.tasks.spawn(async move {
            f.await;
            let path = if toggle.load(Ordering::SeqCst) {
                &jam_paths.1
            } else {
                &jam_paths.0
            };
            let mut file = fs::File::create(path)
                .await
                .map_err(NockAppError::SaveError)?;

            file.write_all(&bytes)
                .await
                .map_err(NockAppError::SaveError)?;
            file.sync_all().await.map_err(NockAppError::SaveError)?;

            trace!(
                "Write to {:?} successful, checksum: {}, event: {}",
                path.display(),
                checkpoint.checksum,
                checkpoint.event_num
            );

            // Flip toggle after successful write
            toggle.store(!toggle.load(Ordering::SeqCst), Ordering::SeqCst);
            let send = send_lock.lock().await;
            send.send(checkpoint.event_num)?;
            drop(save_permit);
            Ok::<(), NockAppError>(())
        });
        // We don't want to close and re-open the tasktracker from multiple places
        // so we're just returning the join_handle to let the caller decide.
        Ok(join_handle)
    }

    /// Except in tests, save should only be called by the permit handler.
    pub(crate) async fn save(&mut self, save_permit: OwnedMutexGuard<()>) -> NockAppResult {
        let _join_handle = self.save_f(async {}, save_permit).await?;
        Ok(())
    }

    pub async fn save_locked(&mut self) -> NockAppResult {
        let guard = self.save_mutex.clone().lock_owned().await;
        self.save(guard).await.map_err(|e| {
            error!("Failed to save: {:?}", e);
            e
        })?;
        Ok(())
    }

    /// Peek at a noun in the kernel, blocking operation
    #[tracing::instrument(skip(self, path))]
    pub fn peek_sync(&mut self, path: NounSlab) -> Result<NounSlab, NockAppError> {
        trace!("Peeking at noun: {:?}", path);
        let res = self.kernel.peek_sync(path)?;
        trace!("Peeked noun: {:?}", res);
        Ok(res)
    }

    #[tracing::instrument(skip(self, path))]
    pub async fn peek(&mut self, path: NounSlab) -> Result<NounSlab, NockAppError> {
        trace!("Peeking at noun: {:?}", path);
        let res = self.kernel.peek(path).await?;
        trace!("Peeked noun: {:?}", res);
        Ok(res)
    }

    /// Poke at a noun in the kernel, blocking operation
    #[tracing::instrument(skip(self, wire, cause))]
    pub fn poke_sync(
        &mut self,
        wire: WireRepr,
        cause: NounSlab,
    ) -> Result<Vec<NounSlab>, NockAppError> {
        // let wire_noun = wire.copy_to_stack(self.kernel.serf.stack());
        let effects_slab = self.kernel.poke_sync(wire, cause)?;
        Ok(effects_slab.to_vec())
    }

    #[tracing::instrument(skip(self, wire, cause))]
    pub async fn poke(
        &mut self,
        wire: WireRepr,
        cause: NounSlab,
    ) -> Result<Vec<NounSlab>, NockAppError> {
        let effects_slab = self.kernel.poke(wire, cause).await?;
        Ok(effects_slab.to_vec())
    }

    /// Runs until the nockapp is done (returns exit 0 or an error)
    #[instrument(skip(self))]
    pub async fn run_no_join(&mut self) -> NockAppResult {
        debug!("Starting nockapp run");
        // Reset NockApp for next run
        // self.reset();
        // debug!("Reset NockApp for next run");
        loop {
            let work_res = self.work().await;
            match work_res {
                Ok(nockapp_run) => match nockapp_run {
                    crate::nockapp::NockAppRun::Pending => continue,
                    crate::nockapp::NockAppRun::Done => break Ok(()),
                },
                Err(NockAppError::Exit(code)) => {
                    if code == 0 {
                        // zero is success, we're simply done.
                        debug!("nockapp exited successfully with code: {}", code);
                        break Ok(());
                    } else {
                        error!("nockapp exited with error code: {}", code);
                        break Err(NockAppError::Exit(code));
                    }
                }
                Err(e) => {
                    error!("Got error running nockapp: {:?}", e);
                    break Err(e);
                }
            };
        }
    }

    pub async fn join(self) -> NockAppResult {
        debug!("Awaiting serf stop");
        self.kernel.serf.stop().await;
        debug!("Joining serf thread");
        self.kernel
            .serf
            .join()
            .map_err(|e| NockAppError::SerfThreadError(e))?;
        debug!("Serf thread joined");
        Ok(())
    }

    pub async fn run(mut self) -> NockAppResult {
        let res = self.run_no_join().await;
        self.join().await?;
        res
    }

    #[instrument(skip(socket))]
    fn cleanup_socket_(socket: &Option<PathBuf>) {
        // Clean up npc socket file if it exists
        if let Some(socket) = socket {
            if socket.exists() {
                if let Err(e) = std::fs::remove_file(socket) {
                    error!("Failed to remove npc socket file before exit: {}", e);
                }
            }
        }
    }

    #[instrument(skip(self))]
    fn cleanup_socket(&self) {
        // Clean up npc socket file if it exists
        Self::cleanup_socket_(&self.npc_socket_path);
    }

    async fn work(&mut self) -> Result<NockAppRun, NockAppError> {
        // Fires when there is a save interval tick *and* an available permit in the save semaphore
        let save_ready = self
            .save_interval
            .tick()
            .then(|_| self.save_mutex.clone().lock_owned());
        select!(
        _ = self.kernel.serf.finished() => {
                debug!("Serf thread exited");
                Ok(NockAppRun::Done)
            },
            shutdown = &mut self.shutdown_recv => {
                debug!("Shutdown channel received");
                self.metrics.handle_shutdown.increment();
                self.cleanup_socket();
                match shutdown {
                    Ok(Ok(())) => {
                        debug!("Shutdown triggered, exiting");
                        Ok(NockAppRun::Done)
                    },
                    Ok(Err(e)) => {
                        error!("Shutdown triggered with error: {}", e);
                        Err(e)
                    },
                    // Err(_recv_error) => {},
                    Err(_recv_error) => {
                        error!("Shutdown channel closed prematurely");
                        Err(NockAppError::ChannelClosedError)
                    },
                }
            },
            save_guard = save_ready => {
                self.metrics.handle_save_permit_res.increment();
                self.handle_save_permit_res(save_guard).await
            },
            exit = self.exit_recv.recv() => {
                self.metrics.handle_exit.increment();
                debug!("Exit signal received");
                if let Some(code) = exit {
                    self.handle_exit(code).await
                } else {
                    error!("Exit signal channel closed prematurely");
                    Err(NockAppError::ChannelClosedError)
                }
            }
            // FIXME: This shouldn't be hanging the event loop on the kernel poke/peek etc.
            action_res = self.action_channel.recv() => {
                self.metrics.handle_action.increment();
                trace!("Action channel received");
                match action_res {
                    Some(action) => {
                        self.handle_action(action).await;
                        Ok(NockAppRun::Pending)
                    }
                    None => {
                        error!("Action channel closed prematurely");
                        Err(NockAppError::ChannelClosedError)
                    }
                }
            }
        )
    }

    #[instrument(skip_all, level = "trace")]
    async fn handle_save_permit_res(
        &mut self,
        save_guard: OwnedMutexGuard<()>,
    ) -> Result<NockAppRun, NockAppError> {
        //  Check if we should write in the first place
        let curr_event_num = self.kernel.serf.event_number.load(Ordering::SeqCst);
        let saved_event_num = self.watch_recv.borrow();
        if curr_event_num <= *saved_event_num {
            return Ok(NockAppRun::Pending);
        }
        drop(saved_event_num);

        let res = self.save(save_guard).await;

        res.map(|_| NockAppRun::Pending)
    }

    #[instrument(skip_all)]
    async fn handle_action(&mut self, action: IOAction) {
        // Stop processing events if we are exiting
        if self.exit_status.load(Ordering::SeqCst) {
            if let IOAction::Poke { .. } = action {
                self.metrics.poke_during_exit.increment();
                debug!("Poked during exit. Ignoring.")
            } else {
                self.metrics.peek_during_exit.increment();
                debug!("Peeked during exit. Ignoring.")
            }
            return;
        }
        match action {
            IOAction::Poke {
                wire,
                poke,
                ack_channel,
            } => self.handle_poke(wire, poke, ack_channel).await,
            IOAction::Peek {
                path,
                result_channel,
            } => self.handle_peek(path, result_channel).await,
        }
    }

    #[instrument(skip_all)]
    async fn handle_poke(
        &mut self,
        wire: WireRepr,
        cause: NounSlab,
        ack_channel: tokio::sync::oneshot::Sender<PokeResult>,
    ) {
        let poke_result = self.kernel.poke(wire, cause).await;
        match poke_result {
            Ok(effects) => {
                let _ = ack_channel.send(PokeResult::Ack);
                for effect_slab in effects.to_vec() {
                    let _ = self.effect_broadcast.send(effect_slab);
                }
            }
            Err(_) => {
                let _ = ack_channel.send(PokeResult::Nack);
            }
        }
    }

    #[instrument(skip_all)]
    async fn handle_peek(
        &mut self,
        path: NounSlab,
        result_channel: tokio::sync::oneshot::Sender<Option<NounSlab>>,
    ) {
        let peek_res = self.kernel.peek(path).await;

        match peek_res {
            Ok(res_slab) => {
                let _ = result_channel.send(Some(res_slab));
            }
            Err(e) => {
                error!("Peek error: {:?}", e);
                let _ = result_channel.send(None);
            }
        }
    }

    // TODO: We should explicitly kick off a save somehow
    #[instrument(skip_all)]
    async fn handle_exit(&mut self, code: usize) -> Result<NockAppRun, NockAppError> {
        // `cargo nextest run`
        // 2025-01-23T01:11:52.365215Z  INFO crown::nockapp::nockapp: Exit request received, waiting for save checkpoint with event_num 60
        // 2025-01-23T01:11:52.403120Z ERROR crown::nockapp::nockapp: Action channel closed prematurely
        // 2025-01-23T01:11:52.403132Z ERROR crown::nockapp::nockapp: Got error running nockapp: ChannelClosedError
        // test tests::test_compile_test_app ... FAILED
        // self.action_channel.close();
        // TODO: See if exit_status is duplicative of what the cancel token is for.
        self.exit_status.store(true, Ordering::SeqCst);
        let exit_event_num = self.kernel.serf.event_number.load(Ordering::SeqCst);
        debug!(
            "Exit request received, waiting for save checkpoint with event_num {} (code {})",
            exit_event_num, code
        );

        let mut recv = self.watch_recv.clone();
        // let cancel_token = self.cancel_token.clone();
        let shutdown_send = self.shutdown_send.take().unwrap_or_else(|| {
            panic!(
                "Panicked at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });
        // self.tasks.close();
        // self.tasks.wait().await;
        // recv from the watch channel until we reach the exit event_num, wrapped up in a future
        // that will send the shutdown result when we're done.
        let socket_path = self.npc_socket_path.clone();
        // TODO: Break this out as a separate select! handler with no spawn
        self.tasks.spawn(async move {
            recv.wait_for(|&new| {
                assert!(
                    new <= exit_event_num,
                    "new {new:?} exit_event_num {exit_event_num:?}"
                );
                new == exit_event_num
            })
            .await
            .expect("Failed to wait for saves to catch up to exit_event_num");
            Self::cleanup_socket_(&socket_path);
            debug!("Save event_num reached, finishing with code {}", code);
            let shutdown_result = if code == 0 {
                Ok(())
            } else {
                Err(NockAppError::Exit(code))
            };
            // Ensure we send the shutdown result before canceling so that
            // we don't get a race condition where the yielded result is
            // "canceled" instead of the actual result.
            debug!("Sending shutdown result");
            let _ = shutdown_send.send(shutdown_result);
        });
        Ok(NockAppRun::Pending)
    }
}
