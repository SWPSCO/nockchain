use std::sync::Arc;

use bytes::buf::BufMut;
use nockvm::noun::{D, T};
use nockvm_macros::tas;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::select;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Duration};
use tracing::{debug, error};

use crate::nockapp::driver::{make_driver, IODriverFn, PokeResult, TaskJoinSet};
use crate::nockapp::wire::{Wire, WireRepr};
use crate::nockapp::NockAppError;
use crate::noun::slab::NounSlab;
use crate::Bytes;

/// Timeout constants for npc driver operations
const OVERALL_WRITE_TIMEOUT_SECS: u64 = 300; // 5 minutes
const LENGTH_WRITE_TIMEOUT_SECS: u64 = 5; // 5 seconds
const CONTENT_WRITE_TIMEOUT_SECS: u64 = 60; // 1 minute
const LISTENER_SLEEP_MILLIS: u64 = 100; // 100ms to avoid tight-looping

pub enum NpcWire {
    Poke(u64),
    Pack(u64),
    Nack(u64),
    Bind(u64),
}

impl Wire for NpcWire {
    const VERSION: u64 = 1;
    const SOURCE: &'static str = "npc";

    fn to_wire(&self) -> WireRepr {
        let tags = match self {
            NpcWire::Poke(pid) => vec!["poke".into(), pid.into()],
            NpcWire::Pack(pid) => vec!["pack".into(), pid.into()],
            NpcWire::Nack(pid) => vec!["nack".into(), pid.into()],
            NpcWire::Bind(pid) => vec!["bind".into(), pid.into()],
        };
        WireRepr::new(Self::SOURCE, Self::VERSION, tags)
    }
}

/// NPC Listener IO driver
pub fn npc_listener(listener: UnixListener) -> IODriverFn {
    make_driver(move |mut handle| async move {
        let mut client_join_set = TaskJoinSet::new();
        loop {
            select! {
                stream_res = listener.accept() => {
                    debug!("Accepted new connection");
                    match stream_res {
                        Ok((stream, _)) => {
                            let (my_handle, their_handle) = handle.dup();
                            handle = my_handle;
                            let _ = client_join_set.spawn(npc_client(stream)(their_handle));
                        },
                        Err(e) => {
                            error!("Error accepting connection: {:?}", e);
                        }
                    }
                },
                Some(result) = client_join_set.join_next() => {
                    match result {
                        Ok(Ok(())) => debug!("npc: client task completed successfully"),
                        Ok(Err(e)) => error!("npc: client task error: {:?}", e),
                        Err(e) => error!("npc: client task join error: {:?}", e),
                    }
                },
                // TODO: don't do this, revive robin hood
                _ = sleep(Duration::from_millis(LISTENER_SLEEP_MILLIS)) => {
                    // avoid tight-looping
                }
            }
        }
    })
}

/// NPC Client IO driver
pub fn npc_client(stream: UnixStream) -> IODriverFn {
    make_driver(move |handle| async move {
        let (stream_read, mut stream_write) = split(stream);
        let stream_read_arc = Arc::new(Mutex::new(stream_read));
        let mut read_message_join_set = JoinSet::new();
        read_message_join_set.spawn(read_message(stream_read_arc.clone()));

        'driver: loop {
            select! {
                message = read_message_join_set.join_next() => {
                    match message {
                        Some(Ok(Ok(Some(mut slab)))) => {
                            debug!("npc_client: read message");
                            let Ok(message_cell) = unsafe { slab.root() }.as_cell() else {
                                continue;
                            };

                            let (pid, directive_cell) = match (message_cell.head().as_direct(), message_cell.tail().as_cell()) {
                                (Ok(direct), Ok(cell)) => (direct.data(), cell),
                                _ => continue,
                            };

                            let Ok(directive_tag) = directive_cell.head().as_direct() else {
                                continue;
                            };
                            let directive_tag = directive_tag.data();

                            match directive_tag {
                                tas!(b"poke") => {
                                    debug!("npc_client: poke");
                                    let mut poke_slab = NounSlab::new();
                                    let poke = directive_cell.tail();
                                    poke_slab.copy_into(poke);
                                    let wire = NpcWire::Poke(pid).to_wire();
                                    let result = handle.poke(wire, poke_slab).await?;
                                    let (tag, noun) = match result {
                                        PokeResult::Ack => (tas!(b"pack"), D(0)),
                                        PokeResult::Nack => (tas!(b"nack"), D(0)),
                                    };

                                    let mut response_slab = NounSlab::new();
                                    let response_noun = T(&mut response_slab, &[D(pid), D(tag), noun]);
                                    response_slab.set_root(response_noun);
                                    match write_message(&mut stream_write, response_slab).await {
                                        Ok(false) => break 'driver,
                                        Err(NockAppError::IoError(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                                            error!("npc_client: write timeout, closing connection to allow reconnect");
                                            break 'driver;
                                        },
                                        Err(e) => return Err(e),
                                        Ok(true) => {}, // Success, continue
                                    }
                                },
                                tas!(b"peek") => {
                                    debug!("npc_client: peek");
                                    let path = directive_cell.tail();
                                    slab.set_root(path);
                                    let peek_res = handle.peek(slab).await?;
                                    match peek_res {
                                        Some(mut bind_slab) => {
                                            bind_slab.modify(|root| {
                                                vec![D(pid), D(tas!(b"bind")), root]
                                            });
                                            match write_message(&mut stream_write, bind_slab).await {
                                                Ok(false) => break 'driver,
                                                Err(NockAppError::IoError(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                                                    error!("npc_client: write timeout, closing connection to allow reconnect");
                                                    break 'driver;
                                                },
                                                Err(e) => return Err(e),
                                                Ok(true) => {}, // Success, continue
                                            }
                                        },
                                        None => {
                                            error!("npc: peek failed!");
                                        }
                                    }
                                },
                                tas!(b"pack") | tas!(b"nack") | tas!(b"bind") => {
                                    debug!("npc_client: pack, nack, or bind");
                                    let tag = match directive_tag {
                                        tas!(b"pack") => tas!(b"npc-pack"),
                                        tas!(b"nack") => tas!(b"npc-nack"),
                                        tas!(b"bind") => tas!(b"npc-bind"),
                                        _ => unreachable!(),
                                    };
                                    let wire = match directive_tag {
                                        tas!(b"pack") => NpcWire::Pack(pid),
                                        tas!(b"nack") => NpcWire::Nack(pid),
                                        tas!(b"bind") => NpcWire::Bind(pid),
                                        _ => unreachable!(),
                                    };
                                    let poke = if tag == tas!(b"npc-bind") {
                                        T(&mut slab, &[D(tag), D(pid), directive_cell.tail()])
                                    } else {
                                        T(&mut slab, &[D(tag), D(pid)])
                                    };
                                    slab.set_root(poke);

                                    handle.poke(wire.to_wire(), slab).await?;
                                },
                                _ => {
                                    debug!("npc_client: unexpected message: {:?}", directive_tag);
                                },
                            }
                        },
                        Some(Ok(Ok(None))) => {
                            break 'driver;
                        },
                        Some(Err(e)) => {
                            error!("{e:?}");
                        },
                        Some(Ok(Err(e))) => {
                            error!("{e:?}");
                        },
                        None => {
                            read_message_join_set.spawn(read_message(stream_read_arc.clone()));
                        }
                    }
                },
                effect_res = handle.next_effect() => {
                    let mut slab = effect_res?; // Closed error should error driver
                    let Ok(effect_cell) = unsafe { slab.root() }.as_cell() else {
                        continue;
                    };
                    // TODO: distinguish connections
                    if unsafe { effect_cell.head().raw_equals(&D(tas!(b"npc"))) } {
                        slab.set_root(effect_cell.tail());
                        match write_message(&mut stream_write, slab).await {
                            Ok(false) => break 'driver,
                            Err(NockAppError::IoError(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                                error!("npc_client: write timeout, closing connection to allow reconnect");
                                break 'driver;
                            },
                            Err(e) => return Err(e),
                            Ok(true) => {}, // Success, continue
                        }
                    }
                }
            }
        }
        Ok(())
    })
}

async fn read_message(
    stream_arc: Arc<Mutex<ReadHalf<UnixStream>>>,
) -> Result<Option<NounSlab>, NockAppError> {
    let mut stream = stream_arc.lock_owned().await;
    let mut size_bytes = [0u8; 8];
    debug!("Attempting to read message size...");
    match stream.read_exact(&mut size_bytes).await {
        Ok(0) => {
            debug!("Connection closed");
            return Ok(None);
        }
        Ok(size) => {
            debug!("Read size: {:?}", size);
        }
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            debug!("Connection closed unexpectedly");
            return Ok(None);
        }
        Err(e) => {
            debug!("Error reading size: {:?}", e);
            return Err(NockAppError::IoError(e));
        }
    }
    let size = usize::from_le_bytes(size_bytes);
    debug!("Message size: {} bytes", size);
    let mut buf = Vec::with_capacity(size).limit(size);
    while buf.remaining_mut() > 0 {
        debug!(
            "Reading message content, {} bytes remaining",
            buf.remaining_mut()
        );
        match stream.read_buf(&mut buf).await {
            Ok(0) => {
                debug!("Connection closed while reading message content");
                return Ok(None);
            }
            Ok(_) => {}
            Err(e) => return Err(NockAppError::IoError(e)),
        }
    }
    debug!("Successfully read entire message");
    let mut slab = NounSlab::new();
    let noun = slab.cue_into(Bytes::from(buf.into_inner()))?;
    slab.set_root(noun);
    Ok(Some(slab))
}

async fn write_message(
    stream: &mut WriteHalf<UnixStream>,
    msg_slab: NounSlab,
) -> Result<bool, NockAppError> {
    let msg_bytes = msg_slab.jam();
    let msg_len = msg_bytes.len();
    debug!("Attempting to write message of {} bytes", msg_len);

    // timeout wrapper for entire write operation
    let write_timeout = Duration::from_secs(OVERALL_WRITE_TIMEOUT_SECS);

    match timeout(write_timeout, async {
        let mut msg_len_bytes = &msg_len.to_le_bytes()[..];
        let mut msg_buf = &msg_bytes[..];

        // Write length header
        while !msg_len_bytes.is_empty() {
            debug!(
                "Writing message length, {} bytes remaining",
                msg_len_bytes.len()
            );

            match timeout(
                Duration::from_secs(LENGTH_WRITE_TIMEOUT_SECS),
                stream.write_buf(&mut msg_len_bytes),
            )
            .await
            {
                Ok(Ok(bytes)) => {
                    if bytes == 0 {
                        debug!("Wrote 0 bytes for message length, connection likely closed");
                        return Ok(false);
                    }
                    debug!("Wrote {} bytes of length header", bytes);
                }
                Ok(Err(e)) => return Err(NockAppError::IoError(e)),
                Err(_timeout) => {
                    error!(
                        "Timeout writing message length after {}s",
                        LENGTH_WRITE_TIMEOUT_SECS
                    );
                    return Err(NockAppError::IoError(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Timeout writing message length",
                    )));
                }
            }
        }

        // Write message content
        while !msg_buf.is_empty() {
            debug!("Writing message content, {} bytes remaining", msg_buf.len());

            match timeout(
                Duration::from_secs(CONTENT_WRITE_TIMEOUT_SECS),
                stream.write_buf(&mut msg_buf),
            )
            .await
            {
                Ok(Ok(bytes)) => {
                    if bytes == 0 {
                        debug!("Wrote 0 bytes for message content, connection likely closed");
                        return Ok(false);
                    }
                    debug!("Wrote {} bytes of message content", bytes);
                }
                Ok(Err(e)) => return Err(NockAppError::IoError(e)),
                Err(_timeout) => {
                    error!(
                        "Timeout writing message content after {}s, {} bytes remaining",
                        CONTENT_WRITE_TIMEOUT_SECS,
                        msg_buf.len()
                    );
                    return Err(NockAppError::IoError(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "Timeout writing message content - {} bytes stuck",
                            msg_buf.len()
                        ),
                    )));
                }
            }
        }

        debug!("Successfully wrote entire message");
        Ok(true)
    })
    .await
    {
        Ok(result) => result,
        Err(_timeout) => {
            error!(
                "Overall write operation timed out after {} seconds",
                OVERALL_WRITE_TIMEOUT_SECS
            );
            Err(NockAppError::IoError(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Write operation timed out - socket may be stuck",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::time::Duration;

    use tempfile::tempdir;
    use tokio::net::UnixStream;
    use tokio::sync::{broadcast, mpsc};
    use tokio::time::timeout;
    use tracing_test::traced_test;

    use super::*;
    use crate::metrics::NockAppMetrics;
    use crate::nockapp::driver::{IOAction, NockAppHandle};
    use crate::NockAppExit;

    async fn setup_socket_pair() -> (UnixStream, StdUnixStream) {
        let dir = tempdir().unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });
        let socket_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&socket_path).unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });

        let client = StdUnixStream::connect(&socket_path).unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });
        let (server, _) = listener.accept().await.unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });

        (server, client)
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_write_message_format() {
        let (server, mut client) = setup_socket_pair().await;
        let (_, mut writer) = split(server);

        let mut test_slab = NounSlab::new();
        let test_noun = T(&mut test_slab, &[D(123), D(456)]);
        test_slab.set_root(test_noun);

        write_message(&mut writer, test_slab)
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            });

        let mut size_buf = [0u8; 8];
        client.read_exact(&mut size_buf).unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });
        let size = usize::from_le_bytes(size_buf);

        let mut msg_buf = vec![0u8; size];
        client.read_exact(&mut msg_buf).unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });

        let mut received_slab: NounSlab = NounSlab::new();
        let received_noun = received_slab
            .cue_into(Bytes::from(msg_buf))
            .unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            });
        received_slab.set_root(received_noun);

        let root = unsafe { received_slab.root() };
        let cell = root.as_cell().unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });

        assert_eq!(
            cell.head()
                .as_direct()
                .unwrap_or_else(|err| {
                    panic!(
                        "Panicked with {err:?} at {}:{} (git sha: {:?})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA")
                    )
                })
                .data(),
            123
        );
        assert_eq!(
            cell.tail()
                .as_direct()
                .unwrap_or_else(|err| {
                    panic!(
                        "Panicked with {err:?} at {}:{} (git sha: {:?})",
                        file!(),
                        line!(),
                        option_env!("GIT_SHA")
                    )
                })
                .data(),
            456
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_write_message_empty() {
        let (server, mut client) = setup_socket_pair().await;
        let (_, mut writer) = split(server);

        let mut test_slab = NounSlab::new();
        let test_noun = T(&mut test_slab, &[D(0), D(0)]);
        test_slab.set_root(test_noun);

        assert!(write_message(&mut writer, test_slab)
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            }));

        let mut size_buf = [0u8; 8];
        client.read_exact(&mut size_buf).unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });
        assert!(usize::from_le_bytes(size_buf) > 0);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_read_message_eof() {
        let (server, client) = setup_socket_pair().await;
        drop(client);

        let stream_arc = Arc::new(Mutex::new(split(server).0));
        let result = read_message(stream_arc).await;
        assert!(result
            .unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            })
            .is_none());
    }

    #[tokio::test]
    #[traced_test]
    #[cfg_attr(miri, ignore)]
    async fn test_npc_driver() {
        // Setup
        let dir = tempdir().unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });
        let socket_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&socket_path).unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });

        // Create channels for driver communication
        let (tx_io, mut rx_io) = mpsc::channel(32);
        let (tx_effect_chan, rx_effect) = broadcast::channel(32);
        let tx_effect = Arc::new(tx_effect_chan);
        let metrics = Arc::new(
            NockAppMetrics::register(gnort::global_metrics_registry())
                .expect("Failed to register metrics!"),
        );

        let (tx_exit, _) = NockAppExit::new();

        let handle = NockAppHandle {
            io_sender: tx_io,
            effect_sender: tx_effect.clone(),
            effect_receiver: Mutex::new(rx_effect),
            metrics: metrics,
            exit: tx_exit,
        };

        // Spawn the listener driver
        let _driver_task = tokio::spawn(npc_listener(listener)(handle));

        // Connect client
        let mut client = StdUnixStream::connect(&socket_path).unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });

        // Create test noun slab
        let mut test_slab: NounSlab = NounSlab::new();
        let msg_noun = T(&mut test_slab, &[D(tas!(b"poke")), D(123), D(456)]);
        let test_noun = T(&mut test_slab, &[D(1), msg_noun]);
        test_slab.set_root(test_noun);

        // Jam the noun to bytes
        let msg_bytes = test_slab.jam();
        let msg_len = msg_bytes.len();

        // Write length prefix and jammed noun
        client
            .write_all(&(msg_len as u64).to_le_bytes())
            .unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            });
        client.write_all(&msg_bytes).unwrap_or_else(|err| {
            panic!(
                "Panicked with {err:?} at {}:{} (git sha: {:?})",
                file!(),
                line!(),
                option_env!("GIT_SHA")
            )
        });

        debug!("client: wrote {} bytes", msg_len);

        // Verify driver received poke
        if let Some(IOAction::Poke {
            wire: _wire,
            poke: noun_slab,
            ack_channel: _,
            timeout: _,
        }) = timeout(Duration::from_secs(1), rx_io.recv())
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            })
        {
            debug!("test_npc_driver: poke data: {:?}", unsafe {
                noun_slab.root()
            });

            // Verify noun content
            let noun = unsafe { noun_slab.root() };
            let noun_cell = noun.as_cell().unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            });
            assert_eq!(
                noun_cell
                    .head()
                    .as_direct()
                    .unwrap_or_else(|err| {
                        panic!(
                            "Panicked with {err:?} at {}:{} (git sha: {:?})",
                            file!(),
                            line!(),
                            option_env!("GIT_SHA")
                        )
                    })
                    .data(),
                123
            );
            assert_eq!(
                noun_cell
                    .tail()
                    .as_direct()
                    .unwrap_or_else(|err| {
                        panic!(
                            "Panicked with {err:?} at {}:{} (git sha: {:?})",
                            file!(),
                            line!(),
                            option_env!("GIT_SHA")
                        )
                    })
                    .data(),
                456
            );

        // TODO: make this work
        /* ack_channel.send(PokeResult::Ack).unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA")));

        // Send effect through broadcast channel
        let mut ack_slab = NounSlab::new();
        let ack = T(&mut ack_slab.clone(), &[
            D(tas!(b"npc")),
            T(&mut ack_slab.clone(), &[D(123), D(tas!(b"pack")), D(0)])
        ]);
        ack_slab.set_root(ack);
        tx_effect.send(ack_slab).unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA")));

        // Verify client receives ack
        let mut size_buf = [0u8; 8];
        client.read_exact(&mut size_buf).unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA")));
        let size = usize::from_le_bytes(size_buf);

        let mut msg_buf = vec![0u8; size];
        client.read_exact(&mut msg_buf).unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA")));

        let mut received_slab = NounSlab::new();
        let received_noun = received_slab.cue_into(Bytes::from(msg_buf)).unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA")));
        received_slab.set_root(received_noun);

        let root = unsafe { received_slab.root() };
        let cell = root.as_cell().unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA")));
        assert_eq!(cell.head().as_direct().unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA"))).data(), 123);
        let rest = cell.tail().as_cell().unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA")));
        assert_eq!(rest.head().as_direct().unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA"))).data(), tas!(b"pack"));
        assert_eq!(rest.tail().as_direct().unwrap_or_else(|| panic!("Panicked at {}:{} (git sha: {:?})", file!(), line!(), option_env!("GIT_SHA"))).data(), 0); */
        } else {
            panic!("Did not receive poke message");
        }

        // Cleanup
        drop(client);
    }
}
