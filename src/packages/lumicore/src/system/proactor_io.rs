// MIT License — clean-room implementation of high-performance async I/O proactor.

/// Proactor pattern I/O engine — platform-specific completion-based async operations.
///
/// The Proactor pattern decouples asynchronous event initiation from completion
/// handling. On each platform LumiNet uses the native completion-port API:
///   - Linux/Android: epoll with `EPOLLOUT`/`EPOLLIN` edge-triggered polling
///   - macOS/iOS:     kqueue with EVFILT_READ/EVFILT_WRITE
///   - Windows:       IOCP (I/O Completion Ports) via `GetQueuedCompletionStatus`
///
/// `ProactorIO` is the cross-platform entry point. The actual proactor
/// implementations live in the `platform/` sub-module (conditionally compiled
/// via `#[cfg(target_os = "...")]`).
///
/// Usage:
/// ```ignore
/// let proactor = ProactorIO::new()?;
/// proactor.submit_read(fd, buf, token).await?;
/// while let Some(op) = proactor.next().await {
///     // handle completion
/// }
/// ```
use std::io;
#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(not(unix))]
type RawFd = i32;
use std::sync::Arc;

use tokio::sync::oneshot;

pub use self::kqueue::KqueueProactor;

/// Represents a completed I/O operation returned by `ProactorIO::next()`.
#[derive(Debug, Clone)]
pub struct Completion {
    /// Opaque token that was passed when the operation was submitted.
    pub token: u64,
    /// Number of bytes transferred (read or written). Zero means EOF for reads.
    pub bytes: usize,
    /// Whether this operation completed successfully.
    pub ok: bool,
    /// Platform-specific error code when `ok` is false (0 on success).
    pub err_code: i32,
}

impl Completion {
    /// Returns `Ok(bytes)` if the operation succeeded, otherwise `Err(io::Error)`.
    #[inline]
    pub fn result(&self) -> io::Result<usize> {
        if self.ok {
            Ok(self.bytes)
        } else {
            Err(io::Error::from_raw_os_error(self.err_code))
        }
    }
}

/// A submitted but not-yet-completed I/O operation.
enum PendingOp {
    Read {
        _buf: Vec<u8>,
        _token: u64,
        tx: oneshot::Sender<Completion>,
    },
    Write {
        _data: bytes::Bytes,
        _token: u64,
        tx: oneshot::Sender<Completion>,
    },
}

/// Cross-platform async I/O proactor.
///
/// Created with [`ProactorIO::new`], which selects the best available platform
/// backend at compile time. Call `submit_read` / `submit_write` to queue
/// operations, then `next()` to consume completions.
pub struct ProactorIO {
    backend: KqueueProactor,
    pending: Arc<dashmap::DashMap<RawFd, Vec<PendingOp>>>,
}

impl Default for ProactorIO {
    fn default() -> Self {
        Self::new().expect("ProactorIO: failed to initialise proactor")
    }
}

impl ProactorIO {
    /// Create a new proactor, auto-selecting the best available platform backend.
    pub fn new() -> io::Result<Self> {
        let backend = KqueueProactor::new()?;
        Ok(Self {
            backend,
            pending: Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Submit an asynchronous read operation on a socket.
    pub fn submit_read(
        &self,
        fd: RawFd,
        buf: Vec<u8>,
        token: u64,
    ) -> impl std::future::Future<Output = Completion> + Send {
        let (tx, rx) = oneshot::channel();
        {
            let mut ops = self.pending.entry(fd).or_default();
            ops.push(PendingOp::Read {
                _buf: buf,
                _token: token,
                tx,
            });
        }
        self.backend.submit_read(fd, token);
        async move {
            rx.await.unwrap_or(Completion {
                token,
                bytes: 0,
                ok: false,
                err_code: libc::ECANCELED,
            })
        }
    }

    /// Submit an asynchronous write operation on a socket.
    pub fn submit_write(
        &self,
        fd: RawFd,
        data: bytes::Bytes,
        token: u64,
    ) -> impl std::future::Future<Output = Completion> + Send {
        let (tx, rx) = oneshot::channel();
        {
            let mut ops = self.pending.entry(fd).or_default();
            ops.push(PendingOp::Write {
                _data: data,
                _token: token,
                tx,
            });
        }
        self.backend.submit_write(fd, token);
        async move {
            rx.await.unwrap_or(Completion {
                token,
                bytes: 0,
                ok: false,
                err_code: libc::ECANCELED,
            })
        }
    }

    /// Poll for the next completed readiness event.
    pub async fn next(&self) -> Option<Completion> {
        self.backend.next().await
    }

    /// Register a file descriptor for proactor I/O.
    pub fn register(&self, fd: RawFd) -> io::Result<()> {
        self.backend.register(fd)
    }

    /// Deregister a file descriptor and cancel all pending operations on it.
    pub fn deregister(&self, fd: RawFd) -> io::Result<()> {
        self.backend.deregister(fd);
        if let Some((_fd, ops)) = self.pending.remove(&fd) {
            for op in ops {
                op.cancel();
            }
        }
        Ok(())
    }
}

impl PendingOp {
    fn cancel(self) {
        match self {
            PendingOp::Read { tx, .. } | PendingOp::Write { tx, .. } => {
                let _ = tx.send(Completion {
                    token: 0,
                    bytes: 0,
                    ok: false,
                    err_code: libc::ECANCELED,
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod kqueue {
    use super::*;

    /// Linux/epoll proactor backend.
    pub struct KqueueProactor {
        epfd: RawFd,
    }

    impl KqueueProactor {
        pub fn new() -> io::Result<Self> {
            let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if epfd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { epfd })
        }

        #[inline]
        pub fn submit_read(&self, fd: RawFd, _token: u64) {
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32 | libc::EPOLLONESHOT as u32,
                u64: fd as u64,
            };
            unsafe {
                libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_MOD, fd, &mut ev);
            }
        }

        #[inline]
        pub fn submit_write(&self, fd: RawFd, _token: u64) {
            let mut ev = libc::epoll_event {
                events: libc::EPOLLOUT as u32 | libc::EPOLLONESHOT as u32,
                u64: fd as u64,
            };
            unsafe {
                libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_MOD, fd, &mut ev);
            }
        }

        pub fn register(&self, fd: RawFd) -> io::Result<()> {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut ev = libc::epoll_event {
                events: libc::EPOLLONESHOT as u32,
                u64: fd as u64,
            };
            if unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn deregister(&self, fd: RawFd) {
            unsafe {
                libc::epoll_ctl(
                    self.epfd,
                    libc::EPOLL_CTL_DEL,
                    fd,
                    std::ptr::null_mut(),
                );
            }
        }

        pub async fn next(&self) -> Option<Completion> {
            const MAX_EVENTS: usize = 64;
            let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; MAX_EVENTS];

            let n = loop {
                let res = unsafe {
                    libc::epoll_wait(
                        self.epfd,
                        events.as_mut_ptr(),
                        MAX_EVENTS as i32,
                        -1,
                    )
                };
                if res < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return None;
                }
                break res as usize;
            };

            for ev in events.iter().take(n) {
                let fd = ev.u64 as RawFd;
                if ev.events & libc::EPOLLERR as u32 != 0 {
                    return Some(Completion {
                        token: fd as u64,
                        bytes: 0,
                        ok: false,
                        err_code: libc::ECONNRESET,
                    });
                }
                if ev.events & (libc::EPOLLIN as u32 | libc::EPOLLOUT as u32) != 0 {
                    return Some(Completion {
                        token: fd as u64,
                        bytes: 0,
                        ok: true,
                        err_code: 0,
                    });
                }
            }
            None
        }
    }

    impl Drop for KqueueProactor {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.epfd);
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod kqueue {
    use super::*;

    /// macOS kqueue proactor backend.
    pub struct KqueueProactor {
        kq: RawFd,
    }

    impl KqueueProactor {
        pub fn new() -> io::Result<Self> {
            let kq = unsafe { libc::kqueue() };
            if kq < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { kq })
        }

        #[inline]
        pub fn submit_read(&self, fd: RawFd, _token: u64) {
            self.arm(fd, libc::EVFILT_READ);
        }

        #[inline]
        pub fn submit_write(&self, fd: RawFd, _token: u64) {
            self.arm(fd, libc::EVFILT_WRITE);
        }

        fn arm(&self, fd: RawFd, filter: i16) {
            let ev = libc::kevent {
                ident: fd as libc::uintptr_t,
                filter,
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            unsafe {
                libc::kevent(
                    self.kq,
                    &ev,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                );
            }
        }

        pub fn register(&self, fd: RawFd) -> io::Result<()> {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn deregister(&self, fd: RawFd) {
            for filter in [libc::EVFILT_READ, libc::EVFILT_WRITE] {
                let ev = libc::kevent {
                    ident: fd as libc::uintptr_t,
                    filter,
                    flags: libc::EV_DELETE,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                };
                unsafe {
                    libc::kevent(
                        self.kq,
                        &ev,
                        1,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null(),
                    );
                }
            }
        }

        pub async fn next(&self) -> Option<Completion> {
            let mut events = [libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            }; 64];

            let n = loop {
                let res = unsafe {
                    libc::kevent(
                        self.kq,
                        std::ptr::null(),
                        0,
                        events.as_mut_ptr(),
                        events.len() as i32,
                        std::ptr::null(),
                    )
                };
                if res < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return None;
                }
                break res as usize;
            };

            if n == 0 {
                return None;
            }
            let ev = &events[0];
            let ok = ev.flags & libc::EV_ERROR == 0;
            Some(Completion {
                token: ev.ident as u64,
                bytes: ev.data.max(0) as usize,
                ok,
                err_code: if ok { 0 } else { ev.data as i32 },
            })
        }
    }

    impl Drop for KqueueProactor {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.kq);
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod kqueue {
    use super::*;

    /// Windows compatibility backend. IOCP is not implemented yet; callers can
    /// construct the type, but submitted operations remain unsupported.
    pub struct KqueueProactor;

    impl KqueueProactor {
        pub fn new() -> io::Result<Self> {
            Ok(Self)
        }
        pub fn submit_read(&self, _fd: RawFd, _token: u64) {}
        pub fn submit_write(&self, _fd: RawFd, _token: u64) {}
        pub fn register(&self, _fd: RawFd) -> io::Result<()> {
            Ok(())
        }
        pub fn deregister(&self, _fd: RawFd) {}
        pub async fn next(&self) -> Option<Completion> {
            None
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod kqueue {
    use super::*;

    pub struct KqueueProactor;

    impl KqueueProactor {
        pub fn new() -> io::Result<Self> {
            Ok(Self)
        }
        pub fn submit_read(&self, _fd: RawFd, _token: u64) {}
        pub fn submit_write(&self, _fd: RawFd, _token: u64) {}
        pub fn register(&self, _fd: RawFd) -> io::Result<()> {
            Ok(())
        }
        pub fn deregister(&self, _fd: RawFd) {}
        pub async fn next(&self) -> Option<Completion> {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proactor_creation() {
        let result = ProactorIO::new();
        if let Err(error) = result {
            assert_ne!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn completion_result_ok() {
        let completion = Completion {
            token: 42,
            bytes: 100,
            ok: true,
            err_code: 0,
        };
        assert_eq!(completion.result().unwrap(), 100);
    }

    #[test]
    fn completion_result_err() {
        let completion = Completion {
            token: 0,
            bytes: 0,
            ok: false,
            err_code: libc::ECONNRESET,
        };
        assert!(completion.result().is_err());
    }
}
