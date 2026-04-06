use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, Permissions},
    io::{self, BufRead, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use daemonize::Daemonize;
use nix::{
    sys::signal,
    unistd::{Pid as NixPid, Uid},
};
use sysinfo::{
    Pid as SysPid, ProcessRefreshKind, ProcessesToUpdate, System, MINIMUM_CPU_UPDATE_INTERVAL,
};

use crate::{BootArgs, server};

const BIN_NAME: &str = env!("CARGO_PKG_NAME");
const DEFAULT_PID_PATH: &str = concat!("/var/run/", env!("CARGO_PKG_NAME"), ".pid");
const DEFAULT_STDOUT_PATH: &str = concat!("/var/run/", env!("CARGO_PKG_NAME"), ".out");
const DEFAULT_STDERR_PATH: &str = concat!("/var/run/", env!("CARGO_PKG_NAME"), ".err");

pub struct Daemon {
    pid_file: PathBuf,
    stdout_file: PathBuf,
    stderr_file: PathBuf,
}

impl Default for Daemon {
    fn default() -> Self {
        Daemon {
            pid_file: PathBuf::from(DEFAULT_PID_PATH),
            stdout_file: PathBuf::from(DEFAULT_STDOUT_PATH),
            stderr_file: PathBuf::from(DEFAULT_STDERR_PATH),
        }
    }
}

impl Daemon {
    /// Start the daemon
    pub fn start(&self, config: BootArgs) -> crate::Result<()> {
        if let Some(pid) = self.pid()? {
            println!("{BIN_NAME} is already running with pid: {pid}");
            return Ok(());
        }

        Daemon::root();

        let pid_file = File::create(&self.pid_file)?;
        pid_file.set_permissions(Permissions::from_mode(0o755))?;

        let stdout = File::create(&self.stdout_file)?;
        stdout.set_permissions(Permissions::from_mode(0o755))?;

        let stderr = File::create(&self.stderr_file)?;
        stderr.set_permissions(Permissions::from_mode(0o755))?;

        let mut daemonize = Daemonize::new()
            .pid_file(&self.pid_file)
            .chown_pid_file(true)
            .umask(0o777)
            .stdout(stdout)
            .stderr(stderr)
            .privileged_action(|| "Executed before drop privileges");

        if let Ok(user) = std::env::var("SUDO_USER") {
            if let Ok(Some(real_user)) = nix::unistd::User::from_name(&user) {
                daemonize = daemonize
                    .user(real_user.name.as_str())
                    .group(real_user.gid.as_raw());
            }
        }

        if let Some(err) = daemonize.start().err() {
            eprintln!("Error: {err}");
            std::process::exit(-1)
        }

        server::run(config)
    }

    /// Stop the daemon
    pub fn stop(&self) -> crate::Result<()> {
        Daemon::root();

        if let Some(pid) = self.pid()? {
            for _ in 0..360 {
                if signal::kill(NixPid::from_raw(pid as _), signal::SIGINT).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1))
            }
        }

        if let Some(err) = fs::remove_file(&self.pid_file).err() {
            if !matches!(err.kind(), io::ErrorKind::NotFound) {
                println!("failed to remove pid file: {err}");
            }
        }

        Ok(())
    }

    /// Restart the daemon
    pub fn restart(&self, config: BootArgs) -> crate::Result<()> {
        self.stop()?;

        const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

        for i in 0..30 {
            print!("\r{}", SPINNER[i % 4]);
            io::stdout().flush()?;
            std::thread::sleep(Duration::from_millis(100));
        }

        print!("\r \r");
        io::stdout().flush()?;

        self.start(config)
    }

    /// Show the status of the daemon
    pub fn status(&self) -> crate::Result<()> {
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        // CPU usage needs two samples; first refresh is the baseline.
        std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .without_tasks(),
        );

        let pidfile_pid = self.pidfile_raw().and_then(|pid| {
            sys.process(SysPid::from_u32(pid))
                .filter(|p| is_listed_vproxy_process(p))
                .map(|_| pid)
        });

        let mut rows: Vec<_> = sys
            .processes()
            .iter()
            .filter(|(_, p)| is_listed_vproxy_process(p))
            .map(|(pid, p)| (*pid, p))
            .collect();

        rows.sort_by_key(|(pid, _)| pid.as_u32());

        if rows.is_empty() {
            println!("{BIN_NAME} is not running");
            return Ok(());
        }

        println!(
            "{:<8} {:<10} {:<8} {:<10} {:<8}",
            "PID", "MANAGER", "CPU(%)", "MEM(MB)", "RUN(s)"
        );
        for (raw_pid, process) in rows {
            let manager = manager_label(&sys, process, pidfile_pid);
            println!(
                "{:<8} {:<10} {:<8.1} {:<10.1} {:<8}",
                raw_pid,
                manager,
                process.cpu_usage(),
                (process.memory() as f64) / 1024.0 / 1024.0,
                process.run_time(),
            );
        }
        Ok(())
    }

    /// Show the log of the daemon
    pub fn log(&self) -> crate::Result<()> {
        fn read_and_print_file(file_path: &Path, placeholder: &str) -> crate::Result<()> {
            if !file_path.exists() {
                return Ok(());
            }

            let metadata = fs::metadata(file_path)?;
            if metadata.len() == 0 {
                return Ok(());
            }

            let file = File::open(file_path)?;
            let reader = io::BufReader::new(file);
            let mut start = true;

            for line in reader.lines() {
                if let Ok(content) = line {
                    if start {
                        start = false;
                        println!("{placeholder}");
                    }
                    println!("{content}");
                } else if let Err(err) = line {
                    eprintln!("Error reading line: {err}");
                }
            }

            Ok(())
        }

        read_and_print_file(&self.stdout_file, "STDOUT>")?;
        read_and_print_file(&self.stderr_file, "STDERR>")?;

        Ok(())
    }

    fn pidfile_raw(&self) -> Option<u32> {
        fs::read_to_string(&self.pid_file)
            .ok()
            .and_then(|data| data.trim().parse().ok())
    }

    fn pid(&self) -> crate::Result<Option<u32>> {
        let Some(pid) = self.pidfile_raw() else {
            return Ok(None);
        };

        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let sys_pid = SysPid::from_u32(pid);
        if let Some(process) = sys.process(sys_pid) {
            if is_listed_vproxy_process(process) {
                return Ok(Some(pid));
            }
            println!(
                "PID {pid} exists but belongs to different process: {:?}",
                process.name()
            );
        }

        let _ = fs::remove_file(&self.pid_file);

        Ok(None)
    }

    fn root() {
        if !Uid::effective().is_root() {
            println!("You must run this executable with root permissions");
            std::process::exit(-1)
        }
    }
}

#[inline]
fn vproxy_exe_name() -> &'static OsStr {
    OsStr::new(BIN_NAME)
}

fn is_vproxy_process(p: &sysinfo::Process) -> bool {
    if p.name() == vproxy_exe_name() {
        return true;
    }
    p.exe()
        .and_then(|path| path.file_name())
        .is_some_and(|n| n == vproxy_exe_name())
}

/// Linux lists each task under `/proc/.../task/` as its own PID; skip those so `ps` shows one row
/// per real process (thread-group leader only).
#[inline]
fn is_listed_vproxy_process(p: &sysinfo::Process) -> bool {
    is_vproxy_process(p) && p.thread_kind().is_none()
}

fn bytes_contain_pm2(b: &[u8]) -> bool {
    b.windows(3).any(|w| w.eq_ignore_ascii_case(b"pm2"))
}

fn cmdline_has_pm2_marker(cmd: &[OsString]) -> bool {
    cmd.iter()
        .any(|arg| bytes_contain_pm2(arg.as_os_str().as_encoded_bytes()))
}

fn exe_has_pm2_marker(p: &sysinfo::Process) -> bool {
    p.exe()
        .is_some_and(|path| bytes_contain_pm2(path.as_os_str().as_encoded_bytes()))
}

fn environ_has_pm2_marker(env: &[OsString]) -> bool {
    env.iter().any(|e| {
        e.to_string_lossy()
            .as_bytes()
            .get(..4)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"PM2_"))
    })
}

fn process_suggests_pm2(p: &sysinfo::Process) -> bool {
    cmdline_has_pm2_marker(p.cmd())
        || exe_has_pm2_marker(p)
        || environ_has_pm2_marker(p.environ())
}

fn managed_by_pm2(sys: &System, proc: &sysinfo::Process) -> bool {
    if process_suggests_pm2(proc) {
        return true;
    }
    let mut next = proc.parent();
    for _ in 0..16 {
        let Some(ppid) = next else {
            break;
        };
        let Some(parent) = sys.process(ppid) else {
            break;
        };
        if process_suggests_pm2(parent) {
            return true;
        }
        next = parent.parent();
    }
    false
}

fn manager_label(sys: &System, proc: &sysinfo::Process, pidfile_pid: Option<u32>) -> &'static str {
    if pidfile_pid.is_some_and(|p| p == proc.pid().as_u32()) {
        return "daemon";
    }
    if managed_by_pm2(sys, proc) {
        return "pm2";
    }
    "direct"
}
