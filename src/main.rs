#[macro_use]
extern crate clap;

use daemonize::Daemonize;
use fanotify::high_level::*;
use nix::poll::{poll, PollFd, PollFlags};
use std::fs::OpenOptions;
use std::process::Command;

fn main() {
    let app = clap_app!(deis =>
        (about:         crate_description!())
        (author:        crate_authors!())
        (version:       crate_version!())
        (@arg daemon: -d --daemon "daemonize")
        (@arg log: -l --log +takes_value "log file path")
        (@arg pid: -p --pid +takes_value "pid file path")
        (@arg mountpoint: "mountpoint")
        (@arg scanner: "scanner")
    )
    .get_matches();

    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "INFO")
    }

    if app.is_present("daemon") {
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(app.value_of("log").unwrap_or("./deis.log"))
            .unwrap();

        let daemonize = Daemonize::new()
            .pid_file(app.value_of("pid").unwrap_or("./deis.pid"))
            .chown_pid_file(true)
            .working_directory("/")
            .user("deis")
            .group("deis")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .exit_action(|| println!("Bye"))
            .privileged_action(|| println!("Bye"));

        match daemonize.start() {
            Ok(_) => {
                let pid =
                    std::fs::read_to_string(app.value_of("pid").unwrap_or("./deis.pid")).unwrap();
                println!("Success, daemon pid is {}", pid);
            }
            Err(e) => eprintln!("Error, {}", e),
        }
    }

    let fd = Fanotify::new_with_nonblocking(FanotifyMode::CONTENT);
    if let Err(e) = fd.add_mountpoint(
        FAN_OPEN_EXEC_PERM,
        app.value_of("mountpoint").unwrap(),
    ) {
        eprintln!("Error on add_mountpoint: {}", e);
        std::process::exit(1);
    }

    let mut fds = [PollFd::new(fd.as_raw_fd(), PollFlags::POLLIN)];
    loop {
        let poll_num = poll(&mut fds, -1).unwrap();
        if poll_num > 0 {
            assert!(fds[0].revents().unwrap().contains(PollFlags::POLLIN));
            for event in fd.read_event() {
                println!("{:#?}", event);
                if event.events.contains(&FanEvent::OpenExecPerm) {
                    let mut response = FanotifyResponse::Allow;
                    if let Some(scanner) = app.value_of("scanner") {
                        if Command::new(scanner)
                            .arg(event.path)
                            .status()
                            .unwrap()
                            .code()
                            .unwrap()
                            != 0
                        {
                            response = FanotifyResponse::Deny;
                        }
                    }
                    fd.send_response(event.fd, response);
                }
            }
        } else {
            eprintln!("poll_num <= 0!");
            break;
        }
    }
}
