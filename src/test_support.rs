use crate::{
    config::Config,
    process::{ProcSample, ProcessState},
};
use std::time::Instant;

pub fn config() -> Config {
    let mut cfg: Config = toml::from_str(include_str!("../config/config.example.toml")).unwrap();
    cfg.rules.root_whitelist.sustained_secs = 0;
    cfg
}

pub fn state(comm: &str, exe: &str, ppid: i32, start: u64, now: Instant) -> ProcessState {
    ProcessState::new(
        &ProcSample {
            comm: comm.into(),
            uid: 0,
            ppid,
            pgrp: ppid,
            starttime: start,
            flags: 0,
            exe: Some(exe.into()),
            utime: 0,
            stime: 0,
            rss_bytes: 4096,
        },
        "root".into(),
        now,
    )
}
