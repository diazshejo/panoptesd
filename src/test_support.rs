use crate::{
    config::Config,
    process::{ProcSample, ProcessState},
};
use std::time::Instant;

pub fn config() -> Config {
    toml::from_str(include_str!("../config/config.example.toml")).unwrap()
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
