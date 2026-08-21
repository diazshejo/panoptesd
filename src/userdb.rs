//! Cache de resolucion uid -> nombre de usuario, leyendo /etc/passwd
//! directamente (evita depender del crate `users`, que enlaza contra NSS
//! y trae mas superficie de la que necesitamos aqui).

use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};

pub struct UserDb {
    map: HashMap<u32, String>,
    loaded_at: Instant,
}

impl UserDb {
    pub fn load() -> Self {
        UserDb {
            map: Self::parse_passwd(),
            loaded_at: Instant::now(),
        }
    }

    fn parse_passwd() -> HashMap<u32, String> {
        let mut map = HashMap::new();
        let content = match fs::read_to_string("/etc/passwd") {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "no se pudo leer /etc/passwd, usernames se mostraran como uid");
                return map;
            }
        };
        for line in content.lines() {
            // formato: nombre:x:uid:gid:gecos:home:shell
            let mut parts = line.splitn(4, ':');
            let name = match parts.next() {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            let _passwd = parts.next();
            let uid_str = match parts.next() {
                Some(u) => u,
                None => continue,
            };
            if let Ok(uid) = uid_str.parse::<u32>() {
                map.insert(uid, name.to_string());
            }
        }
        map
    }

    /// Re-lee /etc/passwd si el cache tiene mas de `ttl` de antiguedad.
    /// Se llama periodicamente desde el loop principal, no en cada tick.
    pub fn refresh_if_stale(&mut self, ttl: Duration) {
        if self.loaded_at.elapsed() >= ttl {
            self.map = Self::parse_passwd();
            self.loaded_at = Instant::now();
        }
    }

    /// Devuelve el nombre de usuario, o el uid como string si no se
    /// encuentra en /etc/passwd (por ejemplo usuarios de LDAP/NSS externo).
    pub fn lookup(&self, uid: u32) -> String {
        self.map
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }
}
