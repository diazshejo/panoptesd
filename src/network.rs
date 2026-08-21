//! Correlacion opcional de conexiones de red con procesos, leyendo
//! /proc/net/tcp{,6} y /proc/<pid>/fd/* a mano (sin libs de sockets).
//!
//! Es la regla mas costosa (recorre los fds de todos los procesos), por
//! eso el loop principal solo la ejecuta cada `check_every_n_cycles` y
//! unicamente si `network.enabled = true` en la configuracion.

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;

pub struct Connection {
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub inode: u64,
}

/// Parsea /proc/net/tcp (IPv4). Solo se consideran conexiones establecidas
/// (st == 01) con puerto remoto != 0, para no marcar sockets en escucha.
pub fn parse_tcp_connections(path: &str) -> Vec<Connection> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let state = fields[3];
        if state != "01" {
            // 01 = ESTABLISHED; se ignoran LISTEN/TIME_WAIT/etc.
            continue;
        }
        if let Some((ip, port)) = parse_hex_ipv4_port(fields[2]) {
            if port == 0 {
                continue;
            }
            if let Ok(inode) = fields[9].parse::<u64>() {
                out.push(Connection {
                    remote_ip: ip,
                    remote_port: port,
                    inode,
                });
            }
        }
    }
    out
}

fn parse_hex_ipv4_port(s: &str) -> Option<(Ipv4Addr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 8 {
        return None;
    }
    let addr_le = u32::from_str_radix(addr_hex, 16).ok()?;
    // La direccion se almacena en orden de bytes de la maquina (little
    // endian en x86/arm64), no en network byte order.
    let bytes = addr_le.to_le_bytes();
    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((ip, port))
}

/// Construye un mapa inode de socket -> pid recorriendo /proc/<pid>/fd de
/// los pids indicados. Costoso: un readdir + readlink por fd abierto.
pub fn build_inode_to_pid(pids: &[i32]) -> HashMap<u64, i32> {
    let mut map = HashMap::new();
    for &pid in pids {
        let fd_dir = format!("/proc/{}/fd", pid);
        let entries = match fs::read_dir(&fd_dir) {
            Ok(e) => e,
            Err(_) => continue, // proceso sin permisos o ya no existe
        };
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                if let Some(name) = target.to_str() {
                    if let Some(inode) = parse_socket_inode(name) {
                        map.insert(inode, pid);
                    }
                }
            }
        }
    }
    map
}

fn parse_socket_inode(link_target: &str) -> Option<u64> {
    // formato: "socket:[12345]"
    let inner = link_target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

/// Matcher CIDR IPv4 minimo (sin dependencias externas). Formato esperado
/// "a.b.c.d/prefix"; entradas invalidas se ignoran silenciosamente (se
/// loguea al cargar config, no en el loop caliente).
pub fn ipv4_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let (base, prefix) = match cidr.split_once('/') {
        Some((b, p)) => (b, p),
        None => return false,
    };
    let base_ip: Ipv4Addr = match base.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix_len: u32 = match prefix.parse() {
        Ok(p) if p <= 32 => p,
        _ => return false,
    };
    let mask = if prefix_len == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix_len)
    };
    let ip_u32 = u32::from_be_bytes(ip.octets());
    let base_u32 = u32::from_be_bytes(base_ip.octets());
    (ip_u32 & mask) == (base_u32 & mask)
}

/// True si la conexion esta dentro de lo esperado segun la configuracion.
pub fn is_allowed(conn: &Connection, allowed_ports: &[u16], allowed_cidrs: &[String]) -> bool {
    if allowed_ports.contains(&conn.remote_port) {
        return true;
    }
    allowed_cidrs
        .iter()
        .any(|cidr| ipv4_in_cidr(conn.remote_ip, cidr))
}
