//! Correlacion opcional de conexiones de red con procesos, leyendo
//! /proc/net/{tcp,udp}{,6} y /proc/<pid>/fd/* a mano (sin libs de sockets).
//! Dos reglas independientes usan estas primitivas (ver `main.rs`):
//! puertos LISTEN nuevos (tcp/tcp6/udp/udp6) y conexiones salientes
//! establecidas fuera de los CIDRs esperados (solo IPv4 por ahora, igual
//! que la whitelist de CIDRs de la config).
//!
//! Es la correlacion mas costosa (recorre los fds de todos los procesos),
//! por eso el loop principal solo la ejecuta cada `check_every_n_cycles` y
//! unicamente si `network.enabled = true` en la configuracion.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Connection {
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub inode: u64,
}

/// Rango de puertos efimeros del kernel (`ip_local_port_range`), inclusivo.
/// Es el rango del que el kernel toma el puerto LOCAL de una conexion
/// iniciada desde esta maquina; sirve para distinguir el sentido de un
/// socket ESTABLISHED, que /proc/net/tcp no indica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralRange {
    pub low: u16,
    pub high: u16,
}

impl EphemeralRange {
    /// Default de Linux (net.ipv4.ip_local_port_range = 32768 60999).
    pub const LINUX_DEFAULT: EphemeralRange = EphemeralRange {
        low: 32768,
        high: 60999,
    };

    pub fn contains(&self, port: u16) -> bool {
        port >= self.low && port <= self.high
    }
}

/// Lee el rango efimero real de /proc/sys/net/ipv4/ip_local_port_range.
/// Si no se puede leer o parsear (contenedor sin /proc/sys, formato raro)
/// se cae al default de Linux en vez de fallar.
pub fn local_port_range() -> EphemeralRange {
    fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|c| parse_local_port_range(&c))
        .unwrap_or(EphemeralRange::LINUX_DEFAULT)
}

/// Formato del sysctl: "32768\t60999\n" (dos enteros separados por
/// whitespace, low <= high).
fn parse_local_port_range(content: &str) -> Option<EphemeralRange> {
    let mut it = content.split_whitespace();
    let low: u16 = it.next()?.parse().ok()?;
    let high: u16 = it.next()?.parse().ok()?;
    if low > high {
        return None;
    }
    Some(EphemeralRange { low, high })
}

/// True si una conexion ESTABLISHED es ENTRANTE (alguien se conecto a un
/// servicio de esta maquina) y por lo tanto NO debe evaluarse por
/// `conexion_saliente_no_esperada`: si el puerto no deberia estar
/// escuchando, eso ya lo cubre `nuevo_puerto_listen`.
///
/// El puerto LOCAL decide el sentido: es entrante si es un puerto de
/// servicio, o sea si esta en `allowed_listen_ports`, es privilegiado
/// (< 1024), tiene un socket TCP en LISTEN en este mismo ciclo
/// (`listening`, cubre servicios en puertos altos no listados: 8080,
/// 3000...) o cae fuera del rango efimero del kernel (un puerto que el
/// kernel nunca asignaria a una conexion iniciada localmente). Todo lo
/// demas se considera saliente. Deliberadamente NO se mira el puerto
/// remoto: una conexion efimero->efimero (ej un C2 escuchando en 44444)
/// tiene que seguir llegando a la whitelist de CIDRs.
pub fn is_inbound(
    conn: &Connection,
    allowed_listen_ports: &[u16],
    listening: &HashSet<u16>,
    ephemeral: EphemeralRange,
) -> bool {
    let port = conn.local_port;
    allowed_listen_ports.contains(&port)
        || port < 1024
        || listening.contains(&port)
        || !ephemeral.contains(port)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

pub struct ListenSocket {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub protocol: Protocol,
    pub inode: u64,
}

/// Parsea /proc/net/tcp (IPv4). Solo se consideran conexiones establecidas
/// (st == 01) con puerto remoto != 0, para no marcar sockets en escucha.
/// Un socket ESTABLISHED se ve igual sea entrante o saliente: el sentido
/// se decide despues con `is_inbound` a partir del puerto local.
pub fn parse_tcp_connections(path: &str) -> Vec<Connection> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_tcp_connections_from(&content)
}

fn parse_tcp_connections_from(content: &str) -> Vec<Connection> {
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
        let local_port = match parse_hex_ipv4_port(fields[1]) {
            Some((_, port)) => port,
            None => continue,
        };
        if let Some((ip, port)) = parse_hex_ipv4_port(fields[2]) {
            if port == 0 {
                continue;
            }
            if let Ok(inode) = fields[9].parse::<u64>() {
                out.push(Connection {
                    local_port,
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

/// Igual que `parse_hex_ipv4_port` pero para /proc/net/{tcp,udp}6: la
/// direccion son 32 hex chars = 4 palabras de 32 bits (s6_addr32[0..4]),
/// cada una con el mismo problema de orden de bytes que el caso v4 (hay
/// que revertir cada palabra de 4 bytes por separado, no el bloque
/// completo).
fn parse_hex_ipv6_port(s: &str) -> Option<(Ipv6Addr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&addr_hex[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((Ipv6Addr::from(bytes), port))
}

/// Parsea sockets en estado de "escucha" de un archivo /proc/net/{tcp,udp}{,6}.
/// Para TCP eso es el estado LISTEN (0A hex); UDP no tiene un estado de
/// escucha real (es sin conexion), asi que se usa la misma convencion que
/// `ss -l`: estado 07 (UNCONN) = socket bindeado a un puerto local
/// esperando datagramas, el equivalente practico a "escuchando".
fn parse_listen_sockets(
    path: &str,
    protocol: Protocol,
    listen_state: &str,
    is_v6: bool,
) -> Vec<ListenSocket> {
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
        if fields[3] != listen_state {
            continue;
        }
        let parsed = if is_v6 {
            parse_hex_ipv6_port(fields[1]).map(|(ip, port)| (IpAddr::V6(ip), port))
        } else {
            parse_hex_ipv4_port(fields[1]).map(|(ip, port)| (IpAddr::V4(ip), port))
        };
        let (local_ip, local_port) = match parsed {
            Some(v) => v,
            None => continue,
        };
        let inode = match fields[9].parse::<u64>() {
            Ok(i) => i,
            Err(_) => continue,
        };
        out.push(ListenSocket {
            local_ip,
            local_port,
            protocol,
            inode,
        });
    }
    out
}

pub fn parse_listen_tcp(path: &str, is_v6: bool) -> Vec<ListenSocket> {
    parse_listen_sockets(path, Protocol::Tcp, "0A", is_v6)
}

pub fn parse_listen_udp(path: &str, is_v6: bool) -> Vec<ListenSocket> {
    parse_listen_sockets(path, Protocol::Udp, "07", is_v6)
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
    let inner = link_target.strip_prefix("socket:[")?.strip_suffix(']')?;
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

/// True si la conexion SALIENTE esta dentro de lo esperado segun la
/// configuracion (llamar solo sobre conexiones que `is_inbound` descarto).
pub fn is_allowed(conn: &Connection, allowed_ports: &[u16], allowed_cidrs: &[String]) -> bool {
    if allowed_ports.contains(&conn.remote_port) {
        return true;
    }
    allowed_cidrs
        .iter()
        .any(|cidr| ipv4_in_cidr(conn.remote_ip, cidr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(local_port: u16, remote_port: u16) -> Connection {
        Connection {
            local_port,
            remote_ip: Ipv4Addr::new(203, 0, 113, 7),
            remote_port,
            inode: 1,
        }
    }

    const EPH: EphemeralRange = EphemeralRange::LINUX_DEFAULT;

    #[test]
    fn ssh_entrante_es_inbound() {
        // Caso real: sshd, local 22, remoto efimero (10773 / 12179).
        let listening = HashSet::new();
        assert!(is_inbound(&conn(22, 10773), &[22], &listening, EPH));
        assert!(is_inbound(&conn(22, 12179), &[22], &listening, EPH));
        // Aun sin 22 en allowed_listen_ports: es privilegiado.
        assert!(is_inbound(&conn(22, 10773), &[], &listening, EPH));
    }

    #[test]
    fn ssh_saliente_no_es_inbound() {
        // Cliente ssh desde esta maquina: local efimero, remoto 22.
        let listening = HashSet::new();
        assert!(!is_inbound(&conn(45678, 22), &[22], &listening, EPH));
    }

    #[test]
    fn servicio_en_puerto_alto_escuchando_es_inbound() {
        let listening: HashSet<u16> = [8080].into_iter().collect();
        assert!(is_inbound(&conn(8080, 51000), &[], &listening, EPH));
        // ...pero si nadie escucha en ese puerto y es efimero, es saliente.
        assert!(!is_inbound(&conn(51000, 8080), &[], &listening, EPH));
    }

    #[test]
    fn puerto_local_fuera_del_rango_efimero_es_inbound() {
        // 3306 no es privilegiado ni esta listado, pero el kernel no lo
        // asignaria como puerto de origen: tiene que ser un servicio.
        let listening = HashSet::new();
        assert!(is_inbound(&conn(3306, 40000), &[], &listening, EPH));
    }

    #[test]
    fn efimero_a_efimero_sigue_siendo_saliente() {
        // C2 escuchando en un puerto alto: no se mira el remoto.
        let listening = HashSet::new();
        assert!(!is_inbound(&conn(40000, 44444), &[], &listening, EPH));
    }

    #[test]
    fn rango_efimero_respeta_la_config_del_kernel() {
        let custom = EphemeralRange {
            low: 10000,
            high: 65000,
        };
        let listening = HashSet::new();
        assert!(!is_inbound(&conn(10773, 443), &[], &listening, custom));
        assert!(is_inbound(&conn(10773, 443), &[], &listening, EPH));
    }

    #[test]
    fn parse_ip_local_port_range() {
        assert_eq!(
            parse_local_port_range("32768\t60999\n"),
            Some(EphemeralRange {
                low: 32768,
                high: 60999
            })
        );
        assert_eq!(
            parse_local_port_range("1024 65535"),
            Some(EphemeralRange {
                low: 1024,
                high: 65535
            })
        );
        assert_eq!(parse_local_port_range("60999 32768"), None);
        assert_eq!(parse_local_port_range(""), None);
        assert_eq!(parse_local_port_range("abc def"), None);
    }

    #[test]
    fn parse_tcp_conserva_puerto_local() {
        // 0100007F:0016 = 127.0.0.1:22 ; 0A00000A:2A15 = 10.0.0.10:10773
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:0016 0A00000A:2A15 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 20 4 30 10 -1\n\
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0\n";
        let conns = parse_tcp_connections_from(content);
        assert_eq!(conns.len(), 1, "solo la ESTABLISHED, no la LISTEN");
        assert_eq!(conns[0].local_port, 22);
        assert_eq!(conns[0].remote_ip, Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(conns[0].remote_port, 10773);
        assert_eq!(conns[0].inode, 12345);
    }

    #[test]
    fn cidr_matcher() {
        assert!(ipv4_in_cidr(Ipv4Addr::new(10, 1, 2, 3), "10.0.0.0/8"));
        assert!(!ipv4_in_cidr(Ipv4Addr::new(11, 1, 2, 3), "10.0.0.0/8"));
        assert!(ipv4_in_cidr(Ipv4Addr::new(1, 2, 3, 4), "0.0.0.0/0"));
        assert!(!ipv4_in_cidr(Ipv4Addr::new(1, 2, 3, 4), "garbage"));
    }
}
