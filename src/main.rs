//! Puls3Scan: escáner SYN stateless (estilo masscan) con dos modos:
//!   -a <ip|dominio>       -> un host, todos los puertos por defecto
//!   range <cidr>...       -> rangos grandes, orden pseudoaleatorio
//! Requiere root o CAP_NET_RAW. Úsalo solo contra redes que tengas autorización para escanear.

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use ipnetwork::Ipv4Network;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
};
use std::collections::{hash_map::DefaultHasher, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::io::{IsTerminal, Write};
use std::{fs, process, thread};

const COMMON_PORTS: &str =
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443";

#[derive(Parser)]
#[command(name = "pscan", about = "Puls3Scan: escáner SYN stateless rápido")]
struct Cli {
    /// Escanea un solo objetivo: IP o nombre de dominio (por defecto, los 65535 puertos)
    #[arg(short = 'a', long = "address", value_name = "IP|DOMINIO")]
    address: Option<String>,
    #[command(flatten)]
    common: Common,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Barre uno o varios rangos (CIDR o IP) en orden aleatorio
    Range {
        /// Objetivos: 10.0.0.0/16 192.168.1.5 ...
        targets: Vec<String>,
        /// Rangos a excluir (CIDR o IP), repetible
        #[arg(long)]
        exclude: Vec<String>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// SYN en crudo si es fiable; connect() automáticamente en WSL2 con NAT
    Auto,
    /// SYN stateless (rápido; requiere root y red "real")
    Syn,
    /// connect() normal del kernel (lento pero funciona a través de NAT/WSL2)
    Connect,
}

#[derive(Args)]
struct Common {
    /// Puertos: "-p 22", "-p 80,443,8000-9000"; "-p" sin valor = todos (1-65535).
    /// Sin -p: host = todos, range = puertos comunes
    #[arg(global = true, short, long, num_args = 0..=1, default_missing_value = "1-65535")]
    ports: Option<String>,
    /// Paquetes por segundo en modo syn (por defecto: 10000 en un host, 100000 en rangos)
    #[arg(global = true, short, long)]
    rate: Option<u64>,
    /// Método de escaneo
    #[arg(global = true, long, value_enum, default_value_t = Mode::Auto)]
    mode: Mode,
    /// Conexiones simultáneas en modo connect
    #[arg(global = true, long, default_value_t = 400)]
    workers: usize,
    /// Timeout por conexión en modo connect (ms)
    #[arg(global = true, long, default_value_t = 800)]
    timeout_ms: u64,
    /// Hilos de envío
    #[arg(global = true, short, long, default_value_t = 2)]
    threads: usize,
    /// Segundos de espera de respuestas tras el último envío
    #[arg(global = true, long, default_value_t = 3)]
    wait: u64,
    /// Reintentos (pasadas extra sobre todo el espacio)
    #[arg(global = true, long, default_value_t = 0)]
    retries: u32,
    /// Semilla del orden aleatorio (reproducible)
    #[arg(global = true, long)]
    seed: Option<u64>,
    /// IP de origen (por defecto se autodetecta)
    #[arg(global = true, long)]
    src_ip: Option<Ipv4Addr>,
    /// No mostrar el banner
    #[arg(global = true, long)]
    no_banner: bool,
    /// Banner estático: sin animación (también: PSCAN_NO_ANIM=1)
    #[arg(global = true, long)]
    no_anim: bool,
    /// Duración del barrido de carga del banner en ms (0 = sin animación; la ola posterior dura ~2.6 s)
    #[arg(global = true, long, default_value_t = ANIM_DEFAULT_MS, value_name = "MS")]
    anim_ms: u64,
    /// Muestra detalles del escaneo (modo, workers, avisos de WSL2...)
    #[arg(global = true, short, long)]
    verbose: bool,
    /// Guarda resultados "ip:puerto", uno por línea
    #[arg(global = true, short, long, value_name = "FICHERO")]
    output: Option<String>,
    /// Guarda las IPs con puertos abiertos como array JSON (-oi)
    #[arg(global = true, long = "oi", value_name = "FICHERO")]
    out_ips: Option<String>,
    /// Guarda los puertos abiertos (únicos) como array JSON (-op)
    #[arg(global = true, long = "op", value_name = "FICHERO")]
    out_ports: Option<String>,
}

// ---------- Permutación pseudoaleatoria (Feistel + cycle walking) ----------

struct Perm {
    n: u64,
    half: u32,
    keys: [u64; 4],
}

fn splitmix(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

impl Perm {
    fn new(n: u64, mut seed: u64) -> Self {
        let mut bits = if n <= 1 { 0 } else { 64 - (n - 1).leading_zeros() };
        if bits % 2 == 1 {
            bits += 1;
        }
        let keys = [splitmix(&mut seed), splitmix(&mut seed), splitmix(&mut seed), splitmix(&mut seed)];
        Perm { n, half: bits / 2, keys }
    }
    #[inline]
    fn enc(&self, x: u64) -> u64 {
        let mask = (1u64 << self.half) - 1;
        let (mut l, mut r) = (x >> self.half, x & mask);
        for &k in &self.keys {
            let mut z = r.wrapping_add(k).wrapping_mul(0x9E3779B97F4A7C15);
            z ^= z >> 29;
            z = z.wrapping_mul(0xBF58476D1CE4E5B9);
            z ^= z >> 32;
            let t = r;
            r = l ^ (z & mask);
            l = t;
        }
        (l << self.half) | r
    }
    #[inline]
    fn get(&self, i: u64) -> u64 {
        let mut x = self.enc(i);
        while x >= self.n {
            x = self.enc(x);
        }
        x
    }
}

// ---------- Cookie SYN ----------

#[inline]
fn cookie(secret: u64, ip: u32, dport: u16, sport: u16) -> u32 {
    let mut h = DefaultHasher::new();
    (secret, ip, dport, sport).hash(&mut h);
    h.finish() as u32
}

#[inline]
fn src_port_for(c: u32) -> u16 {
    (40000 + c % 20000) as u16
}

// ---------- Colores ----------

fn color_on(is_tty: bool) -> bool {
    is_tty && std::env::var_os("NO_COLOR").is_none()
}

type Rgb = (u8, u8, u8);

/// Degradado del banner: naranja (arriba-izquierda) -> blanco (abajo-derecha).
const COLOR_FROM: Rgb = (255, 106, 0);
const COLOR_TO: Rgb = (255, 255, 255);

/// Frases del banner: se elige una al azar en cada ejecución. Añade las tuyas.
const PHRASES: &[&str] = &[
    "Llamando a todas las puertas, una por una.",
    "Puertos abiertos, corazones cerrados.",
    "Cada puerto tiene su historia.",
    "Un SYN a tiempo vale más que mil connect().",
    "Si no lo escaneas, no existe.",
    "Escanear sin permiso no es hacking, es mala educación.",
    "Pulso estable, puertos a la vista.",
    "Hasta el último puerto, sin prisa y sin pausa.",
    "Tu red, tus reglas, tu autorización.",
    "Más rápido que un café de máquina.",
    "Menos esperar, más escanear.",
    "Úsalo solo con autorización.",
];

/// Versión (sale de Cargo.toml) y arte del banner.
const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const BANNER: &str = r#"
██████╗ ██╗   ██╗██╗     ███████╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██║   ██║██║     ██╔════╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝██║   ██║██║     ███████╗█████╗  ███████╗██║     ███████║██╔██╗ ██║
██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ╚██████╔╝███████╗███████║███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"#;

fn lerp(a: Rgb, b: Rgb, t: f32) -> Rgb {
    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    (f(a.0, b.0), f(a.1, b.1), f(a.2, b.2))
}

fn fg(c: Rgb) -> String {
    format!("\x1b[38;2;{};{};{}m", c.0, c.1, c.2)
}

/// Degradado horizontal carácter a carácter.
fn grad(text: &str, from: Rgb, to: Rgb, bold: bool) -> String {
    let n = text.chars().count().max(2);
    let mut out = String::new();
    if bold {
        out.push_str("\x1b[1m");
    }
    for (i, ch) in text.chars().enumerate() {
        out.push_str(&fg(lerp(from, to, i as f32 / (n - 1) as f32)));
        out.push(ch);
    }
    out.push_str("\x1b[0m");
    out
}

fn hsv(h: f32, s: f32, v: f32) -> Rgb {
    let h = h.rem_euclid(360.0) / 60.0;
    let c = v * s;
    let x = c * (1.0 - ((h % 2.0) - 1.0).abs());
    let m = v - c;
    let (r, g, b) = match h as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    (((r + m) * 255.0) as u8, ((g + m) * 255.0) as u8, ((b + m) * 255.0) as u8)
}

/// Cada IP: degradado propio, con tono estable según la IP.
fn paint_ip(ip: Ipv4Addr, on: bool) -> String {
    if !on {
        return ip.to_string();
    }
    let o = ip.octets();
    let h = ((o[1] as u32 * 7 + o[2] as u32 * 13 + o[3] as u32 * 29) % 360) as f32;
    grad(&ip.to_string(), hsv(h, 0.75, 1.0), hsv(h + 70.0, 0.75, 1.0), true)
}

fn paint_port(p: u16, on: bool) -> String {
    if on { grad(&p.to_string(), (255, 214, 0), (255, 95, 31), true) } else { p.to_string() }
}

// ---------- Banner ----------
//
// El banner se imprime EN LÍNEA, justo donde está el cursor: no limpia la
// pantalla ni salta a la esquina superior izquierda; el programa continúa
// debajo, en la misma terminal.
//
// Animación: un barrido en diagonal (de arriba-izquierda a abajo-derecha) va
// "encendiendo" las letras con el degradado naranja -> blanco. Al terminar, el
// frame final queda impreso como banner estático. Todo es cosmético: ningún
// fallo de terminal aborta el escaneo.

/// Frames por segundo de la animación.
const ANIM_FPS: u64 = 60;
/// Duración por defecto del barrido (ms). 0 = sin animación.
const ANIM_DEFAULT_MS: u64 = 900;
/// Ancho del borde luminoso del barrido (fracción de la diagonal).
const SWEEP_EDGE: f64 = 0.25;
/// Una celda de terminal es ~2x más alta que ancha: contamos cada fila como 2
/// columnas para que la diagonal salga a 45°.
const ROW_WEIGHT: f64 = 2.0;
/// Color de las letras que el barrido aún no ha alcanzado.
const DIM: Rgb = (70, 70, 70);
/// Ola de brillo tras el barrido: duración (ms), vueltas completas durante ese
/// tiempo, bandas visibles a la vez a lo largo de la diagonal y brillo mínimo
/// de los valles (0.0 = negro, 1.0 = sin contraste).
const WAVE_MS: u64 = 2600;
const WAVE_CYCLES: f64 = 2.0;
const WAVE_BANDS: f64 = 1.5;
const WAVE_TROUGH: f32 = 0.3;
/// Filas extra tras el arte: versión + frase + línea en blanco.
const EXTRA_ROWS: usize = 3;

const CURSOR_HIDE: &str = "\x1b[?25l";
const CURSOR_SHOW: &str = "\x1b[0m\x1b[?25h";

/// Escribe en stderr ignorando cualquier error (a diferencia de `eprint!`,
/// que hace panic si falla; con panic = "abort" eso mataría el escaneo).
fn write_stderr(s: &str) -> bool {
    let mut e = std::io::stderr().lock();
    e.write_all(s.as_bytes()).and_then(|_| e.flush()).is_ok()
}

/// Frase aleatoria sin dependencias extra (reloj + splitmix).
fn random_phrase() -> &'static str {
    let mut s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    PHRASES[(splitmix(&mut s) % PHRASES.len() as u64) as usize]
}

/// Líneas del arte sin los saltos de línea de los extremos.
fn banner_lines() -> Vec<&'static str> {
    BANNER.trim_matches('\n').lines().collect()
}

fn banner_width(lines: &[&str]) -> usize {
    lines.iter().map(|l| l.chars().count()).max().unwrap_or(1).max(1)
}

/// Línea de la versión, alineada a la derecha: queda justo bajo la última N.
fn version_row(width: usize, color: bool) -> String {
    let pad = " ".repeat(width.saturating_sub(VERSION.chars().count()));
    if color {
        format!("{pad}\x1b[1m{}{VERSION}\x1b[0m\n", fg(COLOR_TO))
    } else {
        format!("{pad}{VERSION}\n")
    }
}

/// Un frame completo (arte + versión + frase + línea en blanco). Ocupa siempre
/// `lines.len() + EXTRA_ROWS` filas, todas terminadas en '\n'.
/// `reveal` va de 0.0 (todo apagado) a 1.0 (degradado completo y textos visibles).
fn banner_frame(lines: &[&str], width: usize, reveal: f64, wave: (f64, f64), phrase: &str) -> String {
    let (phase, amp) = wave; // amp 0.0 = sin ola; 1.0 = ola completa
    let rows = lines.len();
    let span = width as f64 + rows.saturating_sub(1) as f64 * ROW_WEIGHT;
    let lead = reveal * (1.0 + SWEEP_EDGE);
    let mut out = String::with_capacity(rows * width * 22 + 512);
    for (row, l) in lines.iter().enumerate() {
        for (col, ch) in l.chars().enumerate() {
            if ch == ' ' {
                out.push(' ');
                continue;
            }
            let d = (col as f64 + row as f64 * ROW_WEIGHT) / span; // 0.0 arriba-izq .. 1.0 abajo-der
            let fin = lerp(COLOR_FROM, COLOR_TO, d as f32);
            let k = lead - d;
            let c = if k >= SWEEP_EDGE {
                fin
            } else if k >= 0.0 {
                lerp(COLOR_TO, fin, (k / SWEEP_EDGE) as f32) // borde brillante del barrido
            } else {
                DIM
            };
            let c = if amp > 0.0 {
                // Ola diagonal: la cresta (color del degradado) avanza hacia abajo-derecha.
                let w = 0.5 + 0.5 * (std::f64::consts::TAU * (d * WAVE_BANDS - phase)).sin();
                let w = (w * w) as f32;
                let dark = ((c.0 as f32 * WAVE_TROUGH) as u8, (c.1 as f32 * WAVE_TROUGH) as u8, (c.2 as f32 * WAVE_TROUGH) as u8);
                lerp(c, lerp(dark, c, w), amp as f32)
            } else {
                c
            };
            out.push_str(&fg(c));
            out.push(ch);
        }
        out.push_str("\x1b[0m\n");
    }
    if reveal >= 1.0 {
        out.push_str(&version_row(width, true));
        out.push_str(&format!("{}\n\n", grad(phrase, COLOR_FROM, COLOR_TO, false)));
    } else {
        out.push_str("\n\n\n"); // mismas filas, aún sin texto
    }
    out
}

/// Banner estático (sin secuencias de cursor).
fn print_banner(color: bool, phrase: &str) {
    let lines = banner_lines();
    let width = banner_width(&lines);
    if color {
        write_stderr(&banner_frame(&lines, width, 1.0, (0.0, 0.0), phrase));
    } else {
        write_stderr(&format!("{}\n{}{phrase}\n\n", lines.join("\n"), version_row(width, false)));
    }
}

/// Ctrl+C / SIGTERM durante la animación: vuelve a mostrar el cursor (solo Unix,
/// sin dependencias; únicamente funciones async-signal-safe).
#[cfg(unix)]
mod sig {
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
        fn write(fd: i32, buf: *const u8, count: usize) -> isize;
        fn _exit(status: i32) -> !;
    }
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    const SIG_DFL: usize = 0;

    pub fn raw_write_stderr(b: &[u8]) {
        unsafe {
            write(2, b.as_ptr(), b.len());
        }
    }
    extern "C" fn on_signal(_: i32) {
        raw_write_stderr(super::CURSOR_SHOW.as_bytes());
        raw_write_stderr(b"\n");
        unsafe { _exit(130) }
    }
    pub fn install() {
        unsafe {
            signal(SIGINT, on_signal as *const () as usize);
            signal(SIGTERM, on_signal as *const () as usize);
        }
    }
    pub fn restore() {
        unsafe {
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
        }
    }
}
#[cfg(not(unix))]
mod sig {
    use std::io::Write;
    pub fn raw_write_stderr(b: &[u8]) {
        let _ = std::io::stderr().write_all(b);
    }
    pub fn install() {}
    pub fn restore() {}
}

/// Oculta el cursor mientras vive y lo restaura SIEMPRE al soltarse (salida
/// normal), por señal (Ctrl+C/SIGTERM) o por pánico (hook previo al abort).
struct CursorGuard;

impl CursorGuard {
    fn hide() -> Self {
        sig::install();
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            sig::raw_write_stderr(CURSOR_SHOW.as_bytes());
            prev(info);
        }));
        write_stderr(CURSOR_HIDE);
        CursorGuard
    }
}

impl Drop for CursorGuard {
    fn drop(&mut self) {
        write_stderr(CURSOR_SHOW);
        sig::restore();
    }
}

/// Animación en el sitio, en dos fases: (1) barrido de carga que enciende las
/// letras y (2) ola de brillo diagonal, de izquierda a derecha, que se va
/// apagando hasta dejar el degradado final. Redibuja el banner subiendo el
/// cursor al inicio en cada frame; el último frame (banner completo) queda
/// impreso con el cursor justo debajo.
fn animate_banner(ms: u64, phrase: &str) {
    let lines = banner_lines();
    let width = banner_width(&lines);
    let up = lines.len() + EXTRA_ROWS;
    let sweep = (ms * ANIM_FPS / 1000).max(2);
    let wave = (WAVE_MS * ANIM_FPS / 1000).max(2);
    let frame_dur = Duration::from_micros(1_000_000 / ANIM_FPS);
    let _guard = CursorGuard::hide();
    let start = Instant::now();
    for n in 0..=(sweep + wave) {
        let (reveal, w) = if n <= sweep {
            (n as f64 / sweep as f64, (0.0, 0.0))
        } else {
            let t = (n - sweep) as f64 / wave as f64; // 0.0..=1.0
            // Entra y sale suave: el último frame (t = 1) es exactamente el degradado final.
            let amp = (t / 0.15).min(1.0) * ((1.0 - t) / 0.25).min(1.0);
            (1.0, (t * WAVE_CYCLES, amp.max(0.0)))
        };
        let mut f = String::new();
        if n > 0 {
            f.push_str(&format!("\x1b[{up}A\r")); // subir al inicio del banner
        }
        f.push_str(&banner_frame(&lines, width, reveal, w, phrase));
        if !write_stderr(&f) {
            break;
        }
        if n < sweep + wave {
            let next = start + frame_dur.mul_f64((n + 1) as f64);
            if let Some(w) = next.checked_duration_since(Instant::now()) {
                thread::sleep(w);
            }
        }
    }
}

/// Tamaño de la terminal (filas, columnas) vía ioctl sobre stderr. Solo Linux
/// x86_64/aarch64; en el resto devuelve None.
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn term_size() -> Option<(usize, usize)> {
    #[repr(C)]
    #[allow(dead_code)]
    struct Winsize {
        rows: u16,
        cols: u16,
        xpix: u16,
        ypix: u16,
    }
    extern "C" {
        fn ioctl(fd: i32, request: std::os::raw::c_ulong, ...) -> i32;
    }
    const TIOCGWINSZ: std::os::raw::c_ulong = 0x5413;
    let mut ws = Winsize { rows: 0, cols: 0, xpix: 0, ypix: 0 };
    let r = unsafe { ioctl(2, TIOCGWINSZ, &mut ws as *mut Winsize) };
    if r == 0 && ws.cols > 0 && ws.rows > 0 { Some((ws.rows as usize, ws.cols as usize)) } else { None }
}
#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn term_size() -> Option<(usize, usize)> {
    None
}

/// ¿Se puede animar? Requiere color, sin --no-anim / --anim-ms 0 / PSCAN_NO_ANIM=1,
/// TERM != dumb y una terminal lo bastante ancha y alta para el banner entero
/// (si no cupiera, subir el cursor dejaría restos en pantalla).
fn anim_allowed(c: &Common, color: bool, width: usize, height: usize) -> bool {
    color
        && !c.no_anim
        && c.anim_ms > 0
        && std::env::var("PSCAN_NO_ANIM").map_or(true, |v| v != "1")
        && std::env::var("TERM").map_or(true, |t| t != "dumb")
        && term_size().map_or(true, |(rows, cols)| cols >= width && rows > height)
}

/// Punto de entrada del banner. Solo stderr y solo si es un TTY. Imprime en
/// línea (continúa donde estaba el cursor) y termina antes de lanzar el escaneo.
fn show_banner(c: &Common) {
    if c.no_banner || !std::io::stderr().is_terminal() {
        return;
    }
    let color = color_on(true); // NO_COLOR => banner plano, sin animación
    let lines = banner_lines();
    let (width, height) = (banner_width(&lines), lines.len() + EXTRA_ROWS);
    let phrase = random_phrase();
    write_stderr("\n");
    if anim_allowed(c, color, width, height) {
        animate_banner(c.anim_ms, phrase);
    } else {
        print_banner(color, phrase);
    }
}

// ---------- Parsing ----------

fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut v = Vec::new();
    for part in s.split(',').filter(|p| !p.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let (a, b): (u16, u16) = (
                a.trim().parse().map_err(|_| format!("puerto inválido: {part}"))?,
                b.trim().parse().map_err(|_| format!("puerto inválido: {part}"))?,
            );
            if a > b || a == 0 {
                return Err(format!("rango inválido: {part}"));
            }
            v.extend(a..=b);
        } else {
            let p: u16 = part.trim().parse().map_err(|_| format!("puerto inválido: {part}"))?;
            if p == 0 {
                return Err("el puerto 0 no es válido".into());
            }
            v.push(p);
        }
    }
    v.sort_unstable();
    v.dedup();
    if v.is_empty() {
        return Err("lista de puertos vacía".into());
    }
    Ok(v)
}

/// Devuelve (inicio, cantidad) de cada rango.
fn parse_target(s: &str) -> Result<(u32, u64), String> {
    if let Ok(net) = s.parse::<Ipv4Network>() {
        return Ok((u32::from(net.network()), 1u64 << (32 - net.prefix() as u32)));
    }
    let addr = (s, 0)
        .to_socket_addrs()
        .map_err(|e| format!("no se pudo resolver {s}: {e}"))?
        .find_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| format!("{s} no tiene dirección IPv4"))?;
    Ok((u32::from(addr), 1))
}

fn detect_src(dst: u32) -> Ipv4Addr {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect((Ipv4Addr::from(dst), 9))?;
            s.local_addr()
        })
        .ok()
        .and_then(|a| match a.ip() {
            IpAddr::V4(v) => Some(v),
            _ => None,
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

// ---------- Motor ----------

struct Job {
    ranges: Vec<(u32, u64)>,
    excl: Vec<(u32, u64)>,
    ports: Vec<u16>,
    total_ips: u64,
}

fn ip_at(ranges: &[(u32, u64)], mut idx: u64) -> u32 {
    for &(start, count) in ranges {
        if idx < count {
            return start.wrapping_add(idx as u32);
        }
        idx -= count;
    }
    unreachable!()
}

#[allow(clippy::too_many_arguments)]
fn sender(
    id: usize,
    nthreads: usize,
    job: Arc<Job>,
    perm: Arc<Perm>,
    src: Ipv4Addr,
    secret: u64,
    rate: u64,
    retries: u32,
    sent: Arc<AtomicU64>,
) {
    let (mut tx, _) = match transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error abriendo raw socket (¿root / CAP_NET_RAW?): {e}");
            process::exit(1);
        }
    };
    let np = job.ports.len() as u64;
    let total = job.total_ips * np;
    let per_thread = (rate / nthreads as u64).max(1) as f64;
    let start = Instant::now();
    let mut n: u64 = 0;
    let mut buf = [0u8; 20];

    for _pass in 0..=retries {
        let mut i = id as u64;
        while i < total {
            let x = perm.get(i);
            i += nthreads as u64;
            let ip = ip_at(&job.ranges, x / np);
            let port = job.ports[(x % np) as usize];
            if job.excl.iter().any(|&(s, c)| ip >= s && ((ip - s) as u64) < c) {
                continue;
            }
            let c = cookie(secret, ip, port, 0);
            let sport = src_port_for(c);
            let c = cookie(secret, ip, port, sport);
            let dst = Ipv4Addr::from(ip);

            let mut pkt = MutableTcpPacket::new(&mut buf).unwrap();
            pkt.set_source(sport);
            pkt.set_destination(port);
            pkt.set_sequence(c);
            pkt.set_acknowledgement(0);
            pkt.set_data_offset(5);
            pkt.set_flags(TcpFlags::SYN);
            pkt.set_window(1024);
            pkt.set_urgent_ptr(0);
            pkt.set_checksum(0);
            let ck = ipv4_checksum(&pkt.to_immutable(), &src, &dst);
            pkt.set_checksum(ck);
            let _ = tx.send_to(pkt, IpAddr::V4(dst));

            n += 1;
            if n % 256 == 0 {
                sent.fetch_add(256, Ordering::Relaxed);
                let want = Duration::from_secs_f64(n as f64 / per_thread);
                let el = start.elapsed();
                if want > el {
                    thread::sleep(want - el);
                }
            }
        }
    }
    sent.fetch_add(n % 256, Ordering::Relaxed);
}

fn is_wsl() -> bool {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| {
            let s = s.to_lowercase();
            s.contains("microsoft") || s.contains("wsl")
        })
        .unwrap_or(false)
}

fn is_private_172(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 172 && (16..=31).contains(&o[1])
}

/// Escaneo connect(): usa la pila TCP del kernel, así que atraviesa el NAT de WSL2 sin problemas.
fn connect_scan(
    job: Arc<Job>,
    perm: Arc<Perm>,
    workers: usize,
    timeout: Duration,
    retries: u32,
) -> Vec<(Ipv4Addr, u16)> {
    let np = job.ports.len() as u64;
    let total = job.total_ips * np;
    let next = Arc::new(AtomicU64::new(0));
    let found: Arc<Mutex<Vec<(Ipv4Addr, u16)>>> = Arc::new(Mutex::new(Vec::new()));
    let color = color_on(std::io::stdout().is_terminal());

    let handles: Vec<_> = (0..workers)
        .map(|_| {
            let (job, perm, next, found) = (job.clone(), perm.clone(), next.clone(), found.clone());
            thread::spawn(move || loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    break;
                }
                let x = perm.get(i);
                let ip = ip_at(&job.ranges, x / np);
                let port = job.ports[(x % np) as usize];
                if job.excl.iter().any(|&(s, c)| ip >= s && ((ip - s) as u64) < c) {
                    continue;
                }
                let ipa = Ipv4Addr::from(ip);
                let addr = SocketAddr::new(IpAddr::V4(ipa), port);
                let mut open = false;
                for _ in 0..=retries {
                    match TcpStream::connect_timeout(&addr, timeout) {
                        Ok(_) => {
                            open = true;
                            break;
                        }
                        // RST: el host responde y el puerto está cerrado, no tiene sentido reintentar
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,
                        Err(_) => continue,
                    }
                }
                if open {
                    let sep = if color { "\x1b[2m:\x1b[0m" } else { ":" };
                    println!("{}{}{}", paint_ip(ipa, color), sep, paint_port(port, color));
                    if let Ok(mut g) = found.lock() {
                        g.push((ipa, port));
                    }
                }
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    let out = found.lock().map(|g| g.clone()).unwrap_or_default();
    out
}

fn save(c: &Common, found: &[(Ipv4Addr, u16)]) {
    let write = |path: &str, text: String| {
        if let Err(e) = fs::write(path, text) {
            eprintln!("no se pudo escribir {path}: {e}");
        }
    };
    if let Some(path) = &c.output {
        write(path, found.iter().map(|(ip, p)| format!("{ip}:{p}\n")).collect());
    }
    if let Some(path) = &c.out_ips {
        let ips: std::collections::BTreeSet<_> = found.iter().map(|(ip, _)| *ip).collect();
        let items: Vec<String> = ips.iter().map(|i| format!("\"{i}\"")).collect();
        write(path, format!("[{}]\n", items.join(", ")));
    }
    if let Some(path) = &c.out_ports {
        let ports: std::collections::BTreeSet<_> = found.iter().map(|(_, p)| *p).collect();
        let items: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        write(path, format!("[{}]\n", items.join(", ")));
    }
}

/// Destino para mostrar: la IP, o la primera IP + cuántas más hay en el rango.
fn target_label(job: &Job) -> String {
    let first = Ipv4Addr::from(job.ranges[0].0);
    if job.total_ips <= 1 {
        first.to_string()
    } else {
        format!("{first} (+{} IPs más)", job.total_ips - 1)
    }
}

fn run(job: Job, c: Common) {
    show_banner(&c);
    let seed = c.seed.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1)
    });
    let secret = seed ^ 0xA5A5_5A5A_DEAD_BEEF;
    let total = job.total_ips * job.ports.len() as u64;
    let src = c.src_ip.unwrap_or_else(|| detect_src(job.ranges[0].0));
    let first = Ipv4Addr::from(job.ranges[0].0);

    let ec = color_on(std::io::stderr().is_terminal());
    let tag = if ec { "\x1b[1;32m[+]\x1b[0m" } else { "[+]" };
    let info = if ec { "\x1b[1;38;2;255;106;0m[~]\x1b[0m" } else { "[~]" };
    let warn = if ec { "\x1b[1;33m[!]\x1b[0m" } else { "[!]" };

    // WSL2 en modo NAT: la IP de origen es 172.16/12 (red virtual de Hyper-V) y el destino es otra red.
    let nat = is_wsl() && is_private_172(src) && !is_private_172(first);
    let use_connect = match c.mode {
        Mode::Connect => true,
        Mode::Syn => false,
        Mode::Auto => nat,
    };
    // Como RustScan: por defecto solo el destino. El resto, con --verbose.
    eprintln!("{info} Objetivo: {}", target_label(&job));
    if c.verbose {
        if nat && use_connect && c.mode == Mode::Auto {
            eprintln!("{warn} WSL2 en modo NAT (origen {src}, destino {first}): los SYN en crudo no atraviesan bien el NAT de Windows.");
            eprintln!("    Uso escaneo connect(). Para SYN real: 'networkingMode=mirrored' en %UserProfile%\\.wslconfig y 'wsl --shutdown'.");
        } else if nat && !use_connect {
            eprintln!("{warn} WSL2 en modo NAT: el escaneo SYN puede no recibir respuestas de {first}. Prueba --mode connect.");
        }
    }

    if use_connect {
        let workers = c.workers.clamp(1, 900);
        let timeout = Duration::from_millis(c.timeout_ms.max(50));
        if c.verbose {
            eprintln!(
                "[*] {} IPs x {} puertos = {} sondas | modo connect | {} workers | timeout {} ms",
                job.total_ips,
                job.ports.len(),
                total * (c.retries as u64 + 1),
                workers,
                c.timeout_ms
            );
        }
        let perm = Arc::new(Perm::new(total, seed));
        let job = Arc::new(job);
        let t0 = Instant::now();
        let mut found = connect_scan(job, perm, workers, timeout, c.retries);
        let secs = t0.elapsed().as_secs_f64();
        found.sort();
        eprintln!("{} {} abiertos | {} sondas en {:.2}s", tag, found.len(), total, secs);
        save(&c, &found);
        return;
    }

    let nthreads = c.threads.max(1);
    let rate = c.rate.unwrap_or(if job.total_ips == 1 { 10_000 } else { 100_000 });
    if c.verbose {
        eprintln!(
            "[*] {} IPs x {} puertos = {} sondas | modo syn | rate {} pps | {} hilos | src {}",
            job.total_ips,
            job.ports.len(),
            total * (c.retries as u64 + 1),
            rate,
            nthreads,
            src
        );
    }

    let (_tx, mut rx) = match transport_channel(1 << 16, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error abriendo raw socket (¿root / CAP_NET_RAW?): {e}");
            process::exit(1);
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_rx = stop.clone();
    let receiver = thread::spawn(move || {
        let mut seen: HashSet<(u32, u16)> = HashSet::new();
        let mut found: Vec<(Ipv4Addr, u16)> = Vec::new();
        let color = color_on(std::io::stdout().is_terminal());
        let mut it = tcp_packet_iter(&mut rx);
        while !stop_rx.load(Ordering::Relaxed) {
            if let Ok(Some((pkt, IpAddr::V4(ip)))) = it.next_with_timeout(Duration::from_millis(100)) {
                if pkt.get_flags() & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                    let dport = pkt.get_source();
                    let sport = pkt.get_destination();
                    let ipn = u32::from(ip);
                    let ck = cookie(secret, ipn, dport, sport);
                    let base = cookie(secret, ipn, dport, 0);
                    if sport == src_port_for(base)
                        && pkt.get_acknowledgement() == ck.wrapping_add(1)
                        && seen.insert((ipn, dport))
                    {
                        let sep = if color { "\x1b[2m:\x1b[0m" } else { ":" };
                        println!("{}{}{}", paint_ip(ip, color), sep, paint_port(dport, color));
                        found.push((ip, dport));
                    }
                }
            }
        }
        found
    });

    let sent = Arc::new(AtomicU64::new(0));
    let job = Arc::new(job);
    let perm = Arc::new(Perm::new(total, seed));
    let t0 = Instant::now();
    let handles: Vec<_> = (0..nthreads)
        .map(|id| {
            let (job, perm, sent) = (job.clone(), perm.clone(), sent.clone());
            let retries = c.retries;
            thread::spawn(move || sender(id, nthreads, job, perm, src, secret, rate, retries, sent))
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    let send_time = t0.elapsed().as_secs_f64();
    if c.verbose {
        eprintln!("[*] envío terminado, esperando {}s respuestas...", c.wait);
    }
    thread::sleep(Duration::from_secs(c.wait));
    stop.store(true, Ordering::Relaxed);
    let mut found = receiver.join().unwrap_or_default();
    found.sort();

    eprintln!(
        "{} {} abiertos | {} paquetes en {:.2}s (~{:.0} pps)",
        tag,
        found.len(),
        sent.load(Ordering::Relaxed),
        send_time,
        sent.load(Ordering::Relaxed) as f64 / send_time.max(0.001)
    );
    if found.is_empty() && nat {
        eprintln!("{warn} 0 respuestas: el NAT de WSL2 suele descartar los SYN-ACK. Usa --mode connect.");
    }
    save(&c, &found);
}

fn die(msg: String) -> ! {
    eprintln!("error: {msg}");
    process::exit(2)
}

fn main() {
    let args = std::env::args().map(|a| match a.as_str() {
        "-oi" => "--oi".to_string(),
        "-op" => "--op".to_string(),
        _ => a,
    });
    let cli = Cli::parse_from(args);
    let common = cli.common;
    match (cli.address, cli.cmd) {
        (Some(target), None) => {
            let ports = parse_ports(common.ports.as_deref().unwrap_or("1-65535")).unwrap_or_else(|e| die(e));
            let r = parse_target(&target).unwrap_or_else(|e| die(e));
            run(Job { total_ips: r.1, ranges: vec![r], excl: vec![], ports }, common);
        }
        (None, Some(Cmd::Range { targets, exclude })) => {
            if targets.is_empty() {
                die("indica al menos un objetivo".into());
            }
            let ports = parse_ports(common.ports.as_deref().unwrap_or(COMMON_PORTS)).unwrap_or_else(|e| die(e));
            let ranges: Vec<_> = targets.iter().map(|t| parse_target(t).unwrap_or_else(|e| die(e))).collect();
            let excl: Vec<_> = exclude.iter().map(|t| parse_target(t).unwrap_or_else(|e| die(e))).collect();
            let total_ips = ranges.iter().map(|r| r.1).sum();
            run(Job { ranges, excl, ports, total_ips }, common);
        }
        (Some(_), Some(_)) => die("usa -a <objetivo> o el subcomando 'range', no los dos a la vez".into()),
        (None, None) => {
            // Sin argumentos: banner animado + ayuda, igual que --help.
            show_banner(&common);
            let _ = Cli::command().print_help();
            println!();
        }
    }
}