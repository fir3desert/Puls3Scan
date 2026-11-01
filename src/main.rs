//! Puls3Scan: escáner de puertos rápido con dos motores:
//!   * SYN stateless (estilo masscan): raw sockets, cookies SYN, filtro BPF en el kernel.
//!   * connect() asíncrono con epoll (estilo RustScan, pero sin hilos por conexión).
//!
//! Dos modos de uso:
//!   -a <ip|dominio|cidr>  -> un objetivo (un host: todos los puertos por defecto)
//!   range <cidr>...       -> rangos grandes, orden pseudoaleatorio
//!
//! El escaneo arranca a la vez que la animación del banner; los resultados se
//! muestran en cuanto la animación termina (o al instante si no hay animación).
//! SYN requiere root o CAP_NET_RAW (si no hay permisos, en modo auto cae a connect).
//! Úsalo solo contra redes que tengas autorización para escanear.

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use ipnetwork::Ipv4Network;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use std::{fs, process, thread};

const COMMON_PORTS: &str =
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443";

/// Tras el último envío SYN: si ya hubo respuestas y pasa este tiempo sin ninguna
/// nueva, se termina sin esperar el `--wait-ms` completo.
const QUIET_MS: u64 = 400;

#[derive(Parser)]
#[command(name = "pscan", about = "Puls3Scan: escáner de puertos rápido (SYN stateless + connect con epoll)")]
struct Cli {
    /// Escanea un objetivo: IP, dominio o red CIDR (p. ej. 192.168.0.0/23).
    /// Un solo host: todos los puertos; una red: puertos comunes (salvo -p)
    #[arg(short = 'a', long = "address", value_name = "IP|DOMINIO|CIDR")]
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
    /// SYN en crudo si es posible; connect() en WSL2 con NAT o si no hay permisos de root
    Auto,
    /// SYN stateless (rápido; requiere root y red "real")
    Syn,
    /// connect() asíncrono con epoll (funciona a través de NAT/WSL2 y sin root)
    Connect,
}

#[derive(Args)]
struct Common {
    /// Puertos: "-p 22", "-p 80,443,8000-9000"; "-p" sin valor = todos (1-65535).
    /// Sin -p: un solo host = todos; red/rango (-a CIDR o range) = puertos comunes
    #[arg(global = true, short, long, num_args = 0..=1, default_missing_value = "1-65535")]
    ports: Option<String>,
    /// Paquetes por segundo en modo syn (por defecto: 100000)
    #[arg(global = true, short, long)]
    rate: Option<u64>,
    /// Método de escaneo
    #[arg(global = true, long, value_enum, default_value_t = Mode::Auto)]
    mode: Mode,
    /// Sockets simultáneos en modo connect (como el batch de RustScan; se limita al ulimit)
    #[arg(global = true, short = 'b', long, visible_alias = "workers", default_value_t = 8000)]
    batch: usize,
    /// Timeout por conexión en modo connect (ms). En LAN/localhost puedes bajarlo a 200-300
    #[arg(global = true, long, default_value_t = 1000)]
    timeout_ms: u64,
    /// Hilos: de envío en modo syn, motores epoll en modo connect
    #[arg(global = true, short, long, default_value_t = 2)]
    threads: usize,
    /// Espera máxima de respuestas tras el último envío SYN (ms). Se acorta sola si
    /// ya hubo respuestas y luego hay 400 ms de silencio
    #[arg(global = true, long, default_value_t = 1200)]
    wait_ms: u64,
    /// Reintentos (pasadas extra en syn; reintentos por timeout en connect)
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
    /// Muestra detalles del escaneo (modo, sockets, avisos de WSL2...)
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

// ---------- Salida compartida ----------
//
// El escaneo corre a la vez que la animación del banner. La animación redibuja
// el banner subiendo el cursor, así que nada más puede escribir en pantalla
// mientras dura: `Out` encola las líneas y las vuelca (en orden) cuando acaba.

struct OutState {
    animating: bool,
    queue: Vec<(bool, String)>, // (es_stderr, texto)
}

struct Out {
    st: Mutex<OutState>,
    /// ¿colorear stdout / stderr?
    oc: bool,
    ec: bool,
}

impl Out {
    fn new() -> Arc<Out> {
        Arc::new(Out {
            st: Mutex::new(OutState { animating: false, queue: Vec::new() }),
            oc: color_on(std::io::stdout().is_terminal()),
            ec: color_on(std::io::stderr().is_terminal()),
        })
    }
    fn lock(&self) -> MutexGuard<'_, OutState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn write(is_err: bool, s: &str) {
        if is_err {
            write_stderr(&format!("{s}\n"));
        } else {
            let mut o = std::io::stdout().lock();
            let _ = writeln!(o, "{s}"); // sin panic si el pipe se cierra (| head)
        }
    }
    fn emit(&self, is_err: bool, s: String) {
        let mut g = self.lock();
        if g.animating {
            g.queue.push((is_err, s));
        } else {
            Self::write(is_err, &s);
        }
    }
    /// Línea de resultado (stdout).
    fn line(&self, s: String) {
        self.emit(false, s);
    }
    /// Línea informativa (stderr).
    fn err(&self, s: String) {
        self.emit(true, s);
    }
    fn begin_anim(&self) {
        self.lock().animating = true;
    }
    fn end_anim(&self) {
        let mut g = self.lock();
        g.animating = false;
        for (e, s) in g.queue.drain(..) {
            Self::write(e, &s);
        }
    }
}

/// Garantiza que la cola se vuelque aunque el hilo de la animación falle.
struct EndAnim(Arc<Out>);
impl Drop for EndAnim {
    fn drop(&mut self) {
        self.0.end_anim();
    }
}

fn hit_line(ip: Ipv4Addr, port: u16, color: bool) -> String {
    let sep = if color { "\x1b[2m:\x1b[0m" } else { ":" };
    format!("{}{}{}", paint_ip(ip, color), sep, paint_port(port, color))
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

/// Cookie sin SipHash: dos rondas de splitmix con la clave secreta de la ejecución.
#[inline]
fn cookie(secret: u64, ip: u32, dport: u16, sport: u16) -> u32 {
    let mut x = secret ^ (((ip as u64) << 32) | ((dport as u64) << 16) | (sport as u64));
    let a = splitmix(&mut x);
    let mut y = a ^ secret.rotate_left(32);
    splitmix(&mut y) as u32
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
██████╗ ██╗   ██╗██╗     ███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██║   ██║██║     ██╔════╝╚════██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝██║   ██║██║     ███████╗ █████╔╝███████╗██║     ███████║██╔██╗ ██║
██╔═══╝ ██║   ██║██║     ╚════██║ ╚═══██╗╚════██║██║     ██╔══██║██║╚██╗██║
██║     ╚██████╔╝███████╗███████║██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"#;

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
// frame final queda impreso como banner estático. Corre en su propio hilo
// MIENTRAS el escaneo ya está en marcha. Si el escaneo termina antes que la ola
// de brillo, la ola se corta y se deja el banner final (el barrido siempre se
// ve completo). Todo es cosmético: ningún fallo de terminal aborta el escaneo.

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
/// únicamente funciones async-signal-safe).
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
/// letras y (2) ola de brillo diagonal que se va apagando hasta dejar el
/// degradado final. Redibuja el banner subiendo el cursor al inicio en cada
/// frame; el último frame (banner completo) queda impreso con el cursor justo
/// debajo. Si `scan_done` se activa durante la ola, salta al frame final.
fn animate_banner(ms: u64, phrase: &str, scan_done: &AtomicBool) {
    let lines = banner_lines();
    let width = banner_width(&lines);
    let up = lines.len() + EXTRA_ROWS;
    let sweep = (ms * ANIM_FPS / 1000).max(2);
    let wave = (WAVE_MS * ANIM_FPS / 1000).max(2);
    let frame_dur = Duration::from_micros(1_000_000 / ANIM_FPS);
    let _guard = CursorGuard::hide();
    let start = Instant::now();
    for n in 0..=(sweep + wave) {
        let finish_now = n > sweep && scan_done.load(Ordering::Relaxed);
        let (reveal, w) = if finish_now {
            (1.0, (0.0, 0.0))
        } else if n <= sweep {
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
        if !write_stderr(&f) || finish_now {
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

/// Punto de entrada del banner. Solo stderr y solo si es un TTY. Si hay
/// animación, arranca en un HILO y devuelve su handle: el llamador puede lanzar
/// el escaneo de inmediato y hacer `join` cuando termine. Mientras la animación
/// vive, `out` encola todo lo que se imprima. Sin animación el banner se
/// imprime al instante (estático) y devuelve None.
fn start_banner(c: &Common, out: &Arc<Out>, scan_done: &Arc<AtomicBool>) -> Option<thread::JoinHandle<()>> {
    if c.no_banner || !std::io::stderr().is_terminal() {
        return None;
    }
    let color = color_on(true); // NO_COLOR => banner plano, sin animación
    let lines = banner_lines();
    let (width, height) = (banner_width(&lines), lines.len() + EXTRA_ROWS);
    let phrase = random_phrase();
    if anim_allowed(c, color, width, height) {
        out.begin_anim(); // antes de lanzar el hilo: sin carreras con el escaneo
        let (out, done, ms) = (out.clone(), scan_done.clone(), c.anim_ms);
        Some(thread::spawn(move || {
            let _end = EndAnim(out);
            write_stderr("\n");
            animate_banner(ms, phrase, &done);
        }))
    } else {
        write_stderr("\n");
        print_banner(color, phrase);
        None
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

// ---------- Trabajo a repartir ----------

struct Job {
    ranges: Vec<(u32, u64)>,
    /// Índice acumulado donde empieza cada rango (para buscar por bisección).
    cum: Vec<u64>,
    /// Exclusiones normalizadas: [inicio, fin) ordenadas y sin solapes.
    excl: Vec<(u64, u64)>,
    ports: Vec<u16>,
    total_ips: u64,
}

impl Job {
    fn new(ranges: Vec<(u32, u64)>, excl: Vec<(u32, u64)>, ports: Vec<u16>) -> Job {
        let mut cum = Vec::with_capacity(ranges.len());
        let mut acc = 0u64;
        for r in &ranges {
            cum.push(acc);
            acc += r.1;
        }
        let mut ex: Vec<(u64, u64)> = excl.iter().map(|&(s, c)| (s as u64, s as u64 + c)).collect();
        ex.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ex.len());
        for (s, e) in ex {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        Job { ranges, cum, excl: merged, ports, total_ips: acc }
    }
    /// IP número `idx` del espacio de objetivos (búsqueda binaria, O(log n)).
    #[inline]
    fn ip_at(&self, idx: u64) -> u32 {
        let k = self.cum.partition_point(|&c| c <= idx) - 1;
        self.ranges[k].0.wrapping_add((idx - self.cum[k]) as u32)
    }
    #[inline]
    fn is_excluded(&self, ip: u32) -> bool {
        if self.excl.is_empty() {
            return false;
        }
        let ip = ip as u64;
        let k = self.excl.partition_point(|&(s, _)| s <= ip);
        k > 0 && ip < self.excl[k - 1].1
    }
}

// ---------- Raw sockets (SYN) ----------

#[cfg(target_os = "linux")]
mod raw {
    use std::net::Ipv4Addr;
    use std::os::raw::c_void;

    pub struct RawSock(pub i32);
    impl Drop for RawSock {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    fn open() -> Result<RawSock, String> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_TCP) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(RawSock(fd))
    }

    /// Filtro BPF clásico: el kernel descarta lo que no pase, sin copiarlo a userspace.
    fn attach(fd: i32, prog: &mut [libc::sock_filter]) {
        let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const _ as *const c_void,
                std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            );
        }
    }

    fn ins(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    /// Socket de envío: no necesita recibir nada (filtro "descartar todo"), así
    /// el kernel no copia cada respuesta TCP a los sockets de los hilos emisores.
    pub fn send_sock() -> Result<RawSock, String> {
        let s = open()?;
        attach(s.0, &mut [ins(0x06, 0, 0, 0)]); // ret 0
        Ok(s)
    }

    /// Socket de recepción: solo SYN+ACK (los RST de los puertos cerrados no
    /// llegan nunca a userspace), buffer de 32 MB y timeout de 20 ms en recv.
    pub fn recv_sock() -> Result<RawSock, String> {
        let s = open()?;
        let mut prog = [
            ins(0xb1, 0, 0, 0),    // ldx 4*([0]&0xf)   -> X = longitud de la cabecera IP
            ins(0x50, 0, 0, 13),   // ldb [x+13]         -> flags TCP
            ins(0x54, 0, 0, 0x12), // and #0x12          -> SYN|ACK
            ins(0x15, 0, 1, 0x12), // jeq #0x12 ? sig : saltar
            ins(0x06, 0, 0, 0xffff), // ret 65535 (aceptar)
            ins(0x06, 0, 0, 0),    // ret 0 (descartar)
        ];
        attach(s.0, &mut prog);
        unsafe {
            let sz: libc::c_int = 32 << 20;
            let p = &sz as *const _ as *const c_void;
            let l = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            if libc::setsockopt(s.0, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, p, l) != 0 {
                libc::setsockopt(s.0, libc::SOL_SOCKET, libc::SO_RCVBUF, p, l);
            }
            let tv = libc::timeval { tv_sec: 0, tv_usec: 20_000 };
            libc::setsockopt(
                s.0,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        Ok(s)
    }

    /// Envía un segmento TCP. 0 = ok; si no, el errno.
    #[inline]
    pub fn send_to(fd: i32, buf: &[u8], dst: Ipv4Addr) -> i32 {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(dst.octets()) },
            sin_zero: [0; 8],
        };
        let r = unsafe {
            libc::sendto(
                fd,
                buf.as_ptr() as *const c_void,
                buf.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if r < 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) } else { 0 }
    }

    #[inline]
    pub fn recv(fd: i32, buf: &mut [u8]) -> isize {
        unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) }
    }

    pub fn is_retryable(errno: i32) -> bool {
        errno == libc::ENOBUFS || errno == libc::EAGAIN || errno == libc::EINTR
    }
}

#[cfg(not(target_os = "linux"))]
mod raw {
    use std::net::Ipv4Addr;
    pub struct RawSock(pub i32);
    pub fn send_sock() -> Result<RawSock, String> {
        Err("el modo syn en crudo solo está soportado en Linux".into())
    }
    pub fn recv_sock() -> Result<RawSock, String> {
        Err("el modo syn en crudo solo está soportado en Linux".into())
    }
    pub fn send_to(_: i32, _: &[u8], _: Ipv4Addr) -> i32 {
        -1
    }
    pub fn recv(_: i32, _: &mut [u8]) -> isize {
        -1
    }
    pub fn is_retryable(_: i32) -> bool {
        false
    }
}

// ---------- Motor SYN ----------

#[allow(clippy::too_many_arguments)]
fn sender(
    id: usize,
    nthreads: usize,
    job: Arc<Job>,
    perm: Arc<Perm>,
    sock: raw::RawSock,
    src: Ipv4Addr,
    secret: u64,
    rate: u64,
    retries: u32,
    sent: Arc<AtomicU64>,
) {
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
            let ip = job.ip_at(x / np);
            let port = job.ports[(x % np) as usize];
            if job.is_excluded(ip) {
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

            // Si el buffer de envío del kernel se llena (ENOBUFS), espera un poco y reintenta.
            let mut tries = 0;
            loop {
                let e = raw::send_to(sock.0, &buf, dst);
                if e == 0 || !raw::is_retryable(e) || tries >= 8 {
                    break;
                }
                tries += 1;
                thread::sleep(Duration::from_micros(200));
            }

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

/// Receptor SYN: lee solo SYN+ACK (el filtro BPF ya descartó el resto), valida la
/// cookie y publica cada puerto abierto en cuanto llega.
fn receiver(
    sock: raw::RawSock,
    stop: Arc<AtomicBool>,
    secret: u64,
    out: Arc<Out>,
    t0: Instant,
    last_ack: Arc<AtomicU64>,
) -> Vec<(Ipv4Addr, u16)> {
    let mut buf = vec![0u8; 4096];
    let mut seen: HashSet<(u32, u16)> = HashSet::new();
    let mut found = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let n = raw::recv(sock.0, &mut buf);
        if n < 40 {
            continue; // timeout (20 ms) o error: reintenta y mira `stop`
        }
        let p = &buf[..n as usize];
        if p[0] >> 4 != 4 || p[9] != 6 {
            continue;
        }
        let ihl = ((p[0] & 0x0f) as usize) * 4;
        if (n as usize) < ihl + 20 {
            continue;
        }
        let t = &p[ihl..];
        if t[13] & 0x12 != 0x12 {
            continue;
        }
        let dport = u16::from_be_bytes([t[0], t[1]]); // puerto del objetivo
        let sport = u16::from_be_bytes([t[2], t[3]]); // nuestro puerto de origen
        let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
        let ipn = u32::from_be_bytes([p[12], p[13], p[14], p[15]]);
        if sport != src_port_for(cookie(secret, ipn, dport, 0)) {
            continue;
        }
        if ack != cookie(secret, ipn, dport, sport).wrapping_add(1) {
            continue;
        }
        last_ack.store(t0.elapsed().as_millis() as u64 + 1, Ordering::Relaxed);
        if seen.insert((ipn, dport)) {
            let ip = Ipv4Addr::from(ipn);
            out.line(hit_line(ip, dport, out.oc));
            found.push((ip, dport));
        }
    }
    found
}

// ---------- Motor connect ----------

/// Linux: connect() no bloqueante + epoll. Miles de sockets en vuelo por hilo,
/// sin un hilo por conexión.
#[cfg(target_os = "linux")]
mod connect_engine {
    use super::*;
    use std::collections::VecDeque;
    use std::os::raw::c_void;

    struct Slot {
        fd: i32,
        ip: u32,
        port: u16,
        tries: u32,
        gen: u32,
        active: bool,
    }

    enum Start {
        Pending(i32),
        Open(i32),
        Closed,
        /// Sin recursos (fds / puertos efímeros / memoria): reducir la concurrencia.
        Backoff,
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// Sube el límite de ficheros abiertos al máximo permitido y lo devuelve.
    pub fn nofile_limit() -> usize {
        unsafe {
            let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
                return 1024;
            }
            let want = rl.rlim_max.min(1_048_576);
            if rl.rlim_cur < want {
                let n = libc::rlimit { rlim_cur: want, rlim_max: rl.rlim_max };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &n) == 0 {
                    rl.rlim_cur = want;
                }
            }
            rl.rlim_cur as usize
        }
    }

    /// Auto-connect de loopback: si el puerto de origen que eligió el kernel coincide
    /// con el de destino, la conexión se "conecta consigo misma" (falso positivo).
    fn is_self_connect(fd: i32, ip: u32, port: u16) -> bool {
        unsafe {
            let mut a: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockname(fd, &mut a as *mut _ as *mut libc::sockaddr, &mut len) != 0 {
                return false;
            }
            a.sin_port == port.to_be() && a.sin_addr.s_addr == u32::from_ne_bytes(ip.to_be_bytes())
        }
    }

    fn start_connect(ip: u32, port: u16) -> Start {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Start::Backoff;
            }
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip.to_be_bytes()) },
                sin_zero: [0; 8],
            };
            let r = libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            if r == 0 {
                return Start::Open(fd);
            }
            match errno() {
                libc::EINPROGRESS => Start::Pending(fd),
                libc::EADDRNOTAVAIL | libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EAGAIN => {
                    libc::close(fd);
                    Start::Backoff
                }
                _ => {
                    // ECONNREFUSED inmediato (loopback), red inalcanzable, etc.
                    libc::close(fd);
                    Start::Closed
                }
            }
        }
    }

    pub fn scan(
        job: Arc<Job>,
        perm: Arc<Perm>,
        batch: usize,
        nthreads: usize,
        timeout: Duration,
        retries: u32,
        out: Arc<Out>,
    ) -> Vec<(Ipv4Addr, u16)> {
        let per = (batch / nthreads).max(1);
        let handles: Vec<_> = (0..nthreads)
            .map(|id| {
                let (job, perm, out) = (job.clone(), perm.clone(), out.clone());
                thread::spawn(move || engine(id, nthreads, job, perm, per, timeout, retries, out))
            })
            .collect();
        let mut all = Vec::new();
        for h in handles {
            if let Ok(mut v) = h.join() {
                all.append(&mut v);
            }
        }
        all
    }

    #[allow(clippy::too_many_arguments)]
    fn engine(
        id: usize,
        nthreads: usize,
        job: Arc<Job>,
        perm: Arc<Perm>,
        batch: usize,
        timeout: Duration,
        retries: u32,
        out: Arc<Out>,
    ) -> Vec<(Ipv4Addr, u16)> {
        let np = job.ports.len() as u64;
        let total = job.total_ips * np;
        let mut found: Vec<(Ipv4Addr, u16)> = Vec::new();

        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if ep < 0 {
            out.err(format!("[!] epoll_create1 falló (errno {})", errno()));
            return found;
        }

        let mut slots: Vec<Slot> = Vec::with_capacity(batch);
        let mut free: Vec<usize> = Vec::new();
        // Todos los timeouts son iguales => los vencimientos salen ordenados (cola FIFO).
        let mut deadlines: VecDeque<(usize, u32, Instant)> = VecDeque::new();
        let mut retry_q: Vec<(u32, u16, u32)> = Vec::new(); // (ip, puerto, intentos hechos)
        let mut next_i = id as u64;
        let mut inflight = 0usize;
        let mut cap = batch; // concurrencia actual (baja si el SO se queda sin recursos)
        let mut stalls = 0u32;
        let mut gen_counter = 0u32;
        let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; 1024];

        let hit = |found: &mut Vec<(Ipv4Addr, u16)>, ip: u32, port: u16| {
            let ipa = Ipv4Addr::from(ip);
            out.line(hit_line(ipa, port, out.oc));
            found.push((ipa, port));
        };

        loop {
            // 1) Rellenar hasta `cap` sockets en vuelo.
            let mut backoff = false;
            let now = Instant::now();
            while inflight < cap {
                let (ip, port, tries) = match retry_q.pop() {
                    Some(p) => p,
                    None => {
                        let mut got = None;
                        while next_i < total {
                            let x = perm.get(next_i);
                            next_i += nthreads as u64;
                            let ip = job.ip_at(x / np);
                            if job.is_excluded(ip) {
                                continue;
                            }
                            got = Some((ip, job.ports[(x % np) as usize], 0u32));
                            break;
                        }
                        match got {
                            Some(g) => g,
                            None => break, // no quedan sondas
                        }
                    }
                };
                match start_connect(ip, port) {
                    Start::Pending(fd) => {
                        gen_counter = gen_counter.wrapping_add(1);
                        let slot = Slot { fd, ip, port, tries, gen: gen_counter, active: true };
                        let idx = match free.pop() {
                            Some(i) => {
                                slots[i] = slot;
                                i
                            }
                            None => {
                                slots.push(slot);
                                slots.len() - 1
                            }
                        };
                        let mut ev = libc::epoll_event {
                            events: (libc::EPOLLOUT | libc::EPOLLERR | libc::EPOLLHUP) as u32,
                            u64: ((gen_counter as u64) << 32) | idx as u64,
                        };
                        if unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) } != 0 {
                            unsafe { libc::close(fd) };
                            slots[idx].active = false;
                            free.push(idx);
                            retry_q.push((ip, port, tries));
                            backoff = true;
                            break;
                        }
                        inflight += 1;
                        deadlines.push_back((idx, gen_counter, now + timeout));
                    }
                    Start::Open(fd) => {
                        let selfc = is_self_connect(fd, ip, port);
                        unsafe { libc::close(fd) };
                        if !selfc {
                            hit(&mut found, ip, port);
                        }
                    }
                    Start::Closed => {}
                    Start::Backoff => {
                        retry_q.push((ip, port, tries));
                        backoff = true;
                        break;
                    }
                }
            }
            if backoff {
                cap = inflight.max(1).min(cap);
                if inflight == 0 {
                    stalls += 1;
                    if stalls > 400 {
                        out.err("[!] no se pueden abrir sockets (límite de ficheros o de puertos efímeros)".into());
                        break;
                    }
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
            } else {
                stalls = 0;
                if cap < batch {
                    cap = (cap + 64).min(batch); // recupera concurrencia poco a poco
                }
            }
            if inflight == 0 {
                break; // sin sockets en vuelo y sin sondas pendientes: terminado
            }

            // 2) Esperar eventos hasta el próximo vencimiento (máx. 50 ms).
            let wait_ms = match deadlines.front() {
                Some(&(_, _, d)) => {
                    let us = d.saturating_duration_since(Instant::now()).as_micros() as i64;
                    ((us + 999) / 1000).min(50) as i32
                }
                None => 50,
            };
            let n = unsafe { libc::epoll_wait(ep, events.as_mut_ptr(), events.len() as i32, wait_ms) };
            if n < 0 {
                if errno() == libc::EINTR {
                    continue;
                }
                break;
            }

            // 3) Conexiones completadas.
            for e in &events[..n as usize] {
                let data = e.u64;
                let idx = (data & 0xffff_ffff) as usize;
                let gen = (data >> 32) as u32;
                if idx >= slots.len() || !slots[idx].active || slots[idx].gen != gen {
                    continue;
                }
                let (fd, ip, port) = (slots[idx].fd, slots[idx].ip, slots[idx].port);
                let mut err: libc::c_int = 0;
                let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                let r = unsafe {
                    libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut _ as *mut c_void, &mut len)
                };
                let open = r == 0 && err == 0 && !is_self_connect(fd, ip, port);
                unsafe { libc::close(fd) }; // cerrar el fd lo quita del epoll
                slots[idx].active = false;
                free.push(idx);
                inflight -= 1;
                if open {
                    hit(&mut found, ip, port);
                }
                // ECONNREFUSED / ICMP inalcanzable: cerrado, no se reintenta.
            }

            // 4) Vencimientos (puertos filtrados o sin respuesta).
            let now = Instant::now();
            while let Some(&(idx, gen, d)) = deadlines.front() {
                if d > now {
                    break;
                }
                deadlines.pop_front();
                if !slots[idx].active || slots[idx].gen != gen {
                    continue; // ya resuelto
                }
                let (fd, ip, port, tries) = (slots[idx].fd, slots[idx].ip, slots[idx].port, slots[idx].tries);
                unsafe { libc::close(fd) };
                slots[idx].active = false;
                free.push(idx);
                inflight -= 1;
                if tries < retries {
                    retry_q.push((ip, port, tries + 1));
                }
            }
        }

        for s in slots.iter().filter(|s| s.active) {
            unsafe { libc::close(s.fd) };
        }
        unsafe { libc::close(ep) };
        found
    }
}

/// Resto de sistemas: fallback con un hilo por conexión (más lento).
#[cfg(not(target_os = "linux"))]
mod connect_engine {
    use super::*;
    use std::net::{SocketAddr, TcpStream};

    pub fn nofile_limit() -> usize {
        1024
    }

    pub fn scan(
        job: Arc<Job>,
        perm: Arc<Perm>,
        batch: usize,
        _nthreads: usize,
        timeout: Duration,
        retries: u32,
        out: Arc<Out>,
    ) -> Vec<(Ipv4Addr, u16)> {
        let np = job.ports.len() as u64;
        let total = job.total_ips * np;
        let next = Arc::new(AtomicU64::new(0));
        let found: Arc<Mutex<Vec<(Ipv4Addr, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let handles: Vec<_> = (0..batch.min(900))
            .map(|_| {
                let (job, perm, next, found, out) = (job.clone(), perm.clone(), next.clone(), found.clone(), out.clone());
                thread::spawn(move || loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    let x = perm.get(i);
                    let ip = job.ip_at(x / np);
                    let port = job.ports[(x % np) as usize];
                    if job.is_excluded(ip) {
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
                            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,
                            Err(_) => continue,
                        }
                    }
                    if open {
                        out.line(hit_line(ipa, port, out.oc));
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
        let v = found.lock().map(|g| g.clone()).unwrap_or_default();
        v
    }
}

// ---------- Utilidades ----------

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

fn save(c: &Common, found: &[(Ipv4Addr, u16)]) {
    let write = |path: &str, text: String| {
        if let Err(e) = fs::write(path, text) {
            write_stderr(&format!("no se pudo escribir {path}: {e}\n"));
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

/// Restaura el cursor (por si la animación lo ocultó) y sale con error.
fn die(msg: String) -> ! {
    if std::io::stderr().is_terminal() {
        write_stderr(CURSOR_SHOW);
    }
    write_stderr(&format!("error: {msg}\n"));
    process::exit(2)
}

// ---------- Ejecución ----------

fn run(job: Job, c: Common) {
    let out = Out::new();
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
    let nthreads = c.threads.max(1);

    let ec = out.ec;
    let tag = if ec { "\x1b[1;32m[+]\x1b[0m" } else { "[+]" };
    let info = if ec { "\x1b[1;38;2;255;106;0m[~]\x1b[0m" } else { "[~]" };
    let warn = if ec { "\x1b[1;33m[!]\x1b[0m" } else { "[!]" };

    // WSL2 en modo NAT: la IP de origen es 172.16/12 (red virtual de Hyper-V) y el destino es otra red.
    let nat = is_wsl() && is_private_172(src) && !is_private_172(first);
    let mut use_connect = match c.mode {
        Mode::Connect => true,
        Mode::Syn => false,
        Mode::Auto => nat,
    };

    // Los raw sockets se abren ANTES de arrancar la animación: si fallan, el aviso
    // (o el error) sale limpio, y en modo auto se cae a connect() en vez de abortar.
    let mut socks: Option<(raw::RawSock, Vec<raw::RawSock>)> = None;
    let mut notes: Vec<String> = Vec::new();
    if !use_connect {
        let opened = raw::recv_sock().and_then(|rx| {
            let txs = (0..nthreads).map(|_| raw::send_sock()).collect::<Result<Vec<_>, _>>()?;
            Ok((rx, txs))
        });
        match opened {
            Ok(s) => socks = Some(s),
            Err(e) if c.mode == Mode::Auto => {
                use_connect = true;
                notes.push(format!("{warn} sin raw sockets ({e}): uso connect(). Para SYN ejecuta con sudo o CAP_NET_RAW."));
            }
            Err(e) => die(format!("error abriendo raw socket (¿root / CAP_NET_RAW?): {e}")),
        }
    }

    // El escaneo arranca YA; el banner se anima en paralelo (los resultados se encolan).
    let scan_done = Arc::new(AtomicBool::new(false));
    let banner = start_banner(&c, &out, &scan_done);

    for n in notes {
        out.err(n);
    }
    // Como RustScan: por defecto solo el destino. El resto, con --verbose.
    out.err(format!("{info} Objetivo: {}", target_label(&job)));
    if c.verbose {
        if nat && use_connect && c.mode == Mode::Auto {
            out.err(format!("{warn} WSL2 en modo NAT (origen {src}, destino {first}): los SYN en crudo no atraviesan bien el NAT de Windows."));
            out.err("    Uso escaneo connect(). Para SYN real: 'networkingMode=mirrored' en %UserProfile%\\.wslconfig y 'wsl --shutdown'.".into());
        } else if nat && !use_connect {
            out.err(format!("{warn} WSL2 en modo NAT: el escaneo SYN puede no recibir respuestas de {first}. Prueba --mode connect."));
        }
    }

    // ---- connect() con epoll ----
    if use_connect {
        let limit = connect_engine::nofile_limit();
        let max_batch = limit.saturating_sub(64 + nthreads * 2).max(1);
        let batch = c.batch.clamp(1, max_batch);
        let timeout = Duration::from_millis(c.timeout_ms.max(20));
        if c.verbose {
            out.err(format!(
                "[*] {} IPs x {} puertos = {} sondas | modo connect (epoll) | {} sockets en vuelo ({} hilos) | timeout {} ms | ulimit {}",
                job.total_ips,
                job.ports.len(),
                total * (c.retries as u64 + 1),
                batch,
                nthreads,
                c.timeout_ms,
                limit
            ));
            if batch < c.batch {
                out.err(format!("{warn} batch limitado a {batch} por el límite de ficheros abiertos (ulimit -n)."));
            }
        }
        let perm = Arc::new(Perm::new(total, seed));
        let job = Arc::new(job);
        let t0 = Instant::now();
        let mut found = connect_engine::scan(job, perm, batch, nthreads, timeout, c.retries, out.clone());
        let secs = t0.elapsed().as_secs_f64();
        finish(&scan_done, banner);
        found.sort();
        out.err(format!("{tag} {} abiertos | {} sondas en {:.2}s", found.len(), total, secs));
        save(&c, &found);
        return;
    }

    // ---- SYN stateless ----
    let (rx_sock, tx_socks) = socks.expect("raw sockets abiertos");
    let rate = c.rate.unwrap_or(100_000);
    if c.verbose {
        out.err(format!(
            "[*] {} IPs x {} puertos = {} sondas | modo syn | rate {} pps | {} hilos | src {}",
            job.total_ips,
            job.ports.len(),
            total * (c.retries as u64 + 1),
            rate,
            nthreads,
            src
        ));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let last_ack = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let rcv = {
        let (stop, out, last_ack) = (stop.clone(), out.clone(), last_ack.clone());
        thread::spawn(move || receiver(rx_sock, stop, secret, out, t0, last_ack))
    };

    let sent = Arc::new(AtomicU64::new(0));
    let job = Arc::new(job);
    let perm = Arc::new(Perm::new(total, seed));
    let handles: Vec<_> = tx_socks
        .into_iter()
        .enumerate()
        .map(|(id, sock)| {
            let (job, perm, sent) = (job.clone(), perm.clone(), sent.clone());
            let retries = c.retries;
            thread::spawn(move || sender(id, nthreads, job, perm, sock, src, secret, rate, retries, sent))
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    let send_time = t0.elapsed().as_secs_f64();
    let send_end = Instant::now();

    // Espera adaptativa: máximo `wait_ms`; si ya hubo respuestas y pasan QUIET_MS sin
    // ninguna nueva (y han pasado QUIET_MS desde el último envío), se termina.
    let max_wait = Duration::from_millis(c.wait_ms);
    let quiet = Duration::from_millis(QUIET_MS.min(c.wait_ms));
    if c.verbose {
        out.err(format!("[*] envío terminado, esperando hasta {} ms respuestas...", c.wait_ms));
    }
    loop {
        let el = send_end.elapsed();
        if el >= max_wait {
            break;
        }
        let last = last_ack.load(Ordering::Relaxed);
        if last > 0 && el >= quiet && (t0 + Duration::from_millis(last - 1)).elapsed() >= quiet {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    let mut found = rcv.join().unwrap_or_default();
    found.sort();
    finish(&scan_done, banner);

    let sent = sent.load(Ordering::Relaxed);
    out.err(format!(
        "{} {} abiertos | {} paquetes en {:.2}s (~{:.0} pps)",
        tag,
        found.len(),
        sent,
        send_time,
        sent as f64 / send_time.max(0.001)
    ));
    if found.is_empty() && nat {
        out.err(format!("{warn} 0 respuestas: el NAT de WSL2 suele descartar los SYN-ACK. Usa --mode connect."));
    }
    save(&c, &found);
}

/// El escaneo terminó: avisa a la animación (corta la ola) y espera a que acabe
/// para que vuelque los resultados encolados.
fn finish(scan_done: &Arc<AtomicBool>, banner: Option<thread::JoinHandle<()>>) {
    scan_done.store(true, Ordering::Relaxed);
    if let Some(h) = banner {
        let _ = h.join();
    }
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
            let r = parse_target(&target).unwrap_or_else(|e| die(e));
            // Una red (CIDR con más de una IP) usa puertos comunes por defecto, como 'range'.
            let default_ports = if r.1 > 1 { COMMON_PORTS } else { "1-65535" };
            let ports = parse_ports(common.ports.as_deref().unwrap_or(default_ports)).unwrap_or_else(|e| die(e));
            run(Job::new(vec![r], vec![], ports), common);
        }
        (None, Some(Cmd::Range { targets, exclude })) => {
            if targets.is_empty() {
                die("indica al menos un objetivo".into());
            }
            let ports = parse_ports(common.ports.as_deref().unwrap_or(COMMON_PORTS)).unwrap_or_else(|e| die(e));
            let ranges: Vec<_> = targets.iter().map(|t| parse_target(t).unwrap_or_else(|e| die(e))).collect();
            let excl: Vec<_> = exclude.iter().map(|t| parse_target(t).unwrap_or_else(|e| die(e))).collect();
            run(Job::new(ranges, excl, ports), common);
        }
        (Some(_), Some(_)) => die("usa -a <objetivo> o el subcomando 'range', no los dos a la vez".into()),
        (None, None) => {
            // Sin argumentos: banner animado + ayuda, igual que --help.
            let out = Out::new();
            let done = Arc::new(AtomicBool::new(false));
            if let Some(h) = start_banner(&common, &out, &done) {
                let _ = h.join();
            }
            let _ = Cli::command().print_help();
            println!();
        }
    }
}
