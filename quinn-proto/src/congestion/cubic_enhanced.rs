use std::any::Any;
use std::sync::Arc;

use super::{Controller, ControllerFactory, BASE_DATAGRAM_SIZE};
use crate::connection::RttEstimator;
use crate::{Duration, Instant};

// ── Constants (from mvfst QuicCubic.cpp / QuicConstants.h) ───────────────────

/// CUBIC β: multiplicative cwnd reduction factor after loss.
const CUBIC_BETA: f64 = 0.7;

/// CUBIC β_lastmax: extra backoff when cwnd never recovered to W_max before the
/// next loss (promotes fairness among competing flows).
const CUBIC_LAST_MAX_BETA: f64 = 0.85;

/// CUBIC C scaling constant.  mvfst calls this kTimeScalingFactor = 0.4,
/// with time measured in milliseconds.
const CUBIC_C: f64 = 0.4;

/// TCP-friendly α ≈ 3·(1−β)/(1+β) ≈ 0.5294.
const CUBIC_TCP_ALPHA: f64 = 3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA);

// Hystart constants
/// Minimum ssthresh in packets before the Hystart exit point is honoured.
const HYSTART_LOW_SSTHRESH_PKTS: u64 = 16;
/// AckTrain: maximum inter-ACK gap to consider two ACKs part of the same train.
const HYSTART_ACK_GAP: Duration = Duration::from_micros(2);
/// DelayIncrease: number of ACK samples per RTT round.
const HYSTART_ACK_SAMPLES: u8 = 8;
/// DelayIncrease η lower bound.
const HYSTART_DELAY_LOWER: Duration = Duration::from_millis(4);
/// DelayIncrease η upper bound.
const HYSTART_DELAY_UPPER: Duration = Duration::from_millis(16);

/// Initial congestion window (packets).
const INIT_CWND_PKTS: u64 = 32;
/// Minimum congestion window (packets).
const MIN_CWND_PKTS: u64 = 2;
/// Maximum congestion window (bytes) — 20 MiB.
const MAX_CWND_BYTES: u64 = 20 * 1024 * 1024;

// ── State machine ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CubicState {
    /// Exponential growth with Hystart exit detection.
    Hystart,
    /// CUBIC congestion avoidance.
    Steady,
    /// Fast recovery after a loss event.
    FastRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HystartFound {
    No,
    AckTrain,
    DelayIncrease,
}

// ── Hystart tracker ───────────────────────────────────────────────────────────

/// State for Hybrid Slow Start detection.
///
/// Two detection methods (mirrors mvfst):
///  1. **AckTrain** – consecutive ACKs within HYSTART_ACK_GAP; if the round has
///     lasted ≥ delayMin/2, the exit point has been found.
///  2. **DelayIncrease** – minimum RTT in the current round (first
///     HYSTART_ACK_SAMPLES ACKs) exceeds last round's minimum by η.
#[derive(Debug, Clone)]
struct HystartTracker {
    /// Round boundary: the wall-clock `now` at which this round was started.
    /// The round ends when we ack a packet with `sent > rtt_round_end_target`.
    rtt_round_end_target: Option<Instant>,

    round_start: Option<Instant>,
    last_jiffy: Option<Instant>,

    /// Minimum RTT observed in the **current** round (first HYSTART_ACK_SAMPLES).
    curr_sampled_rtt: Option<Duration>,
    /// Minimum RTT from the **previous** round.
    last_sampled_rtt: Option<Duration>,
    /// Running minimum of all RTTs — used by the AckTrain method.
    delay_min: Option<Duration>,

    ack_count: u8,
    found: HystartFound,
}

impl Default for HystartTracker {
    fn default() -> Self {
        Self {
            rtt_round_end_target: None,
            round_start: None,
            last_jiffy: None,
            curr_sampled_rtt: None,
            last_sampled_rtt: None,
            delay_min: None,
            ack_count: 0,
            found: HystartFound::No,
        }
    }
}

impl HystartTracker {
    fn start_round(&mut self, now: Instant) {
        self.rtt_round_end_target = Some(now);
        self.round_start = Some(now);
        self.last_jiffy = Some(now);
        self.ack_count = 0;
        self.last_sampled_rtt = self.curr_sampled_rtt.take();
        self.found = HystartFound::No;
    }

    /// Returns true if the current Hystart round should end (i.e., the acked
    /// packet was sent after the round started).
    fn round_ended(&self, sent: Instant) -> bool {
        self.rtt_round_end_target.map_or(false, |t| sent > t)
    }

    fn is_active(&self) -> bool {
        self.rtt_round_end_target.is_some()
    }
}

// ── Steady-state (CUBIC) state ────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CubicSteadyState {
    /// K (milliseconds): time for cwnd to grow from its post-loss value back to W_max.
    time_to_origin: f64,
    /// W_max bytes; `None` = never had a loss.
    last_max_cwnd: Option<u64>,
    /// Origin point matching `time_to_origin`.
    origin_point: Option<u64>,

    /// TCP-friendly Reno estimate for cwnd.
    est_reno_cwnd: u64,

    /// Wall-clock time of the last loss/reduction event.
    last_reduction_time: Option<Instant>,
}

impl CubicSteadyState {
    fn new(initial_cwnd: u64) -> Self {
        Self {
            time_to_origin: 0.0,
            last_max_cwnd: None,
            origin_point: None,
            est_reno_cwnd: initial_cwnd,
            last_reduction_time: None,
        }
    }

    /// Recompute K from W_max and current cwnd.
    ///
    ///   K = cbrt( (W_max − cwnd) / MSS × (1/C) × 1000³ )
    ///     = cbrt( bytesToOrigin × 1e6 / MSS × 2500 )   [ms]  (C=0.4)
    fn update_time_to_origin(&mut self, current_cwnd: u64, mtu: u64) {
        let wmax = match self.last_max_cwnd {
            Some(w) if w > current_cwnd => w,
            _ => {
                self.time_to_origin = 0.0;
                self.origin_point = self.last_max_cwnd;
                return;
            }
        };
        let bytes_to_origin = (wmax - current_cwnd) as f64;
        let mss = mtu as f64;
        self.time_to_origin = (bytes_to_origin * 1e6 / mss * 2500.0_f64).cbrt();
        self.origin_point = Some(wmax);
    }

    /// W(t) = W_max + MSS × C × (t_ms − K_ms)³ / 10⁹
    fn cubic_cwnd_delta(&self, now: Instant, mtu: u64) -> i64 {
        let reduction_time = match self.last_reduction_time {
            Some(t) => t,
            None => return 0,
        };
        if now < reduction_time {
            return 0;
        }
        let elapsed = now - reduction_time;
        // Ceiling to milliseconds (mirrors mvfst chrono::ceil<ms>).
        let elapsed_ms =
            (elapsed.as_nanos() as f64 / 1_000_000.0_f64).ceil();
        let diff = elapsed_ms - self.time_to_origin;
        let cubed = diff * diff * diff;
        if cubed.is_infinite() || cubed.is_nan() {
            return if diff > 0.0 { i64::MAX } else { i64::MIN };
        }
        let mss = mtu as f64;
        let delta = mss * CUBIC_C * cubed / 1e9;
        if delta > i64::MAX as f64 {
            i64::MAX
        } else if delta < i64::MIN as f64 {
            i64::MIN
        } else {
            delta as i64
        }
    }
}

// ── CubicEnhanced controller ──────────────────────────────────────────────────

/// Enhanced CUBIC congestion controller following mvfst QuicCubic.cpp.
///
/// Features:
/// - **Hystart** with AckTrain + DelayIncrease slow-start exit detection
/// - **CUBIC** W(t) = C·(t−K)³ + W_max congestion avoidance
/// - **TCP-friendly** Reno estimate: cwnd = max(cubic, reno)
/// - **Fast Recovery** state with recovery-period skipping
/// - **App-idle** quiescence: CUBIC clock is paused when not cwnd-limited
/// - **Persistent congestion** (RTO) reset back to Hystart
#[derive(Debug, Clone)]
pub struct CubicEnhanced {
    config: Arc<CubicEnhancedConfig>,
    window: u64,
    ssthresh: u64,
    current_mtu: u64,

    state: CubicState,
    hystart: HystartTracker,
    steady: CubicSteadyState,

    /// Time when a loss event started recovery.
    /// ACKs for packets with `sent <= recovery_start_time` are still in recovery.
    recovery_start_time: Option<Instant>,

    /// When the sender became app-limited (cwnd not full); `None` = not quiescent.
    quiescence_start: Option<Instant>,
}

impl CubicEnhanced {
    /// Construct a new CubicEnhanced controller.
    pub fn new(config: Arc<CubicEnhancedConfig>, _now: Instant, current_mtu: u16) -> Self {
        let mtu = current_mtu as u64;
        let init_cwnd = INIT_CWND_PKTS * mtu;
        Self {
            window: init_cwnd,
            ssthresh: u64::MAX,
            current_mtu: mtu,
            state: CubicState::Hystart,
            hystart: HystartTracker::default(),
            steady: CubicSteadyState::new(init_cwnd),
            recovery_start_time: None,
            quiescence_start: None,
            config,
        }
    }

    fn min_window(&self) -> u64 {
        MIN_CWND_PKTS * self.current_mtu
    }

    fn max_window(&self) -> u64 {
        MAX_CWND_BYTES
    }

    // ── Hystart ───────────────────────────────────────────────────────────────

    fn on_ack_hystart(&mut self, now: Instant, sent: Instant, latest_rtt: Duration) {
        if !self.hystart.is_active() {
            self.hystart.start_round(now);
        }

        // Exponential growth.
        let bytes = self.current_mtu; // one packet
        self.window = (self.window + bytes).min(self.max_window());

        // Check whether to exit Hystart.
        let exit = if self.window >= self.ssthresh {
            true
        } else if self.hystart.found != HystartFound::No
            && self.window >= HYSTART_LOW_SSTHRESH_PKTS * self.current_mtu
        {
            true
        } else {
            false
        };

        if exit {
            self.hystart.rtt_round_end_target = None;
            self.ssthresh = self.window;
            self.hystart.curr_sampled_rtt = None;
            // Enter Steady with no prior loss.
            self.steady.last_max_cwnd = None;
            self.steady.last_reduction_time = None;
            self.steady.est_reno_cwnd = self.window;
            self.quiescence_start = None;
            self.state = CubicState::Steady;
            return;
        }

        // Advance RTT round boundary.
        if self.hystart.round_ended(sent) {
            self.hystart.rtt_round_end_target = None; // round ended; next ack starts a new one
        }

        // Detection methods only if exit point not yet found.
        if self.hystart.found != HystartFound::No {
            return;
        }

        // Update running minimum RTT.
        self.hystart.delay_min = Some(match self.hystart.delay_min {
            None => latest_rtt,
            Some(d) => d.min(latest_rtt),
        });

        // ── AckTrain ──
        let round_start = match self.hystart.round_start {
            Some(t) => t,
            None => return,
        };
        let last_jiffy = self.hystart.last_jiffy.unwrap_or(now);
        if now - last_jiffy <= HYSTART_ACK_GAP {
            self.hystart.last_jiffy = Some(now);
            if let Some(delay_min) = self.hystart.delay_min {
                if (now - round_start) * 2 >= delay_min {
                    self.hystart.found = HystartFound::AckTrain;
                    return;
                }
            }
        }

        // ── DelayIncrease ──
        if self.hystart.ack_count < HYSTART_ACK_SAMPLES {
            self.hystart.curr_sampled_rtt = Some(match self.hystart.curr_sampled_rtt {
                None => latest_rtt,
                Some(d) => d.min(latest_rtt),
            });
            self.hystart.ack_count += 1;
            if self.hystart.ack_count < HYSTART_ACK_SAMPLES {
                return;
            }
        }
        // We have enough samples; compare to last round.
        let curr = match self.hystart.curr_sampled_rtt {
            Some(d) => d,
            None => return,
        };
        let last = match self.hystart.last_sampled_rtt {
            Some(d) => d,
            None => return, // no previous round yet
        };
        // η = clamp(last / 16, 4ms, 16ms)
        let eta = (last / 16).clamp(HYSTART_DELAY_LOWER, HYSTART_DELAY_UPPER);
        if curr >= last + eta {
            self.hystart.found = HystartFound::DelayIncrease;
        }
    }

    // ── Steady (CUBIC CA) ──────────────────────────────────────────────────

    fn on_ack_steady(&mut self, now: Instant, acked_bytes: u64) {
        // App-idle handling: pause the CUBIC clock.
        // (app_limited is handled by the Controller trait caller — we skip if
        // app_limited in on_ack. Here we also track quiescence via on_end_acks.)
        if let Some(q_start) = self.quiescence_start {
            // Resume: shift lastReductionTime forward by idle duration.
            if let Some(ref mut t) = self.steady.last_reduction_time {
                let idle = now - q_start;
                *t += idle;
            }
            self.quiescence_start = None;
        }

        // On first ACK in Steady (after Hystart, no prior loss), initialise origin.
        if self.steady.last_max_cwnd.is_none() {
            self.steady.last_max_cwnd = Some(self.window);
            self.steady.time_to_origin = 0.0;
            self.steady.origin_point = Some(self.window);
            self.steady.est_reno_cwnd = self.window;
        } else if self.steady.origin_point != self.steady.last_max_cwnd {
            self.steady.update_time_to_origin(self.window, self.current_mtu);
        }

        // Initialise lastReductionTime if not set.
        if self.steady.last_reduction_time.is_none() {
            self.steady.last_reduction_time = Some(now);
        }

        // Compute cubic cwnd.
        let delta = self.steady.cubic_cwnd_delta(now, self.current_mtu);
        let wmax = self.steady.last_max_cwnd.unwrap_or(self.window) as i64;
        let new_cwnd = self.apply_delta(wmax, delta);
        if new_cwnd >= self.window {
            self.window = new_cwnd;
        }

        // TCP-Reno-friendly estimate: estRenoCwnd += α * ackedBytes * MSS / estRenoCwnd
        if acked_bytes > 0 {
            if self.steady.est_reno_cwnd == 0 {
                self.steady.est_reno_cwnd = self.window;
            }
            let inc = (acked_bytes as f64
                * CUBIC_TCP_ALPHA
                * self.current_mtu as f64
                / self.steady.est_reno_cwnd as f64) as u64;
            self.steady.est_reno_cwnd =
                (self.steady.est_reno_cwnd + inc).min(self.max_window());
            self.window = self.window.max(self.steady.est_reno_cwnd);
        }
        self.window = self.window.min(self.max_window());
    }

    fn apply_delta(&self, wmax: i64, delta: i64) -> u64 {
        let max_cwnd = self.max_window() as i64;
        let min_cwnd = self.min_window() as i64;
        if delta > 0 && wmax > max_cwnd - delta {
            return self.max_window();
        }
        if delta < 0 && -delta > wmax - min_cwnd {
            return self.min_window();
        }
        let result = wmax + delta;
        result.clamp(min_cwnd, max_cwnd) as u64
    }

    // ── Fast Recovery ──────────────────────────────────────────────────────

    fn on_ack_recovery(&mut self, now: Instant, sent: Instant, acked_bytes: u64) {
        // Recovery ends when we ack a packet sent after the loss event.
        let recovery_time = match self.recovery_start_time {
            Some(t) => t,
            None => {
                self.state = CubicState::Steady;
                return;
            }
        };
        if sent <= recovery_time {
            return; // still recovering
        }
        // Recovered: transition to Steady.
        self.state = CubicState::Steady;
        self.recovery_start_time = None;

        // Pre-calculate cubic cwnd at the recovery exit point.
        if self.steady.last_max_cwnd.is_some() && self.steady.last_reduction_time.is_some() {
            self.steady.update_time_to_origin(self.window, self.current_mtu);
            let delta = self.steady.cubic_cwnd_delta(now, self.current_mtu);
            let wmax = self.steady.last_max_cwnd.unwrap_or(self.window) as i64;
            self.window = self.apply_delta(wmax, delta);
        }
        // Continue with one normal Steady update.
        self.on_ack_steady(now, acked_bytes);
    }

    // ── Loss / reduction ───────────────────────────────────────────────────

    fn cubic_reduction(&mut self, loss_time: Instant) {
        // Fast convergence: if cwnd < W_max (never recovered), apply extra backoff.
        self.steady.last_max_cwnd = Some(match self.steady.last_max_cwnd {
            Some(w) if self.window < w => {
                (self.window as f64 * CUBIC_LAST_MAX_BETA) as u64
            }
            _ => self.window,
        });
        self.steady.last_reduction_time = Some(loss_time);

        // Reduce cwnd by β.
        let reduced = (self.window as f64 * CUBIC_BETA) as u64;
        self.window = reduced.max(self.min_window());
        self.steady.est_reno_cwnd = self.window;
    }
}

impl Controller for CubicEnhanced {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // Skip if still in recovery window OR app-limited in steady state.
        if let Some(recovery_time) = self.recovery_start_time {
            if self.state == CubicState::FastRecovery && sent <= recovery_time {
                return;
            }
        }

        if app_limited {
            // Track quiescence start for the CUBIC clock.
            if self.state == CubicState::Steady && self.quiescence_start.is_none() {
                self.quiescence_start = Some(now);
            }
            return;
        }

        let latest_rtt = rtt.get();
        if latest_rtt == Duration::ZERO {
            return;
        }

        match self.state {
            CubicState::Hystart => {
                // Start a new round if needed.
                if !self.hystart.is_active() {
                    self.hystart.start_round(now);
                } else if self.hystart.round_ended(sent) {
                    self.hystart.start_round(now);
                }
                self.on_ack_hystart(now, sent, latest_rtt);
            }
            CubicState::Steady => {
                self.on_ack_steady(now, bytes);
            }
            CubicState::FastRecovery => {
                self.on_ack_recovery(now, sent, bytes);
            }
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        // When resuming from app-idle, we shifted lastReductionTime in on_ack_steady.
        // Here we just clear the quiescence marker if we're no longer app-limited.
        if !app_limited {
            self.quiescence_start = None;
        } else if self.state == CubicState::Steady && self.quiescence_start.is_none() {
            self.quiescence_start = Some(now);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // Ignore loss events already within the current recovery window.
        if let Some(recovery_time) = self.recovery_start_time {
            if sent <= recovery_time {
                return;
            }
        }

        self.recovery_start_time = Some(now);

        if is_persistent_congestion {
            // RTO: reset to Hystart.
            let min_cwnd = self.min_window();
            self.ssthresh = (self.window / 2).max(min_cwnd);
            self.window = min_cwnd;
            self.steady.est_reno_cwnd = 0;
            self.steady.last_reduction_time = None;
            self.steady.last_max_cwnd = None;
            self.steady.origin_point = None;
            self.quiescence_start = None;
            self.hystart = HystartTracker::default();
            self.recovery_start_time = None;
            self.state = CubicState::Hystart;
            return;
        }

        self.cubic_reduction(now);
        if self.state == CubicState::Hystart || self.state == CubicState::Steady {
            self.state = CubicState::FastRecovery;
        }
        self.ssthresh = self.window;
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.window = self.window.max(self.min_window());
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INIT_CWND_PKTS * self.current_mtu
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the `CubicEnhanced` congestion controller.
#[derive(Debug, Clone)]
pub struct CubicEnhancedConfig {
    initial_window: u64,
}

impl CubicEnhancedConfig {
    /// Override the initial congestion window (bytes).
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }
}

impl Default for CubicEnhancedConfig {
    fn default() -> Self {
        Self {
            initial_window: INIT_CWND_PKTS * BASE_DATAGRAM_SIZE,
        }
    }
}

impl ControllerFactory for CubicEnhancedConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(CubicEnhanced::new(self, now, current_mtu))
    }
}
