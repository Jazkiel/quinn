use std::any::Any;
use std::sync::Arc;

use super::{Controller, ControllerFactory, BASE_DATAGRAM_SIZE};
use crate::connection::RttEstimator;
use crate::{Duration, Instant};

// Copa constants — ported from Go copa_sender.go
const COPA_DEFAULT_DELTA: f64 = 0.05;
const COPA_MIN_RTT_WINDOW: Duration = Duration::from_secs(3);
const COPA_STANDING_RTT_MIN_WINDOW: Duration = Duration::from_millis(150);
const COPA_INITIAL_CWND_PKTS: u64 = 10;
const COPA_MIN_CWND_PKTS: u64 = 2;
const COPA_VELOCITY_RTT_THRESHOLD: u32 = 3;
const COPA_MAX_VELOCITY: f64 = 4.0;
const COPA_JITTER_DEAD_ZONE_MULTIPLIER: f64 = 2.0;

/// Max congestion window — 20 MiB, same bound used elsewhere in the codebase.
const COPA_MAX_CWND: u64 = 20 * 1024 * 1024;

// ── Windowed minimum RTT filter ───────────────────────────────────────────────

#[derive(Debug, Clone)]
struct WindowedMin {
    min_rtt: Duration,
    expiry: Option<Instant>,
    /// Sliding window size; may be updated between calls.
    window: Duration,
}

impl WindowedMin {
    fn new(window: Duration) -> Self {
        Self {
            min_rtt: Duration::ZERO,
            expiry: None,
            window,
        }
    }

    fn update(&mut self, rtt: Duration, now: Instant) {
        let expired = self.expiry.map_or(true, |e| now >= e);
        if expired || rtt <= self.min_rtt || self.min_rtt == Duration::ZERO {
            self.min_rtt = rtt;
            self.expiry = Some(now + self.window);
        }
    }

    fn get(&self) -> Duration {
        self.min_rtt
    }

    fn reset(&mut self) {
        self.min_rtt = Duration::ZERO;
        self.expiry = None;
    }
}

// ── Velocity state ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopaDirection {
    None,
    Up,
    Down,
}

#[derive(Debug, Clone)]
struct VelocityState {
    /// Current velocity multiplier; starts at 1, doubles every
    /// COPA_VELOCITY_RTT_THRESHOLD consecutive RTTs in the same direction.
    v: f64,
    direction: CopaDirection,
    same_dir_count: u32,
    last_update: Option<Instant>,
}

impl Default for VelocityState {
    fn default() -> Self {
        Self {
            v: 1.0,
            direction: CopaDirection::None,
            same_dir_count: 0,
            last_update: None,
        }
    }
}

// ── Copa controller ───────────────────────────────────────────────────────────

/// Copa delay-based congestion controller.
///
/// Ported from the Go implementation in `copa_sender.go`, which follows
/// mvfst/quic/congestion_control/Copa.{h,cpp}.
///
/// Key properties:
/// - Targets `targetRate = MSS / (delta * standingDelay)` vs `currentRate = cwnd / srtt`.
/// - Does **not** reduce cwnd on packet loss; only persistent congestion (RTO) resets it.
/// - Jitter dead zone: if the measured queuing delay is within 2 × rttvar, Copa
///   ignores the delay signal and treats the path as uncongested.
#[derive(Debug, Clone)]
pub struct Copa {
    config: Arc<CopaConfig>,
    window: u64,
    current_mtu: u64,

    min_rtt_filter: WindowedMin,
    standing_rtt_filter: WindowedMin,

    /// We track rttvar ourselves because `RttEstimator::var` is private in quinn.
    rttvar: Duration,

    velocity: VelocityState,
    in_slow_start: bool,
    last_cwnd_double: Option<Instant>,

    /// Accumulated acked packets since the last cwnd update (steady-state).
    num_acked_pkts: u64,
}

impl Copa {
    /// Construct a new Copa controller.
    pub fn new(config: Arc<CopaConfig>, _now: Instant, current_mtu: u16) -> Self {
        let mtu = current_mtu as u64;
        Self {
            window: COPA_INITIAL_CWND_PKTS * mtu,
            current_mtu: mtu,
            min_rtt_filter: WindowedMin::new(COPA_MIN_RTT_WINDOW),
            standing_rtt_filter: WindowedMin::new(COPA_STANDING_RTT_MIN_WINDOW),
            rttvar: Duration::ZERO,
            velocity: VelocityState::default(),
            in_slow_start: true,
            last_cwnd_double: None,
            num_acked_pkts: 0,
            config,
        }
    }

    fn min_window(&self) -> u64 {
        COPA_MIN_CWND_PKTS * self.current_mtu
    }

    /// Update our rttvar estimate via EWMA: rttvar = 3/4 * rttvar + 1/4 * |srtt - latest|.
    fn update_rttvar(&mut self, latest_rtt: Duration, srtt: Duration) {
        let deviation = if srtt > latest_rtt {
            srtt - latest_rtt
        } else {
            latest_rtt - srtt
        };
        if self.rttvar == Duration::ZERO {
            self.rttvar = deviation;
        } else {
            self.rttvar = (self.rttvar * 3 + deviation) / 4;
        }
    }

    fn update_cwnd(&mut self, now: Instant, srtt: Duration) {
        let min_rtt = self.min_rtt_filter.get();
        let standing_rtt = self.standing_rtt_filter.get();
        if min_rtt == Duration::ZERO || standing_rtt == Duration::ZERO {
            return;
        }

        // Queuing delay above the baseline.
        let raw_delay = standing_rtt.saturating_sub(min_rtt);

        // Dead zone: if rawDelay <= 2*rttvar, the signal is indistinguishable from
        // path jitter. Clear any accumulated down-velocity bias and treat the path
        // as uncongested (delay = 1ns → targetRate >> currentRate).
        let dead_zone = Duration::from_nanos(
            (self.rttvar.as_nanos() as f64 * COPA_JITTER_DEAD_ZONE_MULTIPLIER) as u64,
        );
        let delay = if raw_delay == Duration::ZERO || raw_delay <= dead_zone {
            if self.velocity.direction == CopaDirection::Down {
                self.velocity = VelocityState::default();
            }
            Duration::from_nanos(1)
        } else {
            raw_delay
        };

        let mss = self.current_mtu as f64;
        let cwnd = self.window as f64;
        let srtt_ns = srtt.as_nanos() as f64;
        let delay_ns = delay.as_nanos() as f64;
        let delta = self.config.delta;

        // targetRate  = MSS / (delta * delay)   [bytes/ns]
        // currentRate = cwnd / srtt              [bytes/ns]
        let target_rate = mss / (delta * delay_ns);
        let current_rate = cwnd / srtt_ns;

        if self.in_slow_start {
            self.update_slow_start(target_rate, current_rate, now, srtt);
        } else {
            self.update_steady_state(target_rate, current_rate, now, srtt);
        }
    }

    fn update_slow_start(
        &mut self,
        target_rate: f64,
        current_rate: f64,
        now: Instant,
        srtt: Duration,
    ) {
        if target_rate >= current_rate {
            // Double cwnd at most once per RTT.
            let should_double = self
                .last_cwnd_double
                .map_or(true, |t| now - t >= srtt);
            if should_double {
                self.window = (self.window * 2).min(COPA_MAX_CWND);
                self.last_cwnd_double = Some(now);
            }
        } else {
            // Congested: exit slow start, then apply a steady-state update.
            self.in_slow_start = false;
            self.update_steady_state(target_rate, current_rate, now, srtt);
        }
    }

    fn update_steady_state(
        &mut self,
        target_rate: f64,
        current_rate: f64,
        now: Instant,
        srtt: Duration,
    ) {
        let mss = self.current_mtu as f64;
        let cwnd = self.window as f64;
        let num_pkts = self.num_acked_pkts as f64;
        self.num_acked_pkts = 0;

        let v = self.velocity.v;
        let delta_cwnd = num_pkts * mss * mss * v / (self.config.delta * cwnd);

        if target_rate >= current_rate {
            self.update_velocity(CopaDirection::Up, now, srtt);
            self.window = ((cwnd + delta_cwnd) as u64).min(COPA_MAX_CWND);
        } else {
            self.update_velocity(CopaDirection::Down, now, srtt);
            let new_cwnd = cwnd - delta_cwnd;
            if new_cwnd >= 0.0 {
                self.window = (new_cwnd as u64).max(self.min_window());
            } else {
                self.window = self.min_window();
            }
        }
    }

    fn update_velocity(&mut self, dir: CopaDirection, now: Instant, srtt: Duration) {
        if self.velocity.direction != dir {
            self.velocity = VelocityState {
                v: 1.0,
                direction: dir,
                same_dir_count: 0,
                last_update: Some(now),
            };
            return;
        }

        let last_update = match self.velocity.last_update {
            Some(t) => t,
            None => {
                self.velocity.last_update = Some(now);
                return;
            }
        };

        if now - last_update < srtt {
            return;
        }
        self.velocity.last_update = Some(now);
        self.velocity.same_dir_count += 1;

        if self.velocity.same_dir_count >= COPA_VELOCITY_RTT_THRESHOLD {
            self.velocity.v = (self.velocity.v * 2.0).min(COPA_MAX_VELOCITY);
            self.velocity.same_dir_count = 0;
        }
    }
}

impl Controller for Copa {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        _bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if app_limited {
            return;
        }

        let srtt = rtt.get();
        if srtt == Duration::ZERO {
            return;
        }

        // Latest RTT approximated as now − sent (the one-way path delay plus ack delay).
        let latest_rtt = now - sent;
        if latest_rtt == Duration::ZERO {
            return;
        }

        // Update our private rttvar estimate.
        self.update_rttvar(latest_rtt, srtt);

        // Update minRTT filter (3-second sliding window).
        self.min_rtt_filter.update(latest_rtt, now);

        // Update standingRTT filter (max(srtt/2, 150ms) window).
        let standing_window = (srtt / 2).max(COPA_STANDING_RTT_MIN_WINDOW);
        self.standing_rtt_filter.window = standing_window;
        self.standing_rtt_filter.update(latest_rtt, now);

        self.num_acked_pkts += 1;
        self.update_cwnd(now, srtt);
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // Copa does not reduce cwnd on ordinary loss.
        // Only persistent congestion (RTO) triggers a full reset.
        if is_persistent_congestion {
            self.window = self.min_window();
            self.in_slow_start = true;
            self.last_cwnd_double = None;
            self.num_acked_pkts = 0;
            self.velocity = VelocityState::default();
            self.min_rtt_filter.reset();
            self.standing_rtt_filter.reset();
            self.rttvar = Duration::ZERO;
        }
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
        COPA_INITIAL_CWND_PKTS * self.current_mtu
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the Copa congestion controller.
#[derive(Debug, Clone)]
pub struct CopaConfig {
    /// Latency/throughput trade-off parameter δ.
    ///
    /// Smaller δ → lower latency, larger δ → higher throughput.
    /// The default (0.05) is a good starting point for real-time media.
    pub delta: f64,
    initial_window: u64,
}

impl CopaConfig {
    /// Override the δ parameter.
    pub fn delta(&mut self, value: f64) -> &mut Self {
        self.delta = value;
        self
    }

    /// Override the initial congestion window (bytes).
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }
}

impl Default for CopaConfig {
    fn default() -> Self {
        Self {
            delta: COPA_DEFAULT_DELTA,
            initial_window: COPA_INITIAL_CWND_PKTS * BASE_DATAGRAM_SIZE,
        }
    }
}

impl ControllerFactory for CopaConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Copa::new(self, now, current_mtu))
    }
}
