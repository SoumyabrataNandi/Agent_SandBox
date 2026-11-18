//! Prometheus metrics (U5 design §6).

use std::sync::atomic::AtomicU64;

use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct RunLabels {
    pub language: String,
    pub policy: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct LangLabel {
    pub language: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct KindLabel {
    pub kind: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ReasonLabel {
    pub reason: String,
}

/// All server metrics.
pub struct Metrics {
    registry: Registry,
    pub(crate) runs: Family<RunLabels, Counter>,
    pub(crate) duration: Family<LangLabel, Histogram>,
    pub(crate) limits: Family<KindLabel, Counter>,
    pub(crate) rejected: Family<ReasonLabel, Counter>,
    pub(crate) queue_depth: Gauge,
    pub(crate) running: Gauge,
    pub(crate) audit_healthy: Gauge,
    pub(crate) startup_ms: Gauge<u64, AtomicU64>,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Metrics")
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::with_prefix("sandboxd");
        let runs = Family::<RunLabels, Counter>::default();
        let duration = Family::<LangLabel, Histogram>::new_with_constructor(|| {
            Histogram::new([0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0])
        });
        let limits = Family::<KindLabel, Counter>::default();
        let rejected = Family::<ReasonLabel, Counter>::default();
        let (queue_depth, running, audit_healthy) =
            (Gauge::default(), Gauge::default(), Gauge::default());
        let startup_ms = Gauge::<u64, AtomicU64>::default();
        registry.register("runs", "Completed runs", runs.clone());
        registry.register(
            "run_duration_seconds",
            "End-to-end run duration",
            duration.clone(),
        );
        registry.register("limits_hit", "Limits hit by runs", limits.clone());
        registry.register(
            "rejected",
            "Requests rejected before running",
            rejected.clone(),
        );
        registry.register(
            "queue_depth",
            "Requests waiting for a slot",
            queue_depth.clone(),
        );
        registry.register("running", "Runs executing now", running.clone());
        registry.register(
            "audit_healthy",
            "1 if the audit log is writable",
            audit_healthy.clone(),
        );
        registry.register(
            "startup_milliseconds",
            "Engine warm-up time",
            startup_ms.clone(),
        );
        Self {
            registry,
            runs,
            duration,
            limits,
            rejected,
            queue_depth,
            running,
            audit_healthy,
            startup_ms,
        }
    }
}

impl Metrics {
    /// Prometheus text exposition.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = encode(&mut s, &self.registry);
        s
    }

    /// Record engine warm-up time.
    pub fn startup_ms_set(&self, d: std::time::Duration) {
        self.startup_ms
            .set(u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    }

    pub(crate) fn reject(&self, reason: &str) {
        self.rejected
            .get_or_create(&ReasonLabel {
                reason: reason.into(),
            })
            .inc();
    }
}
