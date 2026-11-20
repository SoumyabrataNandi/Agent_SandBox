//! Optional OTLP/HTTP export (cycle 2, C2-U4; FR-O1, ADR-C2-6).
//!
//! With the `otel` cargo feature and `[telemetry] otlp_endpoint` set, sandboxd exports the same
//! counters and histograms as `/metrics` plus one `sandboxd.run` span per run, as OTLP/HTTP
//! protobuf to `<endpoint>/v1/metrics` and `<endpoint>/v1/traces`.
//!
//! * Export runs on the OpenTelemetry SDK's own threads (batch span processor, periodic metric
//!   reader). Recording a metric or ending a span only enqueues data, so a slow or failing
//!   collector never blocks or fails a run (O1.3). Full queues drop data rather than wait.
//! * Spans carry no code, output, file paths, URLs or principals (O1.2).
//! * Without the feature this module is an inert handle and none of the OpenTelemetry crates are
//!   compiled.

use std::time::{Duration, SystemTime};

use sandboxd_runtime::RunResult;

/// Default interval between metric exports.
pub const DEFAULT_EXPORT_INTERVAL: Duration = Duration::from_secs(30);
/// Upper bound for flushing on shutdown.
#[cfg(feature = "otel")]
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Process-wide OTLP export handle. Keep it alive for the server's lifetime and call
/// [`Telemetry::shutdown`] at exit to flush.
pub struct Telemetry {
    #[cfg(feature = "otel")]
    providers: Option<imp::Providers>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry")
            .field("enabled", &self.enabled())
            .finish()
    }
}

impl Telemetry {
    /// No export.
    pub fn disabled() -> Self {
        Self {
            #[cfg(feature = "otel")]
            providers: None,
        }
    }

    /// `true` when this build includes the `otel` feature.
    pub const fn compiled_in() -> bool {
        cfg!(feature = "otel")
    }

    /// Start exporting to `endpoint` (base URL such as `http://collector:4318`). `None` → no
    /// export. Without the `otel` feature an endpoint is ignored with a warning.
    ///
    /// Call this **before** creating the `RunService`: its instruments are bound to the global
    /// meter provider at creation.
    pub async fn init(endpoint: Option<&str>, interval: Duration) -> Result<Self, String> {
        let Some(endpoint) = endpoint else {
            return Ok(Self::disabled());
        };
        #[cfg(feature = "otel")]
        {
            let endpoint = endpoint.trim_end_matches('/').to_string();
            // The OTLP client is reqwest's blocking client: build (and later drop) it on a plain
            // OS thread, outside the tokio runtime.
            let providers = run_off_runtime(move || imp::start(&endpoint, interval)).await??;
            Ok(Self {
                providers: Some(providers),
            })
        }
        #[cfg(not(feature = "otel"))]
        {
            let _ = interval;
            tracing::warn!(
                endpoint,
                "telemetry.otlp_endpoint is set, but this build has no `otel` feature; OTLP export is off"
            );
            Ok(Self::disabled())
        }
    }

    /// `true` when exporting.
    pub fn enabled(&self) -> bool {
        #[cfg(feature = "otel")]
        {
            self.providers.is_some()
        }
        #[cfg(not(feature = "otel"))]
        {
            false
        }
    }

    /// Flush and stop the exporters (bounded; never fails the caller).
    pub async fn shutdown(self) {
        #[cfg(feature = "otel")]
        if let Some(p) = self.providers {
            let flushed = tokio::time::timeout(
                SHUTDOWN_TIMEOUT + Duration::from_secs(1),
                run_off_runtime(move || p.shutdown(SHUTDOWN_TIMEOUT)),
            )
            .await;
            if flushed.is_err() {
                tracing::warn!(
                    "OTLP exporter did not shut down in time; pending telemetry dropped"
                );
            }
        }
    }
}

/// Run `f` on a fresh OS thread (not a tokio worker) and await its result.
#[cfg(feature = "otel")]
async fn run_off_runtime<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("sandboxd-otel".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .map_err(|e| format!("otel thread: {e}"))?;
    rx.await.map_err(|_| "otel thread panicked".to_string())
}

/// Record the `sandboxd.run` span for a finished run (no-op without the feature or an endpoint).
pub(crate) fn record_run_span(result: &RunResult, started: SystemTime) {
    #[cfg(feature = "otel")]
    imp::run_span(result, started);
    #[cfg(not(feature = "otel"))]
    let _ = (result, started);
}

/// OTel mirrors of the Prometheus instruments (inert without the feature).
#[derive(Debug, Default)]
pub(crate) struct Instruments {
    #[cfg(feature = "otel")]
    inner: Option<imp::Instruments>,
}

impl Instruments {
    /// Bind to the global meter provider (no-op instruments if none is installed).
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(feature = "otel")]
            inner: Some(imp::Instruments::new()),
        }
    }

    pub(crate) fn run(&self, language: &str, policy: &str, outcome: &str, seconds: f64) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.run(language, policy, outcome, seconds);
        }
        #[cfg(not(feature = "otel"))]
        let _ = (language, policy, outcome, seconds);
    }

    pub(crate) fn limit(&self, kind: &str) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.limit(kind);
        }
        #[cfg(not(feature = "otel"))]
        let _ = kind;
    }

    pub(crate) fn reject(&self, reason: &str) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.reject(reason);
        }
        #[cfg(not(feature = "otel"))]
        let _ = reason;
    }

    pub(crate) fn queue(&self, delta: i64) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.queue.add(delta, &[]);
        }
        #[cfg(not(feature = "otel"))]
        let _ = delta;
    }

    pub(crate) fn running(&self, delta: i64) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.running.add(delta, &[]);
        }
        #[cfg(not(feature = "otel"))]
        let _ = delta;
    }

    pub(crate) fn audit_healthy(&self, ok: bool) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.audit_healthy.record(i64::from(ok), &[]);
        }
        #[cfg(not(feature = "otel"))]
        let _ = ok;
    }

    pub(crate) fn sessions(&self, active: i64) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.sessions_active.record(active, &[]);
        }
        #[cfg(not(feature = "otel"))]
        let _ = active;
    }

    pub(crate) fn session_call(&self) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.session_calls.add(1, &[]);
        }
    }

    pub(crate) fn session_ended(&self, reason: &str) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.sessions_ended.add(
                1,
                &[opentelemetry::KeyValue::new("reason", reason.to_string())],
            );
        }
        #[cfg(not(feature = "otel"))]
        let _ = reason;
    }

    pub(crate) fn pool(&self, slots: u32, in_use: u32) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.pool_slots.record(u64::from(slots), &[]);
            i.pool_in_use.record(u64::from(in_use), &[]);
        }
        #[cfg(not(feature = "otel"))]
        let _ = (slots, in_use);
    }

    pub(crate) fn startup_ms(&self, ms: u64) {
        #[cfg(feature = "otel")]
        if let Some(i) = &self.inner {
            i.startup.record(ms, &[]);
        }
        #[cfg(not(feature = "otel"))]
        let _ = ms;
    }
}

#[cfg(feature = "otel")]
mod imp {
    use std::time::{Duration, SystemTime};

    use opentelemetry::{
        KeyValue, global,
        metrics::{Counter, Gauge, Histogram, UpDownCounter},
        trace::{Span, SpanKind, Status, Tracer},
    };
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{
        Resource,
        metrics::{PeriodicReader, SdkMeterProvider},
        trace::SdkTracerProvider,
    };
    use sandboxd_runtime::{Outcome, RunResult};

    const SCOPE: &str = "sandboxd";
    const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

    pub(super) struct Providers {
        tracer: SdkTracerProvider,
        meter: SdkMeterProvider,
    }

    impl Providers {
        pub(super) fn shutdown(self, timeout: Duration) {
            let _ = self.tracer.force_flush();
            let _ = self.tracer.shutdown_with_timeout(timeout);
            let _ = self.meter.shutdown_with_timeout(timeout);
        }
    }

    pub(super) fn start(endpoint: &str, interval: Duration) -> Result<Providers, String> {
        // reqwest is built with `rustls-no-provider` (shared with the network broker), so a
        // process-wide provider must exist before any client is built (https endpoints). `Err`
        // just means one is already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let spans = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{endpoint}/v1/traces"))
            .with_timeout(EXPORT_TIMEOUT)
            .build()
            .map_err(|e| format!("OTLP span exporter: {e}"))?;
        let metrics = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(format!("{endpoint}/v1/metrics"))
            .with_timeout(EXPORT_TIMEOUT)
            .build()
            .map_err(|e| format!("OTLP metric exporter: {e}"))?;
        let resource = Resource::builder()
            .with_service_name("sandboxd")
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build();
        let tracer = SdkTracerProvider::builder()
            .with_batch_exporter(spans)
            .with_resource(resource.clone())
            .build();
        let meter = SdkMeterProvider::builder()
            .with_reader(
                PeriodicReader::builder(metrics)
                    .with_interval(interval)
                    .build(),
            )
            .with_resource(resource)
            .build();
        global::set_tracer_provider(tracer.clone());
        global::set_meter_provider(meter.clone());
        Ok(Providers { tracer, meter })
    }

    fn outcome_str(o: Outcome) -> String {
        serde_json::to_value(o)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    }

    pub(super) fn run_span(r: &RunResult, started: SystemTime) {
        let tracer = global::tracer(SCOPE);
        let limits: Vec<opentelemetry::StringValue> = r
            .limits_hit
            .iter()
            .filter_map(|k| {
                serde_json::to_value(k)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string().into()))
            })
            .collect();
        let t = r.timings;
        let mut attrs = vec![
            KeyValue::new("sandboxd.run_id", r.run_id.to_string()),
            KeyValue::new("sandboxd.language", r.language.as_str()),
            KeyValue::new("sandboxd.policy", r.policy.clone()),
            KeyValue::new("sandboxd.outcome", outcome_str(r.outcome)),
            KeyValue::new(
                "sandboxd.limits_hit",
                opentelemetry::Value::Array(limits.into()),
            ),
            KeyValue::new("sandboxd.fuel_used", clamp(r.fuel_used)),
            KeyValue::new("sandboxd.peak_memory_bytes", clamp(r.peak_memory)),
            KeyValue::new("sandboxd.net_requests", i64::from(r.net_requests)),
            KeyValue::new("sandboxd.queued_ms", clamp(t.queued_ms)),
            KeyValue::new("sandboxd.setup_ms", clamp(t.setup_ms)),
            KeyValue::new("sandboxd.run_ms", clamp(t.run_ms)),
            KeyValue::new("sandboxd.collect_ms", clamp(t.collect_ms)),
            KeyValue::new("sandboxd.total_ms", clamp(t.total_ms)),
        ];
        if let Some(code) = r.exit_code {
            attrs.push(KeyValue::new("sandboxd.exit_code", i64::from(code)));
        }
        if let Some(e) = &r.error {
            attrs.push(KeyValue::new("sandboxd.error", e.code()));
        }
        let mut span = tracer
            .span_builder("sandboxd.run")
            .with_kind(SpanKind::Internal)
            .with_start_time(started)
            .with_attributes(attrs)
            .start(&tracer);
        if matches!(r.outcome, Outcome::Error | Outcome::Trap) {
            // Only the stable code: error messages may contain request details.
            let code = r.error.as_ref().map(|e| e.code()).unwrap_or("TRAP");
            span.set_status(Status::error(code));
        }
        span.end_with_timestamp(started + Duration::from_millis(t.total_ms));
    }

    fn clamp(v: u64) -> i64 {
        i64::try_from(v).unwrap_or(i64::MAX)
    }

    pub(super) struct Instruments {
        runs: Counter<u64>,
        duration: Histogram<f64>,
        limits: Counter<u64>,
        rejected: Counter<u64>,
        pub(super) queue: UpDownCounter<i64>,
        pub(super) running: UpDownCounter<i64>,
        pub(super) audit_healthy: Gauge<i64>,
        pub(super) startup: Gauge<u64>,
        pub(super) pool_slots: Gauge<u64>,
        pub(super) pool_in_use: Gauge<u64>,
        pub(super) sessions_active: Gauge<i64>,
        pub(super) session_calls: Counter<u64>,
        pub(super) sessions_ended: Counter<u64>,
    }

    impl std::fmt::Debug for Instruments {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Instruments")
        }
    }

    impl Instruments {
        pub(super) fn new() -> Self {
            let m = global::meter(SCOPE);
            Self {
                runs: m
                    .u64_counter("sandboxd.runs")
                    .with_description("Completed runs")
                    .build(),
                duration: m
                    .f64_histogram("sandboxd.run.duration")
                    .with_unit("s")
                    .with_description("End-to-end run duration")
                    .with_boundaries(vec![
                        0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
                    ])
                    .build(),
                limits: m
                    .u64_counter("sandboxd.limits_hit")
                    .with_description("Limits hit by runs")
                    .build(),
                rejected: m
                    .u64_counter("sandboxd.rejected")
                    .with_description("Requests rejected before running")
                    .build(),
                queue: m
                    .i64_up_down_counter("sandboxd.queue_depth")
                    .with_description("Requests waiting for a slot")
                    .build(),
                running: m
                    .i64_up_down_counter("sandboxd.running")
                    .with_description("Runs executing now")
                    .build(),
                audit_healthy: m
                    .i64_gauge("sandboxd.audit_healthy")
                    .with_description("1 if the audit log is writable")
                    .build(),
                startup: m
                    .u64_gauge("sandboxd.startup")
                    .with_unit("ms")
                    .with_description("Engine warm-up time")
                    .build(),
                pool_slots: m
                    .u64_gauge("sandboxd.pool.slots")
                    .with_description("Instance pool size (0 without pooling)")
                    .build(),
                pool_in_use: m
                    .u64_gauge("sandboxd.pool.slots_in_use")
                    .with_description("Instance pool slots in use")
                    .build(),
                sessions_active: m
                    .i64_gauge("sandboxd.sessions.active")
                    .with_description("Live interpreter sessions")
                    .build(),
                session_calls: m
                    .u64_counter("sandboxd.session.calls")
                    .with_description("Calls run in sessions")
                    .build(),
                sessions_ended: m
                    .u64_counter("sandboxd.sessions.ended")
                    .with_description("Sessions ended, by reason")
                    .build(),
            }
        }

        pub(super) fn run(&self, language: &str, policy: &str, outcome: &str, seconds: f64) {
            self.runs.add(
                1,
                &[
                    KeyValue::new("language", language.to_string()),
                    KeyValue::new("policy", policy.to_string()),
                    KeyValue::new("outcome", outcome.to_string()),
                ],
            );
            self.duration
                .record(seconds, &[KeyValue::new("language", language.to_string())]);
        }

        pub(super) fn limit(&self, kind: &str) {
            self.limits
                .add(1, &[KeyValue::new("kind", kind.to_string())]);
        }

        pub(super) fn reject(&self, reason: &str) {
            self.rejected.add(
                1,
                &[opentelemetry::KeyValue::new("reason", reason.to_string())],
            );
        }
    }
}
