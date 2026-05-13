//! Prometheus metrics installation and helpers.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the Prometheus recorder. Safe to call multiple times.
///
/// Returns `Err` only if the global recorder slot is already taken by an
/// incompatible recorder (which never happens in this crate but might if the
/// embedder installed its own first).
pub fn install() -> Option<&'static PrometheusHandle> {
    if let Some(h) = HANDLE.get() {
        return Some(h);
    }
    match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            let _ = HANDLE.set(handle);
            HANDLE.get()
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to install Prometheus recorder; /metrics will be empty");
            None
        }
    }
}

/// Render the current registry as Prometheus text exposition format.
pub fn render() -> String {
    HANDLE
        .get()
        .map(|h| h.render())
        .unwrap_or_else(|| "# metrics not installed\n".to_string())
}
