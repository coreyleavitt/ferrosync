use pyo3::prelude::*;

/// ferrosync Python bindings (Phase 5).
#[pymodule]
fn _ferrosync(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
