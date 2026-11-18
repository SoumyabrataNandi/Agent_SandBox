//! Native-extension detection (FR-1.5; U4 design Q3: after the run, from stderr).

/// Top-level packages that need compiled C/C++/Rust extensions and cannot run in this sandbox.
pub const NATIVE_PACKAGES: &[&str] = &[
    "numpy",
    "pandas",
    "scipy",
    "sklearn",
    "torch",
    "tensorflow",
    "jax",
    "jaxlib",
    "lxml",
    "PIL",
    "cv2",
    "matplotlib",
    "pyarrow",
    "polars",
    "numba",
    "h5py",
    "tables",
    "psycopg2",
    "psycopg",
    "mysqlclient",
    "MySQLdb",
    "cryptography",
    "bcrypt",
    "nacl",
    "grpc",
    "orjson",
    "ujson",
    "pydantic_core",
    "regex",
    "yaml",
    "statsmodels",
    "shapely",
    "fiona",
    "rasterio",
    "xgboost",
    "lightgbm",
    "catboost",
    "duckdb",
    "zmq",
    "gevent",
    "greenlet",
    "tokenizers",
    "transformers",
    "spacy",
    "sentencepiece",
    "onnxruntime",
];

/// If stderr shows a failed import of a known native package, return the module named in the error.
pub fn detect(stderr: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stderr);
    for line in text.lines().rev() {
        let Some(rest) = line
            .trim()
            .strip_prefix("ModuleNotFoundError: No module named ")
        else {
            continue;
        };
        // `'numpy'`, possibly followed by a hint (CPython 3.15 appends
        // ". Site initialization is disabled, did you forget ...").
        let rest = rest.trim();
        let Some(quote) = rest.chars().next().filter(|c| *c == '\'' || *c == '"') else {
            continue;
        };
        let Some(name) = rest[1..].split(quote).next().filter(|n| !n.is_empty()) else {
            continue;
        };
        let root = name.split('.').next().unwrap_or(name);
        if NATIVE_PACKAGES.contains(&root) {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_only_known_native_packages() {
        let tb = b"Traceback (most recent call last):\n  File \"/code/main.py\", line 1, in <module>\n    import pandas as pd\nModuleNotFoundError: No module named 'pandas'\n";
        assert_eq!(detect(tb).as_deref(), Some("pandas"));
        assert_eq!(
            detect(b"ModuleNotFoundError: No module named 'numpy.linalg'").as_deref(),
            Some("numpy.linalg")
        );
        assert_eq!(
            detect(b"ModuleNotFoundError: No module named 'mylib'"),
            None
        );
        let py315 = b"ModuleNotFoundError: No module named 'numpy'. Site initialization is disabled, did you forget to add the site-packages directory to sys.path or to enable your virtual environment?";
        assert_eq!(detect(py315).as_deref(), Some("numpy"));
        assert_eq!(detect(b"print('import numpy')"), None);
    }
}
