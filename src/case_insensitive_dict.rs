use indexmap::IndexMap;
use pyo3::exceptions::{PyKeyError, PyStopIteration, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyMapping, PyTuple};

/// A case-insensitive dict-like object for HTTP headers.
///
/// Remembers the case of the last key to be set, and iteration/keys/items
/// return case-sensitive keys.  Querying and contains testing is case
/// insensitive.
#[pyclass(mapping)]
pub struct CaseInsensitiveDict {
    /// lowercase_key -> (original_key, value)
    store: IndexMap<String, (String, Py<PyAny>)>,
}

impl CaseInsensitiveDict {
    /// Create an empty CaseInsensitiveDict without Python interaction.
    pub fn new_empty() -> Self {
        CaseInsensitiveDict {
            store: IndexMap::new(),
        }
    }

    /// Public Rust accessor: get a value by key (case-insensitive).
    pub fn get_value(&self, py: Python<'_>, key: &str) -> Option<Py<PyAny>> {
        self.store
            .get(&key.to_lowercase())
            .map(|(_, val)| val.clone_ref(py))
    }

    /// Public Rust accessor: check if key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.store.contains_key(&key.to_lowercase())
    }

    /// Public Rust accessor: iterate over (original_key, value) pairs.
    pub fn iter_items(&self) -> impl Iterator<Item = (&str, &Py<PyAny>)> {
        self.store.values().map(|(orig, val)| (orig.as_str(), val))
    }

    /// Public Rust accessor: set a key-value pair.
    pub fn set_item(&mut self, py: Python<'_>, key: &str, value: Bound<'_, PyAny>) -> PyResult<()> {
        self.store.insert(
            key.to_lowercase(),
            (
                key.to_string(),
                value.into_pyobject(py)?.into_any().unbind(),
            ),
        );
        Ok(())
    }

    /// Internal helper: populate from a Python dict, list of tuples, or
    /// another CaseInsensitiveDict.
    fn update_from_obj(&mut self, py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<()> {
        // Check if it's a CaseInsensitiveDict first
        if let Ok(cid) = data.cast::<CaseInsensitiveDict>() {
            let borrowed = cid.borrow();
            for (lower_key, (orig_key, val)) in &borrowed.store {
                self.store
                    .insert(lower_key.clone(), (orig_key.clone(), val.clone_ref(py)));
            }
            return Ok(());
        }

        // Check if it's a mapping (has .keys())
        if let Ok(mapping) = data.cast::<PyMapping>() {
            let keys = mapping.keys()?;
            for i in 0..keys.len() {
                let key = keys.get_item(i)?;
                // Handle both str and bytes keys
                let key_str: String = if key.is_instance_of::<pyo3::types::PyBytes>() {
                    let bytes: Vec<u8> = key.extract()?;
                    String::from_utf8(bytes).map_err(|e| PyTypeError::new_err(e.to_string()))?
                } else {
                    key.extract()?
                };
                let value = mapping.get_item(&key)?;
                self.store.insert(
                    key_str.to_lowercase(),
                    (key_str, value.into_pyobject(py)?.into_any().unbind()),
                );
            }
            return Ok(());
        }

        // Try as iterable of (key, value) pairs
        if let Ok(iter) = data.try_iter() {
            for item in iter {
                let item = item?;
                // Each item should be a tuple/sequence of (key, value)
                if let Ok(tuple) = item.cast::<PyTuple>() {
                    if tuple.len() == 2 {
                        let key_obj = tuple.get_item(0)?;
                        let key_str: String = if key_obj.is_instance_of::<pyo3::types::PyBytes>() {
                            let bytes: Vec<u8> = key_obj.extract()?;
                            String::from_utf8(bytes)
                                .map_err(|e| PyTypeError::new_err(e.to_string()))?
                        } else {
                            key_obj.extract()?
                        };
                        let value = tuple.get_item(1)?;
                        self.store.insert(
                            key_str.to_lowercase(),
                            (key_str, value.into_pyobject(py)?.into_any().unbind()),
                        );
                        continue;
                    }
                }
                // Try extracting as a 2-element sequence
                let key_str: String = item.get_item(0)?.extract()?;
                let value = item.get_item(1)?;
                self.store.insert(
                    key_str.to_lowercase(),
                    (key_str, value.into_pyobject(py)?.into_any().unbind()),
                );
            }
            return Ok(());
        }

        Err(PyTypeError::new_err(
            "cannot convert to CaseInsensitiveDict",
        ))
    }

    fn update_from_kwargs(&mut self, py: Python<'_>, kwargs: &Bound<'_, PyDict>) -> PyResult<()> {
        for (k, v) in kwargs.iter() {
            let key_str: String = k.extract()?;
            self.store.insert(
                key_str.to_lowercase(),
                (key_str, v.into_pyobject(py)?.into_any().unbind()),
            );
        }
        Ok(())
    }
}

#[pymethods]
impl CaseInsensitiveDict {
    #[new]
    #[pyo3(signature = (data=None, **kwargs))]
    fn new(
        py: Python<'_>,
        data: Option<&Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let mut cid = CaseInsensitiveDict {
            store: IndexMap::new(),
        };
        if let Some(d) = data {
            if !d.is_none() {
                cid.update_from_obj(py, d)?;
            }
        }
        if let Some(kw) = kwargs {
            cid.update_from_kwargs(py, kw)?;
        }
        Ok(cid)
    }

    fn __setitem__(&mut self, py: Python<'_>, key: &str, value: Bound<'_, PyAny>) -> PyResult<()> {
        self.store.insert(
            key.to_lowercase(),
            (
                key.to_string(),
                value.into_pyobject(py)?.into_any().unbind(),
            ),
        );
        Ok(())
    }

    fn __getitem__(&self, py: Python<'_>, key: &str) -> PyResult<Py<PyAny>> {
        match self.store.get(&key.to_lowercase()) {
            Some((_orig, val)) => Ok(val.clone_ref(py)),
            None => Err(PyKeyError::new_err(key.to_string())),
        }
    }

    fn __delitem__(&mut self, key: &str) -> PyResult<()> {
        match self.store.shift_remove(&key.to_lowercase()) {
            Some(_) => Ok(()),
            None => Err(PyKeyError::new_err(key.to_string())),
        }
    }

    fn __contains__(&self, key: &str) -> bool {
        self.store.contains_key(&key.to_lowercase())
    }

    fn __len__(&self) -> usize {
        self.store.len()
    }

    fn __bool__(&self) -> bool {
        !self.store.is_empty()
    }

    fn __iter__(slf: Bound<'_, Self>) -> CaseInsensitiveDictIter {
        let keys: Vec<String> = slf
            .borrow()
            .store
            .values()
            .map(|(orig, _)| orig.clone())
            .collect();
        CaseInsensitiveDictIter { keys, pos: 0 }
    }

    fn __eq__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        // Helper to compare two stores
        fn stores_eq(
            py: Python<'_>,
            a: &IndexMap<String, (String, Py<PyAny>)>,
            b: &IndexMap<String, (String, Py<PyAny>)>,
        ) -> PyResult<bool> {
            if a.len() != b.len() {
                return Ok(false);
            }
            for (key, (_orig, val)) in a {
                match b.get(key) {
                    Some((_other_orig, other_val)) => {
                        if !val.bind(py).eq(other_val.bind(py))? {
                            return Ok(false);
                        }
                    }
                    None => return Ok(false),
                }
            }
            Ok(true)
        }

        // If other is a CaseInsensitiveDict, compare lower_items
        if let Ok(other_cid) = other.cast::<CaseInsensitiveDict>() {
            let other_ref = other_cid.borrow();
            let result = stores_eq(py, &self.store, &other_ref.store)?;
            return Ok(result.into_pyobject(py)?.to_owned().into_any().unbind());
        }

        // If other is a Mapping, convert it to CaseInsensitiveDict and compare
        let mapping_abc = py.import("collections.abc")?.getattr("Mapping")?;
        if other.is_instance(&mapping_abc)? {
            let mut temp = CaseInsensitiveDict {
                store: IndexMap::new(),
            };
            temp.update_from_obj(py, other)?;
            let result = stores_eq(py, &self.store, &temp.store)?;
            return Ok(result.into_pyobject(py)?.to_owned().into_any().unbind());
        }

        // Return NotImplemented for non-Mapping types
        Ok(py.NotImplemented())
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        // Build a dict of {original_key: value} and repr it
        let dict = PyDict::new(py);
        for (_lower, (orig, val)) in &self.store {
            dict.set_item(orig, val.bind(py))?;
        }
        let repr = dict.repr()?;
        Ok(repr.to_string())
    }

    #[pyo3(signature = (key, default=None))]
    fn get(&self, py: Python<'_>, key: &str, default: Option<Py<PyAny>>) -> PyResult<Py<PyAny>> {
        match self.store.get(&key.to_lowercase()) {
            Some((_orig, val)) => Ok(val.clone_ref(py)),
            None => Ok(default.unwrap_or_else(|| py.None())),
        }
    }

    #[pyo3(signature = (key, /, *args))]
    fn pop(
        &mut self,
        _py: Python<'_>,
        key: &str,
        args: &Bound<'_, PyTuple>,
    ) -> PyResult<Py<PyAny>> {
        if args.len() > 1 {
            return Err(PyTypeError::new_err("pop expected at most 2 arguments"));
        }
        match self.store.shift_remove(&key.to_lowercase()) {
            Some((_orig, val)) => Ok(val),
            None => {
                if args.len() == 1 {
                    Ok(args.get_item(0)?.unbind())
                } else {
                    Err(PyKeyError::new_err(key.to_string()))
                }
            }
        }
    }

    #[pyo3(signature = (key, default=None))]
    fn setdefault(
        &mut self,
        py: Python<'_>,
        key: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let lower = key.to_lowercase();
        if let Some((_orig, val)) = self.store.get(&lower) {
            return Ok(val.clone_ref(py));
        }
        let val = default.unwrap_or_else(|| py.None());
        self.store
            .insert(lower, (key.to_string(), val.clone_ref(py)));
        Ok(val)
    }

    #[pyo3(signature = (data=None, **kwargs))]
    fn update(
        &mut self,
        py: Python<'_>,
        data: Option<&Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        if let Some(d) = data {
            if !d.is_none() {
                self.update_from_obj(py, d)?;
            }
        }
        if let Some(kw) = kwargs {
            self.update_from_kwargs(py, kw)?;
        }
        Ok(())
    }

    fn copy(&self, py: Python<'_>) -> Self {
        CaseInsensitiveDict {
            store: self
                .store
                .iter()
                .map(|(k, (orig, val))| (k.clone(), (orig.clone(), val.clone_ref(py))))
                .collect(),
        }
    }

    fn keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let keys: Vec<String> = self.store.values().map(|(orig, _)| orig.clone()).collect();
        PyList::new(py, &keys)
    }

    fn values<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let vals: Vec<&Py<PyAny>> = self.store.values().map(|(_, val)| val).collect();
        let list = PyList::empty(py);
        for v in vals {
            list.append(v.bind(py))?;
        }
        Ok(list)
    }

    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for (_lower, (orig, val)) in &self.store {
            let tuple = PyTuple::new(
                py,
                &[orig.into_pyobject(py)?.into_any(), val.bind(py).clone()],
            )?;
            list.append(tuple)?;
        }
        Ok(list)
    }

    fn lower_items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for (lower, (_orig, val)) in &self.store {
            let tuple = PyTuple::new(
                py,
                &[lower.into_pyobject(py)?.into_any(), val.bind(py).clone()],
            )?;
            list.append(tuple)?;
        }
        Ok(list)
    }

    fn clear(&mut self) {
        self.store.clear();
    }

    fn popitem(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match self.store.pop() {
            Some((_lower, (orig_key, val))) => {
                let tuple = PyTuple::new(
                    py,
                    &[orig_key.into_pyobject(py)?.into_any(), val.into_bound(py)],
                )?;
                Ok(tuple.into_any().unbind())
            }
            None => Err(PyKeyError::new_err("popitem(): dictionary is empty")),
        }
    }
}

#[pyclass]
pub struct CaseInsensitiveDictIter {
    keys: Vec<String>,
    pos: usize,
}

#[pymethods]
impl CaseInsensitiveDictIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> PyResult<String> {
        if self.pos < self.keys.len() {
            let key = self.keys[self.pos].clone();
            self.pos += 1;
            Ok(key)
        } else {
            Err(PyStopIteration::new_err(()))
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests for CaseInsensitiveDict methods.
    //
    // NOTE: CaseInsensitiveDict contains Py<PyAny> in its store, which means
    // it cannot be instantiated in `cargo test` (the extension-module feature
    // prevents linking against libpython). The real behavioral tests for
    // clear(), popitem(), and __copy__() live in Group A (Python test suite).
    // These Rust tests verify compile-time invariants and structural assertions.

    #[test]
    fn test_clear_method_exists() {
        // Compile-time assertion: CaseInsensitiveDict has a clear() method
        // with the correct signature fn(&mut self). If this test compiles,
        // the method exists and is callable.
        // The real behavioral test (clear empties the store) runs in Group A.
        fn _assert_clear_signature(cid: &mut super::CaseInsensitiveDict) {
            cid.clear();
        }
    }

    // -- popitem() tests (Issue #83) --

    #[test]
    fn test_popitem_method_exists() {
        // Compile-time assertion: CaseInsensitiveDict has a popitem() method
        // with signature fn(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>>.
        // Returns a tuple of (original_key, value) or raises KeyError if empty.
        fn _assert_popitem_signature(
            cid: &mut super::CaseInsensitiveDict,
            py: pyo3::Python<'_>,
        ) -> pyo3::PyResult<pyo3::Py<pyo3::PyAny>> {
            cid.popitem(py)
        }
    }
}
