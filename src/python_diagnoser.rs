use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use crate::state::CicFeatureVector;

pub struct PythonDiagnoser;

impl PythonDiagnoser {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {

        Python::with_gil(|py| {
            py.run_bound(
                "import signal; signal.signal(signal.SIGINT, signal.SIG_IGN)",
                None,
                None
            )?;
            Ok::<(), PyErr>(())
        })?; // Propagate any Python errors

        Ok(PythonDiagnoser)
    }

    pub fn diagnose(&self, features: &CicFeatureVector) -> PyResult<String> {
        Python::with_gil(|py| {
            // Add the current directory to Python's sys.path to find the script
            let sys = PyModule::import_bound(py, "sys")?;
            let path_obj = sys.getattr("path")?;
            let path_list = path_obj.downcast::<PyList>()?;
            path_list.insert(0, ".")?;


            let feature_names = [
                "Dst Port", "Protocol", "Flow Duration", "Fwd Pkt Len Max",
                "Fwd Pkt Len Std", "Bwd Pkt Len Max", "Bwd Pkt Len Mean",
                "Bwd Pkt Len Std", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Max",
                "Flow IAT Min", "Fwd IAT Mean", "Fwd IAT Max", "Fwd Header Len",
                "Fwd Pkts/s", "Bwd Pkts/s", "RST Flag Cnt", "PSH Flag Cnt",
                "ACK Flag Cnt", "URG Flag Cnt", "ECE Flag Cnt", "Init Fwd Win Byts",
                "Init Bwd Win Byts", "Fwd Seg Size Min"
            ];
            let feature_values = features.to_diagnostic_ndarray();

            let locals = PyDict::new_bound(py);
            for (i, name) in feature_names.iter().enumerate() {
                locals.set_item(name, feature_values[i])?;
            }


            let ml_module = PyModule::import_bound(py, "ml_analysis")?;
            let diagnose_func = ml_module.getattr("diagnose_flow")?;

            let args = (locals,); // Pass the dictionary as an argument
            let result = diagnose_func.call1(args)?;

            result.extract::<String>()
        })
    }
}