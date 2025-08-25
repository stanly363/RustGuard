use crate::state::CicFeatureVector;
use linfa::prelude::*;
use linfa_clustering::KMeans;
use ndarray::{Array1, Array2, Axis};
use ndarray_stats::DeviationExt;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter};

#[derive(Serialize, Deserialize)]
pub struct Model {
    centroids: Vec<Vec<f64>>,
    thresholds: Vec<f64>,
}

pub struct AnomalyDetector {
    model: Model,
}

impl AnomalyDetector {
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let model: Model = serde_json::from_reader(reader)?;
        Ok(AnomalyDetector { model })
    }

    pub fn is_anomalous(&self, features: &CicFeatureVector) -> bool {
        let point = features.to_ndarray();
        let mut min_dist = f64::MAX;
        let mut closest_centroid_index = 0;

        for (i, centroid_vec) in self.model.centroids.iter().enumerate() {
            let centroid = Array1::from_vec(centroid_vec.clone());
            let dist = point.sq_l2_dist(&centroid).unwrap_or(f64::MAX);
            if dist < min_dist {
                min_dist = dist;
                closest_centroid_index = i;
            }
        }
        
        min_dist.sqrt() > self.model.thresholds[closest_centroid_index]
    }
}

pub fn train_model(vectors: Vec<CicFeatureVector>) {
    let observations: Vec<_> = vectors.iter().map(|v| v.to_ndarray()).collect();
    if observations.is_empty() {
        println!("Cannot train model with no data.");
        return;
    }

    let records = Array2::from_shape_vec(
        (observations.len(), observations[0].len()),
        observations.into_iter().flatten().collect::<Vec<_>>(),
    ).expect("Failed to create 2D array from observations");

    let dataset = Dataset::from(records.clone());
    let n_clusters = 5;
    let model = KMeans::params(n_clusters)
        .max_n_iterations(200)
        .tolerance(1e-5)
        .fit(&dataset)
        .expect("KMeans training failed");

    let centroids = model.centroids().axis_iter(Axis(0))
        .map(|row| row.to_vec())
        .collect::<Vec<Vec<f64>>>();
    
    let mut thresholds = Vec::new();
    for i in 0..n_clusters {
        let cluster_points_indices: Vec<_> = model.predict(&records).iter().enumerate()
            .filter(|(_, &label)| label == i)
            .map(|(idx, _)| idx)
            .collect();
        
        if !cluster_points_indices.is_empty() {
            let centroid = model.centroids().row(i);
            let distances: Vec<f64> = cluster_points_indices.iter()
                .map(|&idx| records.row(idx).sq_l2_dist(&centroid).unwrap_or(0.0).sqrt())
                .collect();
            
            let mean = distances.iter().sum::<f64>() / distances.len() as f64;
            let std_dev = (distances.iter().map(|&d| (d - mean).powi(2)).sum::<f64>() / distances.len() as f64).sqrt();
            thresholds.push(mean + 2.0 * std_dev); // Threshold is Mean + 2 * StdDev
        } else {
            thresholds.push(f64::MAX);
        }
    }

    let trained_model = Model { centroids, thresholds };
    let file = File::create("model.json").expect("Failed to create model file");
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &trained_model).expect("Failed to save model");
}