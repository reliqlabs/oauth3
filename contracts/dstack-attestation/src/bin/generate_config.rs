//! Generate expected verification config for the dstack-attestation contract.
//!
//! Two modes:
//!
//! 1. From an existing app-compose.json manifest:
//!    generate-config --manifest <path> [--os-image-hash <hex>]
//!
//! 2. From a docker-compose.yml (wraps into a dstack manifest):
//!    generate-config --docker-compose <path> [--name <app>] [--os-image-hash <hex>]
//!
//! Output: JSON with compose_hash, os_image_hash, and the full SetExpectedEvents msg.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{env, fs, process};

fn usage() -> ! {
    eprintln!(
        "Usage:
  generate-config --manifest <app-compose.json> [--os-image-hash <hex>]
  generate-config --docker-compose <docker-compose.yml> [--name <app-name>] [--os-image-hash <hex>]

Computes compose-hash (SHA256 of normalized manifest) and outputs
the expected events config for the dstack-attestation contract.

The os-image-hash is the SHA256 of the dstack OS rootfs image.
Get it from a running instance's /info endpoint or dstack release metadata."
    );
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut manifest_path: Option<String> = None;
    let mut compose_path: Option<String> = None;
    let mut app_name = "app".to_string();
    let mut os_image_hash: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = Some(args.get(i).unwrap_or_else(|| usage()).clone());
            }
            "--docker-compose" => {
                i += 1;
                compose_path = Some(args.get(i).unwrap_or_else(|| usage()).clone());
            }
            "--name" => {
                i += 1;
                app_name = args.get(i).unwrap_or_else(|| usage()).clone();
            }
            "--os-image-hash" => {
                i += 1;
                os_image_hash = Some(args.get(i).unwrap_or_else(|| usage()).clone());
            }
            "--help" | "-h" => usage(),
            other => {
                eprintln!("Unknown argument: {}", other);
                usage();
            }
        }
        i += 1;
    }

    let manifest: Value = if let Some(path) = manifest_path {
        let content = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Failed to read {}: {}", path, e);
            process::exit(1);
        });
        serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!("Failed to parse {}: {}", path, e);
            process::exit(1);
        })
    } else if let Some(path) = compose_path {
        let compose_content = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Failed to read {}: {}", path, e);
            process::exit(1);
        });
        let encoded = B64.encode(compose_content.as_bytes());
        json!({
            "manifest_version": 2,
            "name": app_name,
            "runner": "docker-compose",
            "docker_compose": {
                "docker_compose_file": encoded
            },
            "docker_config": {}
        })
    } else {
        eprintln!("Must specify --manifest or --docker-compose");
        usage();
    };

    // Normalize: set docker_config to empty object, then compact JSON
    let mut obj = match manifest {
        Value::Object(m) => m,
        _ => {
            eprintln!("Manifest must be a JSON object");
            process::exit(1);
        }
    };
    obj.insert("docker_config".to_string(), Value::Object(Map::new()));

    let normalized = serde_json::to_string(&Value::Object(obj.clone())).unwrap();
    let compose_hash = hex::encode(Sha256::digest(normalized.as_bytes()));

    // app-id = first 20 bytes of compose hash
    let hash_bytes = Sha256::digest(normalized.as_bytes());
    let app_id = hex::encode(&hash_bytes[..20]);

    let output = json!({
        "compose_hash": compose_hash,
        "app_id": app_id,
        "os_image_hash": os_image_hash,
        "normalized_manifest": normalized,
        "set_expected_events_msg": {
            "set_expected_events": {
                "compose_hash": compose_hash,
                "os_image_hash": os_image_hash,
            }
        },
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
