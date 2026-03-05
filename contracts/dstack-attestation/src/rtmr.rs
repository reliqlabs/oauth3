use sha2::{Digest, Sha384};

use crate::msg::EventLogEntry;
use crate::state::ExpectedEvents;

/// IMR index tag for RTMR3 events, as little-endian u32 bytes.
/// 0x08000001 in LE = [0x01, 0x00, 0x00, 0x08]
const RTMR3_TAG: [u8; 4] = [0x01, 0x00, 0x00, 0x08];

/// Replay the RTMR3 hash chain from an event log.
///
/// Algorithm (from dstack cc-eventlog):
///   RTMR3 = [0u8; 48]
///   for each event:
///     digest = SHA384( TAG || b":" || event_name || b":" || payload )
///     RTMR3 = SHA384( RTMR3 || digest )
pub fn replay_rtmr3(events: &[EventLogEntry]) -> [u8; 48] {
    let mut rtmr3 = [0u8; 48];

    for entry in events {
        let mut hasher = Sha384::new();
        hasher.update(RTMR3_TAG);
        hasher.update(b":");
        hasher.update(entry.event.as_bytes());
        hasher.update(b":");
        hasher.update(entry.payload.as_slice());
        let digest: [u8; 48] = hasher.finalize().into();

        let mut extend_hasher = Sha384::new();
        extend_hasher.update(rtmr3);
        extend_hasher.update(digest);
        rtmr3 = extend_hasher.finalize().into();
    }

    rtmr3
}

/// Validate deterministic events against expected values.
/// Returns a list of mismatch descriptions (empty = all good).
pub fn validate_events(events: &[EventLogEntry], expected: &ExpectedEvents) -> Vec<String> {
    let mut mismatches = Vec::new();

    for entry in events {
        let payload_hex = hex::encode(entry.payload.as_slice());

        match entry.event.as_str() {
            "compose-hash" => {
                if let Some(ref exp) = expected.compose_hash {
                    if &payload_hex != exp {
                        mismatches.push(format!(
                            "compose-hash: expected={}, actual={}",
                            exp, payload_hex
                        ));
                    }
                }
            }
            "os-image-hash" => {
                if let Some(ref exp) = expected.os_image_hash {
                    if &payload_hex != exp {
                        mismatches.push(format!(
                            "os-image-hash: expected={}, actual={}",
                            exp, payload_hex
                        ));
                    }
                }
            }
            _ => {} // other events not checked
        }
    }

    mismatches
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::Binary;

    #[test]
    fn test_replay_rtmr3_empty() {
        let result = replay_rtmr3(&[]);
        assert_eq!(result, [0u8; 48]);
    }

    #[test]
    fn test_replay_rtmr3_single_event() {
        let events = vec![EventLogEntry {
            event: "test-event".to_string(),
            payload: Binary::from(b"test-payload".to_vec()),
        }];

        let result = replay_rtmr3(&events);

        // Manually compute expected:
        // digest = SHA384([0x01,0x00,0x00,0x08] || b":" || b"test-event" || b":" || b"test-payload")
        let mut hasher = Sha384::new();
        hasher.update([0x01, 0x00, 0x00, 0x08]);
        hasher.update(b":");
        hasher.update(b"test-event");
        hasher.update(b":");
        hasher.update(b"test-payload");
        let digest: [u8; 48] = hasher.finalize().into();

        // rtmr3 = SHA384([0u8; 48] || digest)
        let mut extend = Sha384::new();
        extend.update([0u8; 48]);
        extend.update(digest);
        let expected: [u8; 48] = extend.finalize().into();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_replay_rtmr3_chain() {
        let events = vec![
            EventLogEntry {
                event: "a".to_string(),
                payload: Binary::from(b"1".to_vec()),
            },
            EventLogEntry {
                event: "b".to_string(),
                payload: Binary::from(b"2".to_vec()),
            },
        ];

        let result = replay_rtmr3(&events);

        // First event
        let mut h1 = Sha384::new();
        h1.update([0x01, 0x00, 0x00, 0x08]);
        h1.update(b":");
        h1.update(b"a");
        h1.update(b":");
        h1.update(b"1");
        let d1: [u8; 48] = h1.finalize().into();

        let mut e1 = Sha384::new();
        e1.update([0u8; 48]);
        e1.update(d1);
        let r1: [u8; 48] = e1.finalize().into();

        // Second event
        let mut h2 = Sha384::new();
        h2.update([0x01, 0x00, 0x00, 0x08]);
        h2.update(b":");
        h2.update(b"b");
        h2.update(b":");
        h2.update(b"2");
        let d2: [u8; 48] = h2.finalize().into();

        let mut e2 = Sha384::new();
        e2.update(r1);
        e2.update(d2);
        let expected: [u8; 48] = e2.finalize().into();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_validate_events_no_expected() {
        let events = vec![EventLogEntry {
            event: "compose-hash".to_string(),
            payload: Binary::from(vec![0xab, 0xcd]),
        }];
        let expected = ExpectedEvents {
            compose_hash: None,
            os_image_hash: None,
        };
        assert!(validate_events(&events, &expected).is_empty());
    }

    #[test]
    fn test_validate_events_match() {
        let events = vec![EventLogEntry {
            event: "compose-hash".to_string(),
            payload: Binary::from(vec![0xab, 0xcd]),
        }];
        let expected = ExpectedEvents {
            compose_hash: Some("abcd".to_string()),
            os_image_hash: None,
        };
        assert!(validate_events(&events, &expected).is_empty());
    }

    #[test]
    fn test_validate_events_mismatch() {
        let events = vec![EventLogEntry {
            event: "compose-hash".to_string(),
            payload: Binary::from(vec![0xab, 0xcd]),
        }];
        let expected = ExpectedEvents {
            compose_hash: Some("1234".to_string()),
            os_image_hash: None,
        };
        let mismatches = validate_events(&events, &expected);
        assert_eq!(mismatches.len(), 1);
        assert!(mismatches[0].contains("compose-hash"));
    }

    #[test]
    fn test_validate_events_unknown_ignored() {
        let events = vec![EventLogEntry {
            event: "custom-thing".to_string(),
            payload: Binary::from(vec![0xff]),
        }];
        let expected = ExpectedEvents {
            compose_hash: Some("deadbeef".to_string()),
            os_image_hash: None,
        };
        // Unknown event name → not checked, compose-hash never seen → no mismatch
        assert!(validate_events(&events, &expected).is_empty());
    }
}
