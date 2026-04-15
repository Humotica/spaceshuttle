//! Lightweight MUX intent router for Android.
//!
//! Maps intent strings to backend targets, matching the
//! tibet_mux.py routes on the server side.

use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct RouteResult {
    pub intent: String,
    pub target: String,
    pub action: String,
    pub protocol: String,
    pub encrypted: bool,
}

/// Route an intent string to a backend target.
///
/// Intent format: `category:action[:modifier]`
///
/// Routes (matching tibet_mux.py):
///   chat:send      → ipoll (encrypted)
///   chat:receive   → ipoll (encrypted)
///   call:voice:*   → voip
///   call:video:*   → webrtc
///   file:send      → sync (encrypted)
///   file:sync      → sync
///   finance:check  → triage (encrypted)
///   finance:transfer → triage (encrypted, L1+)
///   finance:receipt → triage (encrypted)
///   ai:query       → kit-brain
///   ai:generate    → kit-brain
pub fn route_intent(intent: &str) -> RouteResult {
    let parts: Vec<&str> = intent.split(':').collect();
    let category = parts.first().copied().unwrap_or("unknown");
    let action = parts.get(1).copied().unwrap_or("default");

    match category {
        "chat" => RouteResult {
            intent: intent.to_string(),
            target: "ipoll".to_string(),
            action: action.to_string(),
            protocol: "https".to_string(),
            encrypted: true,
        },
        "call" => {
            let is_video = action == "video";
            RouteResult {
                intent: intent.to_string(),
                target: if is_video { "webrtc" } else { "voip" }.to_string(),
                action: parts.get(2).copied().unwrap_or("start").to_string(),
                protocol: if is_video { "webrtc" } else { "iax2" }.to_string(),
                encrypted: true,
            }
        }
        "file" => RouteResult {
            intent: intent.to_string(),
            target: "sync".to_string(),
            action: action.to_string(),
            protocol: "https".to_string(),
            encrypted: true,
        },
        "finance" => RouteResult {
            intent: intent.to_string(),
            target: "triage".to_string(),
            action: action.to_string(),
            protocol: "https".to_string(),
            encrypted: true,
        },
        "ai" => RouteResult {
            intent: intent.to_string(),
            target: "kit-brain".to_string(),
            action: action.to_string(),
            protocol: "https".to_string(),
            encrypted: false,
        },
        _ => RouteResult {
            intent: intent.to_string(),
            target: "unknown".to_string(),
            action: action.to_string(),
            protocol: "none".to_string(),
            encrypted: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_routes_to_ipoll() {
        let r = route_intent("chat:send");
        assert_eq!(r.target, "ipoll");
        assert!(r.encrypted);
    }

    #[test]
    fn voice_routes_to_voip() {
        let r = route_intent("call:voice:start");
        assert_eq!(r.target, "voip");
        assert_eq!(r.protocol, "iax2");
    }

    #[test]
    fn video_routes_to_webrtc() {
        let r = route_intent("call:video:start");
        assert_eq!(r.target, "webrtc");
        assert_eq!(r.protocol, "webrtc");
    }

    #[test]
    fn finance_routes_to_triage() {
        let r = route_intent("finance:transfer");
        assert_eq!(r.target, "triage");
        assert!(r.encrypted);
    }

    #[test]
    fn unknown_intent() {
        let r = route_intent("banana");
        assert_eq!(r.target, "unknown");
    }
}
