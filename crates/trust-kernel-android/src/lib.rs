//! Trust Kernel for Android — JNI bridge
//!
//! AES-256-GCM Bifurcation encryption, MUX intent routing,
//! TIBET provenance tokens, and financial triage levels.
//!
//! Loaded as `librust_kernel_android.so` via System.loadLibrary().

mod bifurcation;
mod mux_lite;
mod jis_bridge;
mod tibet_mint;
mod triage_level;

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong, jstring};

use bifurcation::AndroidBifurcation;

// ═══════════════════════════════════════════════════════════════
// Session Handle Management
//
// Each session gets a heap-allocated AndroidBifurcation,
// returned as a jlong (pointer). Kotlin side stores and passes
// this handle back for each operation.
// ═══════════════════════════════════════════════════════════════

/// Create a new Bifurcation session from a 32-byte key.
/// Returns a native handle (pointer) or 0 on error.
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeCreateSession(
    env: JNIEnv,
    _class: JClass,
    key_bytes: JByteArray,
) -> jlong {
    let key = match env.convert_byte_array(&key_bytes) {
        Ok(k) => k,
        Err(_) => return 0,
    };
    if key.len() != 32 {
        return 0;
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let session = Box::new(AndroidBifurcation::new(key_arr));
    Box::into_raw(session) as jlong
}

/// Create a session with a random key (for testing / demos).
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeCreateRandomSession(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let session = Box::new(AndroidBifurcation::random());
    Box::into_raw(session) as jlong
}

/// Seal (encrypt) plaintext bytes. Returns ciphertext as byte[].
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeSeal(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    plaintext: JByteArray,
) -> jbyteArray {
    let null_result = std::ptr::null_mut();

    if handle == 0 {
        return null_result;
    }
    let session = unsafe { &mut *(handle as *mut AndroidBifurcation) };

    let data = match env.convert_byte_array(&plaintext) {
        Ok(d) => d,
        Err(_) => return null_result,
    };

    let ciphertext = session.seal(&data);

    match env.byte_array_from_slice(&ciphertext) {
        Ok(arr) => arr.into_raw(),
        Err(_) => null_result,
    }
}

/// Open (decrypt) ciphertext bytes. Returns plaintext as byte[].
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeOpen(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    ciphertext: JByteArray,
) -> jbyteArray {
    let null_result = std::ptr::null_mut();

    if handle == 0 {
        return null_result;
    }
    let session = unsafe { &mut *(handle as *mut AndroidBifurcation) };

    let data = match env.convert_byte_array(&ciphertext) {
        Ok(d) => d,
        Err(_) => return null_result,
    };

    match session.open(&data) {
        Some(plaintext) => match env.byte_array_from_slice(&plaintext) {
            Ok(arr) => arr.into_raw(),
            Err(_) => null_result,
        },
        None => null_result,
    }
}

/// Route an intent string to a backend target.
/// Returns JSON: {"target": "ipoll", "action": "send", ...}
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeRouteIntent(
    mut env: JNIEnv,
    _class: JClass,
    intent: JString,
) -> jstring {
    let null_result = std::ptr::null_mut();

    let intent_str: String = match env.get_string(&intent) {
        Ok(s) => s.into(),
        Err(_) => return null_result,
    };

    let result = mux_lite::route_intent(&intent_str);
    let json = serde_json::to_string(&result).unwrap_or_default();

    match env.new_string(&json) {
        Ok(s) => s.into_raw(),
        Err(_) => null_result,
    }
}

/// Mint a TIBET provenance token.
/// Returns JSON with the 4 dimensions (ERIN/ERAAN/EROMHEEN/ERACHTER).
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeMintToken(
    mut env: JNIEnv,
    _class: JClass,
    action: JString,
    actor: JString,
    clearance: jint,
) -> jstring {
    let null_result = std::ptr::null_mut();

    let action_str: String = match env.get_string(&action) {
        Ok(s) => s.into(),
        Err(_) => return null_result,
    };
    let actor_str: String = match env.get_string(&actor) {
        Ok(s) => s.into(),
        Err(_) => return null_result,
    };

    let token = tibet_mint::mint_token(&action_str, &actor_str, clearance as u8);
    let json = serde_json::to_string_pretty(&token).unwrap_or_default();

    match env.new_string(&json) {
        Ok(s) => s.into_raw(),
        Err(_) => null_result,
    }
}

/// Evaluate financial triage level for an amount + action.
/// Returns: 0 = L0 (auto), 1 = L1 (operator), 2 = L2 (senior), 3 = L3 (ceremony)
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeTriageLevel(
    mut env: JNIEnv,
    _class: JClass,
    amount: jlong,
    action: JString,
) -> jint {
    let action_str: String = match env.get_string(&action) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    triage_level::evaluate(amount as f64 / 100.0, &action_str) as jint
}

/// Create a JIS claim from a DID public key hex string.
/// Returns JSON claim that can be used for Bifurcation access.
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeCreateJisClaim(
    mut env: JNIEnv,
    _class: JClass,
    did_pub_hex: JString,
    identity: JString,
    clearance: jint,
) -> jstring {
    let null_result = std::ptr::null_mut();

    let pub_hex: String = match env.get_string(&did_pub_hex) {
        Ok(s) => s.into(),
        Err(_) => return null_result,
    };
    let identity_str: String = match env.get_string(&identity) {
        Ok(s) => s.into(),
        Err(_) => return null_result,
    };

    let claim = jis_bridge::create_claim(&pub_hex, &identity_str, clearance as u8);
    let json = serde_json::to_string(&claim).unwrap_or_default();

    match env.new_string(&json) {
        Ok(s) => s.into_raw(),
        Err(_) => null_result,
    }
}

/// Destroy a session and wipe keys from memory.
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeDestroySession(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let session = unsafe { Box::from_raw(handle as *mut AndroidBifurcation) };
        drop(session); // Explicit drop, key memory is zeroed in Drop impl
    }
}

/// Get library version string.
#[no_mangle]
pub extern "system" fn Java_nl_jasper_jtm_trust_TrustKernelBridge_nativeVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let version = format!("trust-kernel-android {}", env!("CARGO_PKG_VERSION"));
    match env.new_string(&version) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
