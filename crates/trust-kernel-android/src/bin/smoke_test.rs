//! Trust Kernel Android — Smoke Test
//!
//! Standalone binary that runs on Android via `adb shell`.
//! Tests all 5 modules without JNI/JVM.

use std::time::Instant;

// Access internal modules via the library
// (modules are pub because of JNI, so we can use them directly)
use trust_kernel_android::bifurcation::AndroidBifurcation;
use trust_kernel_android::mux_lite;
use trust_kernel_android::jis_bridge;
use trust_kernel_android::tibet_mint;
use trust_kernel_android::triage_level;

fn main() {
    println!("═══════════════════════════════════════════════════════");
    println!("  Trust Kernel Android — Smoke Test");
    println!("  Running on: {}", std::env::consts::ARCH);
    println!("═══════════════════════════════════════════════════════\n");

    let mut passed = 0;
    let mut failed = 0;
    let t_total = Instant::now();

    // ── 1. Bifurcation: AES-256-GCM seal/open ──
    print!("[1/5] Bifurcation AES-256-GCM ... ");
    let t0 = Instant::now();
    let key = [42u8; 32];
    let mut session = AndroidBifurcation::new(key);
    let plaintext = b"Trust Kernel op Android! AES-256-GCM via ARMv8 Crypto Extensions.";

    let sealed = session.seal(plaintext);
    let seal_us = t0.elapsed().as_micros();

    let t1 = Instant::now();
    let opened = session.open(&sealed);
    let open_us = t1.elapsed().as_micros();

    match opened {
        Some(ref data) if data == plaintext => {
            println!("PASS  (seal: {}us, open: {}us, wire: {} bytes)",
                seal_us, open_us, sealed.len());
            passed += 1;
        }
        _ => { println!("FAIL"); failed += 1; }
    }

    // ── 1b. Wrong key must fail ──
    print!("[1b]  Wrong key rejected ... ");
    let wrong_session = AndroidBifurcation::new([99u8; 32]);
    match wrong_session.open(&sealed) {
        None => { println!("PASS  (correctly rejected)"); passed += 1; }
        Some(_) => { println!("FAIL  (should not decrypt!)"); failed += 1; }
    }

    // ── 1c. Throughput test ──
    print!("[1c]  Throughput (1000 seals) ... ");
    let mut session2 = AndroidBifurcation::new([7u8; 32]);
    let data_4k = vec![0xABu8; 4096];
    let t_bench = Instant::now();
    for _ in 0..1000 {
        let _ = session2.seal(&data_4k);
    }
    let bench_ms = t_bench.elapsed().as_millis();
    let throughput_mbps = (4096.0 * 1000.0) / (bench_ms as f64 * 1000.0);
    println!("PASS  ({}ms = {:.1} MB/s)", bench_ms, throughput_mbps);
    passed += 1;

    println!();

    // ── 2. MUX Intent Routing ──
    print!("[2/5] MUX Intent Routing ... ");
    let routes = vec![
        ("chat:send", "ipoll", true),
        ("call:voice:start", "voip", true),
        ("call:video:start", "webrtc", true),
        ("finance:transfer", "triage", true),
        ("file:sync", "sync", true),
        ("ai:query", "kit-brain", false),
    ];
    let mut mux_ok = true;
    for (intent, expected_target, expected_encrypted) in &routes {
        let r = mux_lite::route_intent(intent);
        if r.target != *expected_target || r.encrypted != *expected_encrypted {
            println!("FAIL  ({} -> {} (expected {}))", intent, r.target, expected_target);
            mux_ok = false;
            break;
        }
    }
    if mux_ok {
        println!("PASS  ({} routes verified)", routes.len());
        passed += 1;
    } else {
        failed += 1;
    }

    println!();

    // ── 3. JIS Bridge ──
    print!("[3/5] JIS Bridge (DID claim) ... ");
    let claim = jis_bridge::create_claim(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest",
        "jasper.aint",
        3, // SECRET
    );
    if claim.clearance == 3
        && claim.clearance_label == "SECRET"
        && claim.identity == "jasper.aint"
        && !claim.fingerprint.is_empty()
    {
        println!("PASS  (identity={}, clearance={}, fp={})",
            claim.identity, claim.clearance_label, claim.fingerprint);
        passed += 1;
    } else {
        println!("FAIL"); failed += 1;
    }

    println!();

    // ── 4. TIBET Token Minting ──
    print!("[4/5] TIBET Token Mint ... ");
    let token = tibet_mint::mint_token("finance:transfer", "jasper.aint", 3);
    if token.token_type == "FINANCIAL_ACTION"
        && token.erin == "action:finance:transfer"
        && !token.token_id.is_empty()
        && !token.seal.is_empty()
    {
        println!("PASS");
        println!("       token_id: {}", token.token_id);
        println!("       type:     {}", token.token_type);
        println!("       erin:     {}", token.erin);
        println!("       eraan:    {}", token.eraan);
        println!("       eromheen: {}", token.eromheen);
        println!("       erachter: {}", token.erachter);
        println!("       seal:     {}", token.seal);
        passed += 1;
    } else {
        println!("FAIL"); failed += 1;
    }

    println!();

    // ── 5. Financial Triage ──
    print!("[5/5] Financial Triage ... ");
    let tests = vec![
        (10.0, "transfer", 0, "L0"),
        (200.0, "transfer", 1, "L1"),
        (2000.0, "transfer", 2, "L2"),
        (10000.0, "transfer", 3, "L3"),
        (0.0, "close", 3, "L3"),
        (999999.0, "check", 0, "L0"),
    ];
    let mut triage_ok = true;
    for (amount, action, expected, label) in &tests {
        let level = triage_level::evaluate(*amount, action);
        if level != *expected {
            println!("FAIL  ({}EUR {} -> L{} expected {})", amount, action, level, label);
            triage_ok = false;
            break;
        }
    }
    if triage_ok {
        println!("PASS  ({} levels verified)", tests.len());
        for (amount, action, expected, label) in &tests {
            println!("       {:>8.0}EUR {:10} -> {}", amount, action, label);
        }
        passed += 1;
    } else {
        failed += 1;
    }

    // ── Summary ──
    let total_ms = t_total.elapsed().as_millis();
    println!();
    println!("═══════════════════════════════════════════════════════");
    println!("  Result: {} passed, {} failed ({} ms)", passed, failed, total_ms);
    println!("  Arch: {} | OS: {}", std::env::consts::ARCH, std::env::consts::OS);
    println!("═══════════════════════════════════════════════════════");

    if failed > 0 {
        std::process::exit(1);
    }
}
