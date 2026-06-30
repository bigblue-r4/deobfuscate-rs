//! Demonstrates HMAC-SHA256 signing and chained verification of AuditRecords.
//! Run: cargo run --example audit_sign_verify

#[cfg(feature = "audit")]
fn main() {
    let key = b"my-secret-signing-key";

    // ── Record 1 ──────────────────────────────────────────────────────────────
    let r1 = deobfuscate::analyze("%69%67%6e%6f%72%65 all instructions");
    let mut rec1 = r1.audit.clone();
    rec1.sign(key);

    println!("Record 1");
    println!("  input_hash : {}", rec1.input_hash);
    println!("  score      : {:.2}", rec1.obfuscation_score);
    println!("  blocked    : {}", rec1.blocked);
    println!(
        "  signature  : {}",
        rec1.signature.as_deref().unwrap_or("none")
    );
    println!("  verify(ok) : {}", rec1.verify(key));
    println!();

    // ── Record 2 — chained to record 1 ───────────────────────────────────────
    let r2 = deobfuscate::analyze(r"\x73\x68\x65\x6c\x6c");
    let mut rec2 = r2.audit.clone();
    rec2.prev_hmac = rec1.signature.clone(); // link to previous record
    rec2.sign(key);

    println!("Record 2 (chained)");
    println!(
        "  prev_hmac  : {}",
        rec2.prev_hmac.as_deref().unwrap_or("none")
    );
    println!(
        "  signature  : {}",
        rec2.signature.as_deref().unwrap_or("none")
    );
    println!("  verify(ok) : {}", rec2.verify(key));
    println!();

    // ── Tamper detection ──────────────────────────────────────────────────────
    let mut tampered = rec2.clone();
    tampered.obfuscation_score = 0.0; // attacker tries to zero the score
    println!("After tampering with obfuscation_score:");
    println!("  verify(tampered) : {}", tampered.verify(key)); // false

    let mut broken_chain = rec2.clone();
    broken_chain.prev_hmac = Some("00".repeat(32)); // attacker breaks the chain
    println!("After replacing prev_hmac:");
    println!("  verify(broken chain) : {}", broken_chain.verify(key)); // false
}

#[cfg(not(feature = "audit"))]
fn main() {
    eprintln!("This example requires the 'audit' feature (enabled by default).");
    eprintln!("Run: cargo run --example audit_sign_verify");
}
