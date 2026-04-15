package nl.jasper.jtm.trust

import android.util.Log

/**
 * Trust Kernel JNI Bridge — AES-256-GCM Bifurcation Encryption
 *
 * Kotlin wrapper around libtrust_kernel_android.so.
 * Provides: encrypted messaging, intent routing, TIBET provenance, financial triage.
 *
 * Pattern follows TibetBridge.kt (voip/ChaCha20), but uses AES-256-GCM
 * via X25519 + HKDF for storage/transport encryption.
 *
 * Usage:
 *   val session = TrustKernelBridge.createSession(key)
 *   val sealed = TrustKernelBridge.seal(session, plaintext)
 *   val opened = TrustKernelBridge.open(session, sealed)
 *   TrustKernelBridge.destroySession(session)
 */
object TrustKernelBridge {

    private const val TAG = "TrustKernel"

    /** Native library loaded flag */
    private var loaded = false

    /** Active sessions (sessionId → native handle) */
    private val sessions = mutableMapOf<String, Long>()

    init {
        try {
            System.loadLibrary("trust_kernel_android")
            loaded = true
            Log.i(TAG, "libtrust_kernel_android.so loaded - ${getVersion()}")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load libtrust_kernel_android.so: ${e.message}")
            loaded = false
        }
    }

    /** Check if Trust Kernel encryption is available */
    fun isAvailable(): Boolean = loaded

    // ═══════════════════════════════════════════════════════════════
    // Session Management
    // ═══════════════════════════════════════════════════════════════

    /**
     * Create an encryption session from a 32-byte key.
     *
     * @param sessionId  Unique identifier for this session
     * @param key        32-byte encryption key
     * @return true if session created successfully
     */
    fun createSession(sessionId: String, key: ByteArray): Boolean {
        if (!loaded) {
            Log.w(TAG, "Cannot create session - library not loaded")
            return false
        }
        if (key.size != 32) {
            Log.e(TAG, "Key must be 32 bytes, got ${key.size}")
            return false
        }

        val handle = nativeCreateSession(key)
        if (handle == 0L) {
            Log.e(TAG, "Session creation failed for $sessionId")
            return false
        }

        sessions[sessionId] = handle
        Log.i(TAG, "Session created: $sessionId")
        return true
    }

    /**
     * Create a session with a random key (for testing/demos).
     */
    fun createRandomSession(sessionId: String): Boolean {
        if (!loaded) return false

        val handle = nativeCreateRandomSession()
        if (handle == 0L) return false

        sessions[sessionId] = handle
        Log.i(TAG, "Random session created: $sessionId")
        return true
    }

    // ═══════════════════════════════════════════════════════════════
    // Encryption (AES-256-GCM via Bifurcation)
    // ═══════════════════════════════════════════════════════════════

    /**
     * Seal (encrypt) data using AES-256-GCM Bifurcation.
     *
     * @param sessionId  Session identifier
     * @param plaintext  Data to encrypt
     * @return Sealed bytes (ephemeral_pub + nonce + ciphertext), or null on error
     */
    fun seal(sessionId: String, plaintext: ByteArray): ByteArray? {
        val handle = sessions[sessionId] ?: run {
            Log.w(TAG, "No session found: $sessionId")
            return null
        }
        return nativeSeal(handle, plaintext)
    }

    /**
     * Open (decrypt) sealed data.
     *
     * @param sessionId  Session identifier
     * @param sealed     Sealed bytes from seal()
     * @return Decrypted plaintext, or null on error (wrong key, tampered data)
     */
    fun open(sessionId: String, sealed: ByteArray): ByteArray? {
        val handle = sessions[sessionId] ?: run {
            Log.w(TAG, "No session found: $sessionId")
            return null
        }
        return nativeOpen(handle, sealed)
    }

    // ═══════════════════════════════════════════════════════════════
    // MUX Intent Routing
    // ═══════════════════════════════════════════════════════════════

    /**
     * Route an intent to a backend target.
     *
     * @param intent  Intent string (e.g., "chat:send", "call:voice:start", "finance:transfer")
     * @return JSON with routing info: target, action, protocol, encrypted
     */
    fun routeIntent(intent: String): String? {
        if (!loaded) return null
        return nativeRouteIntent(intent)
    }

    // ═══════════════════════════════════════════════════════════════
    // TIBET Provenance
    // ═══════════════════════════════════════════════════════════════

    /**
     * Mint a TIBET provenance token.
     *
     * @param action     What happened (e.g., "chat:send", "finance:transfer")
     * @param actor      Who did it (e.g., "user.aint")
     * @param clearance  JIS clearance level (0-4)
     * @return JSON TIBET token with 4 dimensions (ERIN/ERAAN/EROMHEEN/ERACHTER)
     */
    fun mintToken(action: String, actor: String, clearance: Int): String? {
        if (!loaded) return null
        return nativeMintToken(action, actor, clearance)
    }

    // ═══════════════════════════════════════════════════════════════
    // Financial Triage
    // ═══════════════════════════════════════════════════════════════

    /**
     * Evaluate financial triage level.
     *
     * @param amountCents  Amount in cents (e.g., 50000 = 500.00 EUR)
     * @param action       Financial action (e.g., "transfer", "receipt", "check")
     * @return Triage level: 0=L0(auto), 1=L1(operator), 2=L2(senior), 3=L3(ceremony)
     */
    fun triageLevel(amountCents: Long, action: String): Int {
        if (!loaded) return -1
        return nativeTriageLevel(amountCents, action)
    }

    // ═══════════════════════════════════════════════════════════════
    // JIS Identity
    // ═══════════════════════════════════════════════════════════════

    /**
     * Create a JIS claim from a DID public key.
     *
     * @param didPubHex  DID public key (base64/hex from Android Keystore)
     * @param identity   Identity string (e.g., "user.aint")
     * @param clearance  Clearance level (0-4)
     * @return JSON JIS claim
     */
    fun createJisClaim(didPubHex: String, identity: String, clearance: Int): String? {
        if (!loaded) return null
        return nativeCreateJisClaim(didPubHex, identity, clearance)
    }

    // ═══════════════════════════════════════════════════════════════
    // Session Lifecycle
    // ═══════════════════════════════════════════════════════════════

    fun hasSession(sessionId: String): Boolean = sessions.containsKey(sessionId)

    fun destroySession(sessionId: String) {
        val handle = sessions.remove(sessionId) ?: return
        nativeDestroySession(handle)
        Log.i(TAG, "Session destroyed: $sessionId")
    }

    fun destroyAll() {
        sessions.values.forEach { nativeDestroySession(it) }
        sessions.clear()
        Log.i(TAG, "All sessions destroyed")
    }

    fun getVersion(): String {
        if (!loaded) return "not loaded"
        return nativeVersion() ?: "unknown"
    }

    // ═══════════════════════════════════════════════════════════════
    // Native JNI Methods
    //
    // Auto-resolved: Java_nl_jasper_jtm_trust_TrustKernelBridge_*
    // ═══════════════════════════════════════════════════════════════

    @JvmStatic private external fun nativeCreateSession(key: ByteArray): Long
    @JvmStatic private external fun nativeCreateRandomSession(): Long
    @JvmStatic private external fun nativeSeal(handle: Long, plaintext: ByteArray): ByteArray?
    @JvmStatic private external fun nativeOpen(handle: Long, ciphertext: ByteArray): ByteArray?
    @JvmStatic private external fun nativeRouteIntent(intent: String): String?
    @JvmStatic private external fun nativeMintToken(action: String, actor: String, clearance: Int): String?
    @JvmStatic private external fun nativeTriageLevel(amountCents: Long, action: String): Int
    @JvmStatic private external fun nativeCreateJisClaim(didPubHex: String, identity: String, clearance: Int): String?
    @JvmStatic private external fun nativeDestroySession(handle: Long)
    @JvmStatic private external fun nativeVersion(): String?
}
