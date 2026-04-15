package nl.jasper.jtm.trust

import android.util.Log
import nl.jasper.jtm.jis.JisKeyManager
import android.content.Context
import java.security.SecureRandom

/**
 * Trust Kernel Manager — High-Level API
 *
 * Wraps TrustKernelBridge with session management, JIS integration,
 * and convenience methods for encrypted messaging.
 */
class TrustKernelManager private constructor(
    private val context: Context
) {
    private val jisKeyManager = JisKeyManager.getInstance(context)

    companion object {
        private const val TAG = "TrustKernelMgr"
        private const val SESSION_MESSAGING = "messaging"
        private const val SESSION_FINANCE = "finance"

        @Volatile
        private var instance: TrustKernelManager? = null

        fun getInstance(context: Context): TrustKernelManager {
            return instance ?: synchronized(this) {
                instance ?: TrustKernelManager(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }

    /** Initialize Trust Kernel with a derived session key */
    fun initialize(): Boolean {
        if (!TrustKernelBridge.isAvailable()) {
            Log.w(TAG, "Trust Kernel native library not available")
            return false
        }

        // Create default sessions
        val messagingKey = deriveSessionKey("messaging")
        val financeKey = deriveSessionKey("finance")

        val msgOk = TrustKernelBridge.createSession(SESSION_MESSAGING, messagingKey)
        val finOk = TrustKernelBridge.createSession(SESSION_FINANCE, financeKey)

        Log.i(TAG, "Initialized: messaging=$msgOk finance=$finOk version=${TrustKernelBridge.getVersion()}")
        return msgOk && finOk
    }

    // ═══════════════════════════════════════════════════════════════
    // Encrypted Messaging (iPoll integration)
    // ═══════════════════════════════════════════════════════════════

    /**
     * Encrypt a message for iPoll transmission.
     *
     * @param plaintext  Message text (UTF-8)
     * @return Sealed bytes ready for iPoll PUSH, or null on error
     */
    fun encryptMessage(plaintext: String): ByteArray? {
        return TrustKernelBridge.seal(SESSION_MESSAGING, plaintext.toByteArray(Charsets.UTF_8))
    }

    /**
     * Decrypt a received iPoll message.
     *
     * @param sealed  Sealed bytes from iPoll PULL
     * @return Decrypted message text, or null on error
     */
    fun decryptMessage(sealed: ByteArray): String? {
        val bytes = TrustKernelBridge.open(SESSION_MESSAGING, sealed) ?: return null
        return String(bytes, Charsets.UTF_8)
    }

    // ═══════════════════════════════════════════════════════════════
    // Intent Routing
    // ═══════════════════════════════════════════════════════════════

    /**
     * Route an intent through the Trust Kernel MUX.
     *
     * @param intent  e.g., "chat:send", "call:voice:start", "finance:transfer"
     * @return JSON with routing info
     */
    fun routeIntent(intent: String): String? {
        return TrustKernelBridge.routeIntent(intent)
    }

    // ═══════════════════════════════════════════════════════════════
    // TIBET Provenance
    // ═══════════════════════════════════════════════════════════════

    /**
     * Mint a TIBET token with device identity.
     *
     * @param action  What happened
     * @return JSON TIBET token signed with device identity
     */
    fun mintToken(action: String): String? {
        val did = jisKeyManager.getOrCreateDID()
        val esimBoost = EsimTrustSignal.getInstance(context).getTrustBoost()
        val baseClearance = 2 // CONFIDENTIAL default
        val clearance = if (esimBoost > 0) minOf(baseClearance + 1, 4) else baseClearance

        return TrustKernelBridge.mintToken(action, did.publicKeyHex, clearance)
    }

    // ═══════════════════════════════════════════════════════════════
    // JIS Claim with eSIM Trust Boost
    // ═══════════════════════════════════════════════════════════════

    /**
     * Create a JIS claim with eSIM trust signal boost.
     *
     * @param identity  .aint identity
     * @return JSON JIS claim
     */
    fun createClaim(identity: String): String? {
        val did = jisKeyManager.getOrCreateDID()
        val esimBoost = EsimTrustSignal.getInstance(context).getTrustBoost()
        val baseClearance = 2 // CONFIDENTIAL
        val clearance = if (esimBoost > 0) minOf(baseClearance + 1, 4) else baseClearance

        return TrustKernelBridge.createJisClaim(did.publicKeyHex, identity, clearance)
    }

    // ═══════════════════════════════════════════════════════════════
    // Financial Triage
    // ═══════════════════════════════════════════════════════════════

    /**
     * Evaluate financial triage for a transaction.
     *
     * @param amountEur  Amount in EUR (e.g., 500.0)
     * @param action     Financial action
     * @return TriageResult with level and TIBET token
     */
    fun evaluateFinancial(amountEur: Double, action: String): TriageResult {
        val amountCents = (amountEur * 100).toLong()
        val level = TrustKernelBridge.triageLevel(amountCents, action)
        val token = TrustKernelBridge.mintToken("finance:$action", "device", level)

        return TriageResult(
            level = level,
            levelName = when (level) {
                0 -> "L0 (auto)"
                1 -> "L1 (operator)"
                2 -> "L2 (senior)"
                3 -> "L3 (ceremony)"
                else -> "unknown"
            },
            amountEur = amountEur,
            action = action,
            tibetToken = token,
            requiresHumanApproval = level >= 1
        )
    }

    fun shutdown() {
        TrustKernelBridge.destroyAll()
        Log.i(TAG, "Trust Kernel shut down")
    }

    // ═══════════════════════════════════════════════════════════════
    // Internal
    // ═══════════════════════════════════════════════════════════════

    private fun deriveSessionKey(purpose: String): ByteArray {
        val did = jisKeyManager.getOrCreateDID()
        val hid = jisKeyManager.getOrCreateHID()
        val binding = jisKeyManager.createHIDBinding(did, hid)

        // HMAC-SHA256(binding, purpose) → 32-byte key
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        val secretKey = javax.crypto.spec.SecretKeySpec(binding.toByteArray(), "HmacSHA256")
        mac.init(secretKey)
        return mac.doFinal(purpose.toByteArray())
    }
}

data class TriageResult(
    val level: Int,
    val levelName: String,
    val amountEur: Double,
    val action: String,
    val tibetToken: String?,
    val requiresHumanApproval: Boolean
)
