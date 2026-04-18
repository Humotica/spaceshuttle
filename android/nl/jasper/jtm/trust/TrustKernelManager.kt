package nl.jasper.jtm.trust

import android.util.Base64
import android.util.Log
import nl.jasper.jtm.jis.JisKeyManager
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
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
        private const val BRAIN_API_URL = "https://brein.jaspervandemeent.nl"

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

    /**
     * Send an encrypted message via iPoll.
     * Seals plaintext with Bifurcation → base64 → iPoll PUSH.
     *
     * @param toAgent   Recipient .aint agent ID
     * @param plaintext Message text
     * @param fromAgent Sender agent ID (default: device DID fingerprint)
     * @return iPoll message ID on success, null on error
     */
    suspend fun sendEncryptedIPoll(
        toAgent: String,
        plaintext: String,
        fromAgent: String? = null
    ): String? = withContext(Dispatchers.IO) {
        try {
            val sealed = encryptMessage(plaintext) ?: return@withContext null
            val b64Content = Base64.encodeToString(sealed, Base64.NO_WRAP)

            val sender = fromAgent ?: run {
                val did = jisKeyManager.getOrCreateDID()
                did.publicKeyHex.take(16)
            }

            val body = JSONObject().apply {
                put("from_agent", sender)
                put("to_agent", toAgent)
                put("content", b64Content)
                put("poll_type", "PUSH")
                put("encrypted", true)
                put("encryption_method", "bifurcation-aes256gcm")
            }

            val url = URL("$BRAIN_API_URL/api/ipoll/push")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                connectTimeout = 10_000
                readTimeout = 10_000
                doOutput = true
            }
            conn.outputStream.use { it.write(body.toString().toByteArray()) }

            val response = conn.inputStream.bufferedReader().readText()
            conn.disconnect()

            val result = JSONObject(response)
            val msgId = result.optString("id", null)
            Log.i(TAG, "Encrypted iPoll sent to $toAgent: $msgId (${sealed.size} bytes sealed)")

            // Mint TIBET provenance token for the send
            mintToken("ipoll:encrypted_send:$toAgent")

            msgId
        } catch (e: Exception) {
            Log.e(TAG, "Encrypted iPoll send failed", e)
            null
        }
    }

    /**
     * Pull and decrypt encrypted messages from iPoll inbox.
     *
     * @param agentId  Agent ID to pull messages for
     * @return List of decrypted messages, skipping non-encrypted ones
     */
    suspend fun receiveEncryptedIPoll(
        agentId: String
    ): List<DecryptedIPollMessage> = withContext(Dispatchers.IO) {
        try {
            val url = URL("$BRAIN_API_URL/api/ipoll/pull/$agentId?mark_read=true")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 10_000
                readTimeout = 10_000
            }
            val response = conn.inputStream.bufferedReader().readText()
            conn.disconnect()

            val json = JSONObject(response)
            val polls = json.optJSONArray("polls") ?: return@withContext emptyList()

            val messages = mutableListOf<DecryptedIPollMessage>()
            for (i in 0 until polls.length()) {
                val poll = polls.getJSONObject(i)
                val metadata = poll.optJSONObject("metadata")
                val isEncrypted = metadata?.optBoolean("encrypted", false) ?: false

                if (isEncrypted) {
                    val b64Content = poll.getString("content")
                    val sealed = Base64.decode(b64Content, Base64.NO_WRAP)
                    val plaintext = decryptMessage(sealed)

                    messages.add(DecryptedIPollMessage(
                        id = poll.optString("id"),
                        from = poll.optString("from_agent"),
                        plaintext = plaintext ?: "[DECRYPTION FAILED]",
                        decrypted = plaintext != null,
                        timestamp = poll.optString("created_at"),
                        tibetToken = metadata?.optString("tibet_token")
                    ))
                } else {
                    // Non-encrypted message, pass through as-is
                    messages.add(DecryptedIPollMessage(
                        id = poll.optString("id"),
                        from = poll.optString("from_agent"),
                        plaintext = poll.optString("content"),
                        decrypted = false,
                        timestamp = poll.optString("created_at"),
                        tibetToken = null
                    ))
                }
            }

            Log.i(TAG, "iPoll pull: ${messages.size} messages (${messages.count { it.decrypted }} encrypted)")
            messages
        } catch (e: Exception) {
            Log.e(TAG, "Encrypted iPoll receive failed", e)
            emptyList()
        }
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

data class DecryptedIPollMessage(
    val id: String,
    val from: String,
    val plaintext: String,
    val decrypted: Boolean,
    val timestamp: String,
    val tibetToken: String?
)
