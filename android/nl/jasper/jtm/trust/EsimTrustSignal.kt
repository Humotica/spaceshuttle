package nl.jasper.jtm.trust

import android.content.Context
import android.os.Build
import android.telephony.SubscriptionManager
import android.telephony.euicc.EuiccManager
import android.util.Log

/**
 * eSIM Trust Signal — Read-only eSIM status for JIS clearance boost.
 *
 * Phase 1: eSIM presence + active profile = trust boost (no carrier ARF needed)
 * Phase 2: Full sovereign carrier via osmo-smdpp SM-DP+ integration
 *
 * Trust boost logic:
 *   - No eSIM hardware:     +0  (no boost)
 *   - eSIM present, no SIM: +10 (hardware capable)
 *   - eSIM + active profile: +30 (identity-bound device)
 *
 * This maps to JIS clearance: base 50 + boost → used in Bifurcation access control.
 */
class EsimTrustSignal private constructor(
    private val context: Context
) {
    companion object {
        private const val TAG = "EsimTrust"

        @Volatile
        private var instance: EsimTrustSignal? = null

        fun getInstance(context: Context): EsimTrustSignal {
            return instance ?: synchronized(this) {
                instance ?: EsimTrustSignal(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }

    /** Cached trust boost value (recalculated on demand) */
    private var cachedBoost: Int? = null

    /**
     * Get the eSIM trust boost value.
     *
     * @return Trust boost: 0, 10, or 30
     */
    fun getTrustBoost(): Int {
        cachedBoost?.let { return it }

        val boost = calculateBoost()
        cachedBoost = boost
        return boost
    }

    /**
     * Get detailed eSIM status for display.
     */
    fun getStatus(): EsimStatus {
        val hasEuicc = isEuiccAvailable()
        val activeProfiles = getActiveProfileCount()
        val boost = getTrustBoost()

        return EsimStatus(
            hasEuiccHardware = hasEuicc,
            activeProfileCount = activeProfiles,
            trustBoost = boost,
            phase = "phase1-readonly"
        )
    }

    /** Invalidate cached boost (call after SIM state changes) */
    fun invalidateCache() {
        cachedBoost = null
    }

    // ═══════════════════════════════════════════════════════════════
    // Internal
    // ═══════════════════════════════════════════════════════════════

    private fun calculateBoost(): Int {
        if (!isEuiccAvailable()) {
            Log.d(TAG, "No eUICC hardware detected")
            return 0
        }

        val activeProfiles = getActiveProfileCount()

        return when {
            activeProfiles > 0 -> {
                Log.i(TAG, "eSIM active: $activeProfiles profiles → +30 trust boost")
                30
            }
            else -> {
                Log.i(TAG, "eUICC hardware present, no active profile → +10 trust boost")
                10
            }
        }
    }

    private fun isEuiccAvailable(): Boolean {
        return try {
            val euiccManager = context.getSystemService(Context.EUICC_SERVICE) as? EuiccManager
            euiccManager?.isEnabled == true
        } catch (e: Exception) {
            Log.w(TAG, "EuiccManager not available: ${e.message}")
            false
        }
    }

    private fun getActiveProfileCount(): Int {
        return try {
            val subManager = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as? SubscriptionManager
            val subscriptions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                subManager?.activeSubscriptionInfoList
            } else {
                @Suppress("DEPRECATION")
                subManager?.activeSubscriptionInfoList
            }

            val esimSubs = subscriptions?.filter { sub ->
                sub.isEmbedded
            }

            esimSubs?.size ?: 0
        } catch (e: SecurityException) {
            Log.w(TAG, "No permission to read subscription info: ${e.message}")
            0
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read subscriptions: ${e.message}")
            0
        }
    }
}

data class EsimStatus(
    val hasEuiccHardware: Boolean,
    val activeProfileCount: Int,
    val trustBoost: Int,
    val phase: String
)
