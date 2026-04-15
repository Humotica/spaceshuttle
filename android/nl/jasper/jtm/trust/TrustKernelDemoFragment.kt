package nl.jasper.jtm.trust

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.Fragment

/**
 * Trust Kernel Demo Fragment — Hackathon showcase UI.
 *
 * Demonstrates:
 * 1. AES-256-GCM Bifurcation seal/open round-trip
 * 2. MUX intent routing
 * 3. TIBET provenance token minting
 * 4. Financial triage levels
 * 5. eSIM trust signal
 */
class TrustKernelDemoFragment : Fragment() {

    private lateinit var outputText: TextView
    private var manager: TrustKernelManager? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val context = requireContext()
        val sb = StringBuilder()

        val scroll = ScrollView(context).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }

        // Title
        layout.addView(TextView(context).apply {
            text = "Trust Kernel Demo"
            textSize = 24f
            setPadding(0, 0, 0, 16)
        })

        // Status
        layout.addView(TextView(context).apply {
            text = "Library: ${if (TrustKernelBridge.isAvailable()) TrustKernelBridge.getVersion() else "NOT LOADED"}"
            textSize = 14f
            setPadding(0, 0, 0, 16)
        })

        // Buttons
        fun addButton(label: String, action: () -> Unit) {
            layout.addView(Button(context).apply {
                text = label
                setOnClickListener { action() }
            })
        }

        addButton("Run All Tests") { runAllTests() }
        addButton("Encryption Round-Trip") { testEncryption() }
        addButton("Intent Routing") { testRouting() }
        addButton("TIBET Token") { testTibetMint() }
        addButton("Financial Triage") { testTriage() }
        addButton("eSIM Trust Signal") { testEsim() }

        // Output area
        outputText = TextView(context).apply {
            textSize = 12f
            setTextIsSelectable(true)
            setPadding(0, 16, 0, 0)
            typeface = android.graphics.Typeface.MONOSPACE
        }
        layout.addView(outputText)

        scroll.addView(layout)
        return scroll
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        manager = TrustKernelManager.getInstance(requireContext())
        manager?.initialize()
    }

    private fun log(msg: String) {
        outputText.append("$msg\n")
    }

    private fun clearLog() {
        outputText.text = ""
    }

    private fun runAllTests() {
        clearLog()
        log("=== Trust Kernel Demo ===\n")
        testEncryption()
        log("")
        testRouting()
        log("")
        testTibetMint()
        log("")
        testTriage()
        log("")
        testEsim()
        log("\n=== Done ===")
    }

    private fun testEncryption() {
        log("[Encryption] AES-256-GCM Bifurcation")
        val mgr = manager ?: run { log("  ERROR: not initialized"); return }

        val plaintext = "Hello from Trust Kernel on Android!"
        val t0 = System.nanoTime()
        val sealed = mgr.encryptMessage(plaintext)
        val sealTime = (System.nanoTime() - t0) / 1000

        if (sealed == null) {
            log("  FAIL: seal returned null")
            return
        }
        log("  Sealed: ${sealed.size} bytes (${sealTime}us)")

        val t1 = System.nanoTime()
        val opened = mgr.decryptMessage(sealed)
        val openTime = (System.nanoTime() - t1) / 1000

        if (opened == plaintext) {
            log("  Opened: \"$opened\" (${openTime}us)")
            log("  PASS: round-trip OK, total ${sealTime + openTime}us")
        } else {
            log("  FAIL: decrypted text does not match")
        }
    }

    private fun testRouting() {
        log("[Routing] MUX Intent Router")
        val intents = listOf(
            "chat:send", "call:voice:start", "call:video:start",
            "finance:transfer", "file:sync", "ai:query"
        )
        for (intent in intents) {
            val result = TrustKernelBridge.routeIntent(intent)
            log("  $intent -> $result")
        }
    }

    private fun testTibetMint() {
        log("[TIBET] Provenance Token")
        val token = manager?.mintToken("demo:test")
        if (token != null) {
            log("  $token")
        } else {
            log("  FAIL: mintToken returned null")
        }
    }

    private fun testTriage() {
        log("[Triage] Financial Levels")
        val tests = listOf(
            10.0 to "transfer",
            200.0 to "transfer",
            2000.0 to "transfer",
            10000.0 to "transfer",
            0.0 to "close",
            999999.0 to "check"
        )
        for ((amount, action) in tests) {
            val result = manager?.evaluateFinancial(amount, action)
            log("  ${amount}EUR $action -> ${result?.levelName} (approval=${result?.requiresHumanApproval})")
        }
    }

    private fun testEsim() {
        log("[eSIM] Trust Signal")
        val status = EsimTrustSignal.getInstance(requireContext()).getStatus()
        log("  eUICC hardware: ${status.hasEuiccHardware}")
        log("  Active profiles: ${status.activeProfileCount}")
        log("  Trust boost: +${status.trustBoost}")
        log("  Phase: ${status.phase}")
    }

    override fun onDestroyView() {
        super.onDestroyView()
        manager?.shutdown()
    }
}
