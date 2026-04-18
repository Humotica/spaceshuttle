package nl.jasper.jtm.trust

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

/**
 * Trust Kernel Demo Screen — Compose UI for hackathon demo.
 *
 * Tests all 5 modules: Bifurcation, MUX routing, JIS claims,
 * TIBET tokens, and financial triage.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrustKernelScreen(
    onNavigateBack: () -> Unit = {}
) {
    val context = LocalContext.current
    var output by remember { mutableStateOf("") }
    var manager by remember { mutableStateOf<TrustKernelManager?>(null) }
    var isInitialized by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    // Initialize on first composition
    LaunchedEffect(Unit) {
        val mgr = TrustKernelManager.getInstance(context)
        isInitialized = mgr.initialize()
        manager = mgr
        output = if (isInitialized) {
            "Trust Kernel initialized: ${TrustKernelBridge.getVersion()}\n"
        } else {
            "Failed to initialize Trust Kernel\n(libtrust_kernel_android.so not found?)\n"
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        // Header
        Text(
            text = "Trust Kernel",
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = if (isInitialized) "AES-256-GCM Bifurcation | TIBET Provenance" else "Library not loaded",
            fontSize = 14.sp,
            color = if (isInitialized) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Buttons
        Button(
            onClick = { output = runAllTests(manager, context) },
            modifier = Modifier.fillMaxWidth(),
            enabled = isInitialized
        ) {
            Text("Run All Tests")
        }

        Spacer(modifier = Modifier.height(8.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { output = testEncryption(manager) },
                modifier = Modifier.weight(1f),
                enabled = isInitialized
            ) { Text("Encrypt", fontSize = 12.sp) }

            Button(
                onClick = { output = testRouting() },
                modifier = Modifier.weight(1f),
                enabled = isInitialized
            ) { Text("Routing", fontSize = 12.sp) }

            Button(
                onClick = { output = testTibet(manager) },
                modifier = Modifier.weight(1f),
                enabled = isInitialized
            ) { Text("TIBET", fontSize = 12.sp) }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { output = testTriage(manager) },
                modifier = Modifier.weight(1f),
                enabled = isInitialized
            ) { Text("Triage", fontSize = 12.sp) }

            Button(
                onClick = { output = testEsim(context) },
                modifier = Modifier.weight(1f)
            ) { Text("eSIM", fontSize = 12.sp) }

            Button(
                onClick = { output = testJis(manager) },
                modifier = Modifier.weight(1f),
                enabled = isInitialized
            ) { Text("JIS", fontSize = 12.sp) }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // iPoll Encrypted Messaging
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = {
                    scope.launch {
                        output = testIPollSend(manager)
                    }
                },
                modifier = Modifier.weight(1f),
                enabled = isInitialized
            ) { Text("iPoll Send", fontSize = 12.sp) }

            Button(
                onClick = {
                    scope.launch {
                        output = testIPollReceive(manager)
                    }
                },
                modifier = Modifier.weight(1f),
                enabled = isInitialized
            ) { Text("iPoll Recv", fontSize = 12.sp) }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Output
        Text(
            text = output,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            lineHeight = 16.sp,
            modifier = Modifier.fillMaxWidth()
        )
    }

    // Cleanup
    DisposableEffect(Unit) {
        onDispose {
            manager?.shutdown()
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Test Functions
// ═══════════════════════════════════════════════════════════════

private fun runAllTests(
    manager: TrustKernelManager?,
    context: android.content.Context
): String {
    val sb = StringBuilder()
    sb.appendLine("=== Trust Kernel — All Tests ===\n")
    sb.appendLine(testEncryption(manager))
    sb.appendLine(testRouting())
    sb.appendLine(testTibet(manager))
    sb.appendLine(testTriage(manager))
    sb.appendLine(testEsim(context))
    sb.appendLine(testJis(manager))
    sb.appendLine("=== Done ===")
    return sb.toString()
}

private fun testEncryption(manager: TrustKernelManager?): String {
    val mgr = manager ?: return "[Encrypt] ERROR: not initialized"
    val sb = StringBuilder("[Encrypt] AES-256-GCM Bifurcation\n")

    val plaintext = "Trust Kernel op Android!"
    val t0 = System.nanoTime()
    val sealed = mgr.encryptMessage(plaintext)
    val sealUs = (System.nanoTime() - t0) / 1000

    if (sealed == null) return sb.append("  FAIL: seal returned null\n").toString()
    sb.appendLine("  Sealed: ${sealed.size} bytes (${sealUs}us)")

    val t1 = System.nanoTime()
    val opened = mgr.decryptMessage(sealed)
    val openUs = (System.nanoTime() - t1) / 1000

    if (opened == plaintext) {
        sb.appendLine("  Opened: \"$opened\" (${openUs}us)")
        sb.appendLine("  PASS: total ${sealUs + openUs}us")
    } else {
        sb.appendLine("  FAIL: mismatch")
    }
    return sb.toString()
}

private fun testRouting(): String {
    val sb = StringBuilder("[Routing] MUX Intent Router\n")
    val intents = listOf(
        "chat:send", "call:voice:start", "call:video:start",
        "finance:transfer", "file:sync", "ai:query"
    )
    for (intent in intents) {
        val result = TrustKernelBridge.routeIntent(intent)
        sb.appendLine("  $intent -> ${result ?: "null"}")
    }
    return sb.toString()
}

private fun testTibet(manager: TrustKernelManager?): String {
    val mgr = manager ?: return "[TIBET] ERROR: not initialized"
    val sb = StringBuilder("[TIBET] Provenance Token\n")
    val token = mgr.mintToken("demo:test")
    sb.appendLine("  ${token ?: "FAIL: null"}")
    return sb.toString()
}

private fun testTriage(manager: TrustKernelManager?): String {
    val mgr = manager ?: return "[Triage] ERROR: not initialized"
    val sb = StringBuilder("[Triage] Financial Levels\n")
    val tests = listOf(
        10.0 to "transfer",
        200.0 to "transfer",
        2000.0 to "transfer",
        10000.0 to "transfer",
        0.0 to "close",
        999999.0 to "check"
    )
    for ((amount, action) in tests) {
        val result = mgr.evaluateFinancial(amount, action)
        sb.appendLine("  ${amount}EUR $action -> ${result.levelName}")
    }
    return sb.toString()
}

private fun testEsim(context: android.content.Context): String {
    val sb = StringBuilder("[eSIM] Trust Signal\n")
    val status = EsimTrustSignal.getInstance(context).getStatus()
    sb.appendLine("  eUICC: ${status.hasEuiccHardware}")
    sb.appendLine("  Profiles: ${status.activeProfileCount}")
    sb.appendLine("  Boost: +${status.trustBoost}")
    return sb.toString()
}

private fun testJis(manager: TrustKernelManager?): String {
    val mgr = manager ?: return "[JIS] ERROR: not initialized"
    val sb = StringBuilder("[JIS] Identity Claim\n")
    val claim = mgr.createClaim("jasper.aint")
    sb.appendLine("  ${claim ?: "FAIL: null"}")
    return sb.toString()
}

private suspend fun testIPollSend(manager: TrustKernelManager?): String {
    val mgr = manager ?: return "[iPoll] ERROR: not initialized"
    val sb = StringBuilder("[iPoll] Encrypted Send\n")

    val testMsg = "Trust Kernel encrypted iPoll test — ${System.currentTimeMillis()}"
    sb.appendLine("  Plaintext: \"$testMsg\"")

    val t0 = System.nanoTime()
    val msgId = mgr.sendEncryptedIPoll(
        toAgent = "root_idd",
        plaintext = testMsg,
        fromAgent = "kit_android"
    )
    val elapsed = (System.nanoTime() - t0) / 1_000_000

    if (msgId != null) {
        sb.appendLine("  Sent: $msgId (${elapsed}ms)")
        sb.appendLine("  PASS: Bifurcation sealed → base64 → iPoll PUSH")
    } else {
        sb.appendLine("  FAIL: send returned null (${elapsed}ms)")
    }
    return sb.toString()
}

private suspend fun testIPollReceive(manager: TrustKernelManager?): String {
    val mgr = manager ?: return "[iPoll] ERROR: not initialized"
    val sb = StringBuilder("[iPoll] Encrypted Receive\n")

    val t0 = System.nanoTime()
    val messages = mgr.receiveEncryptedIPoll("kit_android")
    val elapsed = (System.nanoTime() - t0) / 1_000_000

    sb.appendLine("  Pulled: ${messages.size} messages (${elapsed}ms)")
    for (msg in messages.take(5)) {
        val status = if (msg.decrypted) "DECRYPTED" else "plaintext"
        sb.appendLine("  [${msg.from}] ($status) ${msg.plaintext.take(60)}")
    }
    if (messages.isEmpty()) {
        sb.appendLine("  (no messages in inbox)")
    }
    return sb.toString()
}
