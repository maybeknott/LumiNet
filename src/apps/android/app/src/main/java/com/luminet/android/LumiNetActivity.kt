package com.luminet.android

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat

class LumiNetActivity : ComponentActivity() {
    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                startVpnService()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SovereignGlassTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xFF0A0E1A),
                ) {
                    val runtimeState by VpnEngineService.runtimeState.collectAsStateWithLifecycle()
                    var perAppPolicy by remember { mutableStateOf(PerAppVpnPolicyStore.load(this@LumiNetActivity)) }
                    DashboardScreen(
                        runtimeState = runtimeState,
                        perAppPolicy = perAppPolicy,
                        onSavePerAppPolicy = { candidate ->
                            try {
                                perAppPolicy = PerAppVpnPolicyStore.save(this@LumiNetActivity, candidate)
                                null
                            } catch (ex: IllegalArgumentException) {
                                ex.message ?: "Invalid per-app policy"
                            } catch (ex: IllegalStateException) {
                                ex.message ?: "Unable to save per-app policy"
                            }
                        },
                        onToggleConnection = {
                            if (runtimeState.stage == VpnRuntimeStage.CONNECTED || runtimeState.stage == VpnRuntimeStage.STARTING) {
                                stopVpnService()
                            } else {
                                requestVpnStart()
                            }
                        },
                    )
                }
            }
        }
        if (intent?.getBooleanExtra(EXTRA_REQUEST_VPN, false) == true) {
            intent?.removeExtra(EXTRA_REQUEST_VPN)
            requestVpnStart()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(EXTRA_REQUEST_VPN, false)) {
            intent.removeExtra(EXTRA_REQUEST_VPN)
            requestVpnStart()
        }
    }

    private fun requestVpnStart() {
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            vpnPermissionLauncher.launch(permissionIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, VpnEngineService::class.java),
        )
    }

    private fun stopVpnService() {
        startService(
            Intent(this, VpnEngineService::class.java)
                .setAction(VpnEngineService.ACTION_STOP),
        )
    }

    companion object {
        const val EXTRA_REQUEST_VPN = "com.luminet.android.REQUEST_VPN"
    }
}

@Composable
private fun SovereignGlassTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Color(0xFF00F0FF),
            background = Color(0xFF0A0E1A),
            surface = Color(0xFF121829),
        ),
        content = content,
    )
}

@Composable
private fun DashboardScreen(
    runtimeState: VpnRuntimeState,
    perAppPolicy: PerAppVpnPolicy,
    onSavePerAppPolicy: (PerAppVpnPolicy) -> String?,
    onToggleConnection: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isConnected = runtimeState.stage == VpnRuntimeStage.CONNECTED
    val tunnelBusy = runtimeState.stage == VpnRuntimeStage.STARTING || runtimeState.stage == VpnRuntimeStage.STOPPING
    val actionLabel = if (isConnected) "Disconnect" else "Connect"
    val statusLabel = when (runtimeState.stage) {
        VpnRuntimeStage.IDLE -> stringResource(R.string.vpn_status_idle)
        VpnRuntimeStage.STARTING -> stringResource(R.string.vpn_status_starting)
        VpnRuntimeStage.CONNECTED -> stringResource(R.string.vpn_status_connected)
        VpnRuntimeStage.STOPPING -> stringResource(R.string.vpn_status_stopping)
        VpnRuntimeStage.ERROR -> stringResource(R.string.vpn_status_error)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(28.dp),
    ) {
        Text(
            text = "LumiNet Sovereign Mobile",
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            color = Color(0xFF00F0FF),
        )

        Text(
            text = if (runtimeState.stage == VpnRuntimeStage.ERROR && runtimeState.failureCode != null) {
                stringResource(R.string.vpn_status_error_detail, runtimeState.failureCode)
            } else {
                "Status: $statusLabel"
            },
            color = MaterialTheme.colorScheme.onBackground,
        )

        Button(
            onClick = onToggleConnection,
            enabled = !tunnelBusy,
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isConnected) Color(0xFF00FF66) else Color(0xFFFF0055),
            ),
            modifier = Modifier.size(160.dp),
        ) {
            Text(
                text = actionLabel.uppercase(),
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = Color.Black,
            )
        }

        PerAppPolicyEditor(
            policy = perAppPolicy,
            isConnected = isConnected,
            onSave = onSavePerAppPolicy,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun PerAppPolicyEditor(
    policy: PerAppVpnPolicy,
    isConnected: Boolean,
    onSave: (PerAppVpnPolicy) -> String?,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val launchableApps = remember(context) { loadLaunchableApps(context) }
    var mode by remember(policy) { mutableStateOf(policy.mode) }
    var selectedPackages by remember(policy) { mutableStateOf(policy.packages.toSet()) }
    var search by remember { mutableStateOf("") }
    var status by remember(policy) { mutableStateOf<String?>(null) }
    val visibleApps = remember(launchableApps, search) {
        val needle = search.trim().lowercase()
        launchableApps
            .asSequence()
            .filter { needle.isEmpty() || it.label.lowercase().contains(needle) || it.packageName.lowercase().contains(needle) }
            .take(50)
            .toList()
    }
    val launchablePackages = remember(launchableApps) { launchableApps.mapTo(mutableSetOf()) { it.packageName } }
    val hiddenConfiguredPackages = remember(selectedPackages, launchablePackages) { selectedPackages.filterNot(launchablePackages::contains) }

    Card(modifier = modifier) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Per-app VPN", fontWeight = FontWeight.SemiBold)
            Text(
                "Choose launchable Android apps by name. LumiNet stores package identifiers internally and Android enforces the selected policy before the tunnel is established.",
                style = MaterialTheme.typography.bodySmall,
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                PerAppVpnMode.entries.forEach { candidate ->
                    FilterChip(
                        selected = mode == candidate,
                        onClick = { mode = candidate; status = null },
                        label = {
                            Text(
                                when (candidate) {
                                    PerAppVpnMode.ALL -> "All"
                                    PerAppVpnMode.INCLUDE -> "Only selected"
                                    PerAppVpnMode.EXCLUDE -> "All except"
                                },
                            )
                        },
                    )
                }
            }

            if (mode != PerAppVpnMode.ALL) {
                OutlinedTextField(
                    value = search,
                    onValueChange = { search = it; status = null },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Search installed apps") },
                    supportingText = {
                        Text("Shows launchable apps visible through Android's package-visibility contract; max ${PerAppVpnPolicy.MAX_PACKAGES} selections.")
                    },
                )

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 320.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    visibleApps.forEach { app ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Checkbox(
                                checked = app.packageName in selectedPackages,
                                onCheckedChange = { checked ->
                                    selectedPackages = if (checked) selectedPackages + app.packageName else selectedPackages - app.packageName
                                    status = null
                                },
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(app.label, style = MaterialTheme.typography.bodyMedium)
                                Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                    if (visibleApps.isEmpty()) {
                        Text("No launchable apps match this search.", style = MaterialTheme.typography.bodySmall)
                    }
                }

                if (hiddenConfiguredPackages.isNotEmpty()) {
                    Text(
                        "${hiddenConfiguredPackages.size} previously configured package(s) are not launcher-visible on this device and will be preserved unless the policy is reset.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary,
                    )
                }
                Text(
                    "Selected: ${selectedPackages.size}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            if (isConnected) {
                Text(
                    "Policy changes take effect on the next VPN connection.",
                    color = MaterialTheme.colorScheme.tertiary,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                status?.let {
                    Text(
                        it,
                        color = if (it == "Saved") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1f),
                    )
                } ?: Spacer(Modifier.weight(1f))
                Button(onClick = {
                    val candidate = PerAppVpnPolicy(mode = mode, packages = selectedPackages.toList()).normalized()
                    status = onSave(candidate) ?: "Saved"
                }) {
                    Text("Save policy")
                }
            }
        }
    }
}


private data class LaunchableAppOption(
    val label: String,
    val packageName: String,
)

@Suppress("DEPRECATION")
private fun loadLaunchableApps(context: Context): List<LaunchableAppOption> {
    val packageManager = context.packageManager
    val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    return packageManager.queryIntentActivities(launcherIntent, 0)
        .asSequence()
        .mapNotNull { info ->
            val packageName = info.activityInfo?.packageName?.trim().orEmpty()
            if (packageName.isEmpty() || packageName == context.packageName) return@mapNotNull null
            val label = runCatching { info.loadLabel(packageManager).toString().trim() }
                .getOrDefault(packageName)
                .ifEmpty { packageName }
            LaunchableAppOption(label = label, packageName = packageName)
        }
        .distinctBy { it.packageName }
        .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label }.thenBy { it.packageName })
        .toList()
}
