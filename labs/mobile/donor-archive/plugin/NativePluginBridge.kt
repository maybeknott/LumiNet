package com.luminet.android.plugin

import java.io.File

/**
 * Android SagerNet / NekoBox / Matsuri Native Plugin Bridge.
 * Ported and unified from `nekobepass-main`.
 */
object NativePluginBridge {

    const val ACTION_NATIVE_PLUGIN = "io.nekohasekai.sagernet.plugin.ACTION_NATIVE_PLUGIN"
    const val EXTRA_ENTRY = "io.nekohasekai.sagernet.plugin.EXTRA_ENTRY"
    const val METADATA_KEY_ID = "io.nekohasekai.sagernet.plugin.id"
    const val METADATA_KEY_EXECUTABLE_PATH = "io.nekohasekai.sagernet.plguin.executable_path"
    const val METHOD_GET_EXECUTABLE = "sagernet:getExecutable"
    const val DEFAULT_FILE_MODE = 0b111101101 // 0755 (rwxr-xr-x)

    data class NativePluginDescriptor(
        val id: String,
        val name: String,
        val executablePath: String,
        val fileMode: Int = DEFAULT_FILE_MODE,
        val environmentArgs: List<String> = emptyList()
    )

    data class PluginConfigBuilder(
        var bindAddress: String = "127.0.0.1",
        var bindPort: Int = 10808,
        var remoteDns: String = "1.1.1.1",
        var sni: String? = null,
        var dohUrl: String? = null,
        var splitSni: Boolean = false,
        var udpMode: Boolean = true
    ) {
        fun buildArgs(): List<String> {
            val args = mutableListOf<String>()
            args.add("-l")
            args.add("$bindAddress:$bindPort")

            args.add("-d")
            args.add(remoteDns)

            sni?.let {
                if (it.isNotBlank()) {
                    args.add("-s")
                    args.add(it)
                }
            }

            dohUrl?.let {
                if (it.isNotBlank()) {
                    args.add("--doh")
                    args.add(it)
                }
            }

            if (splitSni) {
                args.add("--split-sni")
            }

            if (udpMode) {
                args.add("-u")
            }

            return args
        }
    }

    object PluginFileManager {
        fun getNativeLibraryPath(nativeLibDir: String, libName: String): String {
            val actualName = if (libName.startsWith("lib") && libName.endsWith(".so")) {
                libName
            } else {
                "lib$libName.so"
            }
            return File(nativeLibDir, actualName).absolutePath
        }

        fun validateBinary(path: String): Boolean {
            val file = File(path)
            return file.exists() && file.isFile && file.canRead()
        }
    }
}
