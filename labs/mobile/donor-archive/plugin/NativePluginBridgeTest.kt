package com.luminet.android.plugin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class NativePluginBridgeTest {

    @Test
    fun testPluginConstantsAndDescriptor() {
        assertEquals("io.nekohasekai.sagernet.plugin.ACTION_NATIVE_PLUGIN", NativePluginBridge.ACTION_NATIVE_PLUGIN)
        assertEquals("sagernet:getExecutable", NativePluginBridge.METHOD_GET_EXECUTABLE)

        val desc = NativePluginBridge.NativePluginDescriptor(
            id = "moe.matsuri.plugin.proxy",
            name = "LumiNet Matsuri Bridge",
            executablePath = "/data/app/lib/arm64/libproxy.so"
        )
        assertEquals("moe.matsuri.plugin.proxy", desc.id)
        assertEquals(0b111101101, desc.fileMode)
    }

    @Test
    fun testPluginConfigBuilder() {
        val builder = NativePluginBridge.PluginConfigBuilder(
            bindAddress = "127.0.0.1",
            bindPort = 2080,
            remoteDns = "8.8.4.4",
            sni = "cdn.example.com",
            dohUrl = "https://1.1.1.1/dns-query",
            splitSni = true,
            udpMode = true
        )

        val args = builder.buildArgs()
        assertTrue(args.contains("-l"))
        assertTrue(args.contains("127.0.0.1:2080"))
        assertTrue(args.contains("-d"))
        assertTrue(args.contains("8.8.4.4"))
        assertTrue(args.contains("-s"))
        assertTrue(args.contains("cdn.example.com"))
        assertTrue(args.contains("--doh"))
        assertTrue(args.contains("https://1.1.1.1/dns-query"))
        assertTrue(args.contains("--split-sni"))
        assertTrue(args.contains("-u"))
    }

    @Test
    fun testPluginFileManagerPathResolution() {
        val dir = "/data/app/~~xyz==/lib/arm64"
        val path1 = NativePluginBridge.PluginFileManager.getNativeLibraryPath(dir, "epass")
        assertEquals(File(dir, "libepass.so").absolutePath, path1)

        val path2 = NativePluginBridge.PluginFileManager.getNativeLibraryPath(dir, "libcustom.so")
        assertEquals(File(dir, "libcustom.so").absolutePath, path2)
    }
}
