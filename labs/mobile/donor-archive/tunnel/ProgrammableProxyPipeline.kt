package com.luminet.android.tunnel

sealed class AndroidPipelineVerdict {
    object PassThrough : AndroidPipelineVerdict()
    data class ShortCircuit(val statusCode: Int, val body: ByteArray) : AndroidPipelineVerdict()
    data class ModifyHeaders(val headers: List<Pair<String, String>>) : AndroidPipelineVerdict()
}

interface AndroidProxyFilterHook {
    fun onRequest(method: String, path: String, headers: List<Pair<String, String>>): AndroidPipelineVerdict
}

class AndroidHeaderInjectorHook(
    private val name: String,
    private val value: String
) : AndroidProxyFilterHook {
    override fun onRequest(
        method: String,
        path: String,
        headers: List<Pair<String, String>>
    ): AndroidPipelineVerdict {
        return AndroidPipelineVerdict.ModifyHeaders(listOf(name to value))
    }
}

class AndroidBlockPathHook(private val blockedPrefix: String) : AndroidProxyFilterHook {
    override fun onRequest(
        method: String,
        path: String,
        headers: List<Pair<String, String>>
    ): AndroidPipelineVerdict {
        return if (path.startsWith(blockedPrefix)) {
            AndroidPipelineVerdict.ShortCircuit(403, "Forbidden by LumiProxy Pipeline".toByteArray())
        } else {
            AndroidPipelineVerdict.PassThrough
        }
    }
}

class ProgrammableProxyPipeline {
    private val hooks = mutableListOf<AndroidProxyFilterHook>()

    fun addHook(hook: AndroidProxyFilterHook) {
        hooks.add(hook)
    }

    fun processRequest(
        method: String,
        path: String,
        headers: MutableList<Pair<String, String>>
    ): Pair<Int, ByteArray?> {
        for (hook in hooks) {
            when (val verdict = hook.onRequest(method, path, headers)) {
                is AndroidPipelineVerdict.PassThrough -> {}
                is AndroidPipelineVerdict.ShortCircuit -> {
                    return verdict.statusCode to verdict.body
                }
                is AndroidPipelineVerdict.ModifyHeaders -> {
                    headers.addAll(verdict.headers)
                }
            }
        }
        return 200 to null
    }
}
