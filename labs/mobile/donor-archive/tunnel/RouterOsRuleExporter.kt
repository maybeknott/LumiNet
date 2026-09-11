package com.luminet.android.tunnel

class RouterOsRuleExporter {
    val entries = mutableListOf<String>()

    fun addEntry(entry: String) {
        val clean = entry.trim()
        if (clean.isNotEmpty()) entries.add(clean)
    }

    fun exportAddressList(listName: String): String {
        val sb = StringBuilder()
        sb.append("/ip firewall address-list\n")
        for (e in entries) {
            sb.append("add list=").append(listName).append(" address=").append(e).append(" comment=\"LumiNet auto\"\n")
        }
        return sb.toString()
    }
}
