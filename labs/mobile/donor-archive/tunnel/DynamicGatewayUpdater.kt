package com.luminet.android.tunnel

data class AndroidGatewayRoute(
    val destinationCidr: String,
    val gatewayIp: String,
    val interfaceName: String,
    val metric: Int
)

class DynamicGatewayUpdater {
    val routes = mutableMapOf<String, AndroidGatewayRoute>()

    fun addRoute(route: AndroidGatewayRoute) {
        routes[route.destinationCidr] = route
    }

    fun removeRoute(cidr: String) {
        routes.remove(cidr)
    }

    fun compileCommands(): List<String> {
        return routes.values.map {
            "ip route add ${it.destinationCidr} via ${it.gatewayIp} dev ${it.interfaceName} metric ${it.metric}"
        }
    }
}
