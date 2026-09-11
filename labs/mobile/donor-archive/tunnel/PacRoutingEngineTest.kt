// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.luminet.android.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PacRoutingEngineTest {

    @Test
    fun testParseRules() {
        val raw = "domain:cloudflare.com,!domain:blocked.ir,*domain:*.cdn.com,ip:192.168.1.5,range:10.0.*,app:ignore"
        val rules = PacRoutingEngine.parseRules(raw)

        assertEquals(5, rules.size)

        assertEquals(PacRuleType.DOMAIN, rules[0].ruleType)
        assertEquals("cloudflare.com", rules[0].value)
        assertFalse(rules[0].forceProxy)

        assertEquals(PacRuleType.DOMAIN, rules[1].ruleType)
        assertEquals("blocked.ir", rules[1].value)
        assertTrue(rules[1].forceProxy)

        assertEquals(PacRuleType.DOMAIN, rules[2].ruleType)
        assertTrue(rules[2].isWildcard)

        assertEquals(PacRuleType.IP, rules[3].ruleType)
        assertEquals("192.168.1.5", rules[3].value)

        assertEquals(PacRuleType.RANGE, rules[4].ruleType)
        assertTrue(rules[4].isWildcard)
    }

    @Test
    fun testEvaluateHost() {
        val rules = listOf(
            PacRule(PacRuleType.DOMAIN, "bypass.com", false, false),
            PacRule(PacRuleType.DOMAIN, "force.com", false, true)
        )

        assertEquals(PacDecision.DIRECT, PacRoutingEngine.evaluateHost("localhost", rules))
        assertEquals(PacDecision.DIRECT, PacRoutingEngine.evaluateHost("127.0.0.1", rules))
        assertEquals(PacDecision.DIRECT, PacRoutingEngine.evaluateHost("bypass.com", rules))
        assertEquals(PacDecision.PROXY, PacRoutingEngine.evaluateHost("force.com", rules))
        assertEquals(PacDecision.DEFAULT_PROXY, PacRoutingEngine.evaluateHost("other.org", rules))
    }

    @Test
    fun testCompilePacScript() {
        val rules = listOf(
            PacRule(PacRuleType.DOMAIN, "direct.net", false, false)
        )

        val script = PacRoutingEngine.compilePacScript("127.0.0.1", 8080, false, rules)
        assertTrue(script.contains("function FindProxyForURL(url, host)"))
        assertTrue(script.contains("PROXY 127.0.0.1:8080; DIRECT"))
        assertTrue(script.contains("host === \"direct.net\""))
    }

    @Test
    fun testColoLocationResolver() {
        val fra = ColoLocationResolver.resolve("FRA")
        assertEquals("DE", fra.countryCode)
        assertEquals("🇩🇪", fra.flagEmoji)

        val unknown = ColoLocationResolver.resolve("XXX")
        assertEquals("XX", unknown.countryCode)
        assertEquals("🌐", unknown.flagEmoji)
    }
}
