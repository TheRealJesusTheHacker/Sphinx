package com.sentinelsafeguard.sphinx.core

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The canonical tunnel corpus — docs/tunnel-corpus.json, read
 * from the repo, every case: TUNNEL-SPEC's "one file, every
 * edition's suite reads it". An edition that disagrees with
 * the corpus is wrong.
 *
 * Path resolution: Gradle's unit-test working directory has
 * varied across versions, so the corpus is located by walking
 * up from this test class's own code-source location (the
 * build tree sits inside the repo checkout) and then by the
 * candidate relative paths BundledListTest uses. Whichever
 * route finds the file, the file read is the committed one.
 */
class TunnelCorpusTest {

    // --- Minimal JSON reader (the corpus's shape only needs
    // objects, arrays, strings, numbers, booleans, null). The
    // unit-test classpath has no JSON library, and adding one
    // for tests alone is not worth a dependency. ---
    private class JsonParser(private val text: String) {
        private var pos = 0

        fun parse(): Any? {
            val value = readValue()
            skipWs()
            if (pos != text.length) failHere("trailing content")
            return value
        }

        private fun failHere(why: String): Nothing =
            throw IllegalArgumentException("JSON parse error at $pos: $why")

        private fun skipWs() {
            while (pos < text.length && text[pos].isWhitespace()) pos++
        }

        private fun readValue(): Any? {
            skipWs()
            if (pos >= text.length) failHere("unexpected end")
            return when (text[pos]) {
                '{' -> readObject()
                '[' -> readArray()
                '"' -> readString()
                't' -> readLiteral("true", true)
                'f' -> readLiteral("false", false)
                'n' -> readLiteral("null", null)
                else -> readNumber()
            }
        }

        private fun readLiteral(word: String, value: Any?): Any? {
            if (!text.startsWith(word, pos)) failHere("bad literal")
            pos += word.length
            return value
        }

        private fun readNumber(): Double {
            val start = pos
            while (pos < text.length && text[pos] in "-+0123456789.eE") pos++
            return text.substring(start, pos).toDouble()
        }

        private fun readString(): String {
            pos++ // opening quote
            val out = StringBuilder()
            while (pos < text.length) {
                val c = text[pos++]
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> {
                        if (pos >= text.length) failHere("bad escape")
                        when (val e = text[pos++]) {
                            'n' -> out.append('\n')
                            't' -> out.append('\t')
                            'r' -> out.append('\r')
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            '/' -> out.append('/')
                            '\\' -> out.append('\\')
                            '"' -> out.append('"')
                            'u' -> {
                                out.append(text.substring(pos, pos + 4).toInt(16).toChar())
                                pos += 4
                            }
                            else -> failHere("unknown escape $e")
                        }
                    }
                    else -> out.append(c)
                }
            }
            failHere("unterminated string")
        }

        private fun readObject(): Map<String, Any?> {
            pos++ // {
            val out = LinkedHashMap<String, Any?>()
            skipWs()
            if (pos < text.length && text[pos] == '}') {
                pos++
                return out
            }
            while (true) {
                skipWs()
                val key = readString()
                skipWs()
                if (pos >= text.length || text[pos] != ':') failHere("expected :")
                pos++
                out[key] = readValue()
                skipWs()
                if (pos >= text.length) failHere("unterminated object")
                when (text[pos]) {
                    ',' -> pos++
                    '}' -> {
                        pos++
                        return out
                    }
                    else -> failHere("expected , or }")
                }
            }
        }

        private fun readArray(): List<Any?> {
            pos++ // [
            val out = ArrayList<Any?>()
            skipWs()
            if (pos < text.length && text[pos] == ']') {
                pos++
                return out
            }
            while (true) {
                out.add(readValue())
                skipWs()
                if (pos >= text.length) failHere("unterminated array")
                when (text[pos]) {
                    ',' -> pos++
                    ']' -> {
                        pos++
                        return out
                    }
                    else -> failHere("expected , or ]")
                }
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun corpusFile(): File {
        // Walk up from the test class's code source: the build
        // tree lives under the repo, so docs/ is an ancestor's
        // child at some level.
        try {
            var dir: File? = File(
                TunnelCorpusTest::class.java.protectionDomain
                    .codeSource.location.toURI()
            )
            var hops = 0
            while (dir != null && hops < 12) {
                val candidate = File(dir, "docs/tunnel-corpus.json")
                if (candidate.isFile) return candidate
                dir = dir.parentFile
                hops++
            }
        } catch (e: Exception) {
            // Fall through to the relative candidates.
        }
        val candidates = listOf(
            File("docs/tunnel-corpus.json"),
            File("../docs/tunnel-corpus.json"),
            File("../../docs/tunnel-corpus.json"),
            File("../../../docs/tunnel-corpus.json"),
        )
        return candidates.firstOrNull { it.isFile } ?: candidates[0]
    }

    @Suppress("UNCHECKED_CAST")
    private fun loadCases(): List<Map<String, Any?>> {
        val file = corpusFile()
        assumeTrue("tunnel corpus not present at ${file.path}", file.isFile)
        val root = JsonParser(file.readText()) .parse() as Map<String, Any?>
        assertEquals(1.0, root["version"] as Double, 0.0)
        return root["cases"] as List<Map<String, Any?>>
    }

    private fun strings(list: Any?): List<String> =
        (list as? List<*>)?.map { it as String } ?: emptyList()

    @Test
    fun everyCorpusCasePasses() {
        val cases = loadCases()
        assertTrue("corpus should carry its cases", cases.size >= 12)
        for (case in cases) {
            val id = case["id"] as String
            val input = case["input_text"] as String
            val expect = case["expect"] as Map<String, Any?>
            val valid = expect["valid"] as Boolean
            when (val result = TunnelProfileParser.parse(input)) {
                is TunnelParseResult.Refused -> {
                    assertTrue("$id: expected valid, got refusal ${result.reason}", valid)
                    assertEquals("$id refusal", expect["refusal"], result.reason)
                    assertNull("$id export", expect["export_text"])
                }
                is TunnelParseResult.Valid -> {
                    assertTrue(
                        "$id: expected refusal ${expect["refusal"]}, got a profile",
                        valid,
                    )
                    val profile = result.profile
                    val facts = expect["profile"] as Map<String, Any?>
                    assertEquals("$id protocol", facts["protocol"], profile.protocol)
                    assertEquals("$id name", facts["name"], profile.name)
                    assertEquals("$id endpoint", facts["endpoint"], profile.endpoint)
                    if (profile is WgProfile) {
                        assertEquals(
                            "$id server key",
                            facts["server_public_key"],
                            profile.serverPublicKey,
                        )
                        assertEquals(
                            "$id addresses",
                            strings(facts["client_addresses"]),
                            profile.clientAddresses,
                        )
                        assertEquals(
                            "$id allowed",
                            strings(facts["allowed_ips"]),
                            profile.allowedIps,
                        )
                        assertEquals("$id dns", strings(facts["dns"]), profile.dnsServers)
                        val scope = expect["scope"] as String?
                        if (scope != null) assertEquals("$id scope", scope, profile.scope)
                        val extras = facts["extras"] as? Map<String, Any?>
                        if (extras != null) {
                            assertEquals(
                                "$id mtu",
                                (extras["mtu"] as Double).toInt(),
                                profile.mtu,
                            )
                            assertEquals(
                                "$id psk",
                                extras["preshared_key"],
                                profile.presharedKey,
                            )
                            assertEquals(
                                "$id keepalive",
                                (extras["persistent_keepalive"] as Double).toInt(),
                                profile.persistentKeepalive,
                            )
                        }
                        val peers = facts["peers"] as? List<Map<String, Any?>>
                        if (peers != null) {
                            assertEquals("$id peer count", peers.size, profile.peers.size)
                            peers.forEachIndexed { index, peerFacts ->
                                val peer = profile.peers[index]
                                assertEquals(
                                    "$id peer $index key",
                                    peerFacts["server_public_key"],
                                    peer.publicKey,
                                )
                                assertEquals(
                                    "$id peer $index endpoint",
                                    peerFacts["endpoint"],
                                    peer.endpoint,
                                )
                                assertEquals(
                                    "$id peer $index allowed",
                                    strings(peerFacts["allowed_ips"]),
                                    peer.allowedIps,
                                )
                            }
                        }
                    }
                    val export = expect["export_text"] as String?
                    assertNotNull("$id export expected", export)
                    assertEquals("$id round-trip", export, profile.exportText())
                }
            }
        }
    }

    @Test
    fun refusalVocabularyIsExactlyTheCorpusSet() {
        val file = corpusFile()
        assumeTrue("tunnel corpus not present", file.isFile)
        val root = JsonParser(file.readText()).parse() as Map<String, Any?>
        val vocabulary = strings(root["refusal_vocabulary"]).toSet()
        assertEquals(
            setOf(
                TunnelProfileParser.REFUSAL_INVALID_KEY,
                TunnelProfileParser.REFUSAL_ENDPOINT_MISSING_PORT,
                TunnelProfileParser.REFUSAL_INVALID_CIDR,
                TunnelProfileParser.REFUSAL_MISSING_SERVER_KEY,
            ),
            vocabulary,
        )
    }

    @Test
    fun renamedProfileKeepsEverythingButTheNameComment() {
        val cases = loadCases()
        val minimal = cases.first { it["id"] == "wg-minimal-full-tunnel" }
        val input = minimal["input_text"] as String
        val profile = (TunnelProfileParser.parse(input) as TunnelParseResult.Valid).profile
        val renamed = profile.withName("Renamed Home")
        assertEquals("Renamed Home", renamed.name)
        val exported = renamed.exportText()
        assertTrue(exported.startsWith("# Sphinx profile: Renamed Home\n"))
        // Everything after the first line is byte-identical.
        assertEquals(
            input.substringAfter('\n'),
            exported.substringAfter('\n'),
        )
        // And the renamed export parses back to the same facts.
        val reparsed = (TunnelProfileParser.parse(exported) as TunnelParseResult.Valid).profile
        assertEquals("Renamed Home", reparsed.name)
        assertEquals(input, (reparsed.withName("Home Server")).exportText())
    }
}
