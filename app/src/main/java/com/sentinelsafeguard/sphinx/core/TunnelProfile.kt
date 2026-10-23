package com.sentinelsafeguard.sphinx.core

import java.util.Base64

/**
 * Server profiles for VPN (TUNNEL) mode — docs/TUNNEL-SPEC.md.
 *
 * The interchange format is the standard WireGuard config text
 * ([Interface] / [Peer]). Parsing is LOSSLESS: the profile keeps
 * every line of the input, in order — recognized fields, fields
 * Sphinx does not use, comments — and [exportText] reproduces the
 * input exactly, modulo a single trailing-newline normalization.
 * Silent data loss is a spec violation, so nothing is dropped:
 * unrecognized keys land in the extras bag (they are visible in
 * the parsed facts and in the export), and a profile is refused
 * at import, with the reason named, only for the corpus refusal
 * vocabulary: invalid-key, endpoint-missing-port, invalid-cidr,
 * missing-server-key.
 *
 * Sphinx writes its profile name as a comment on the first line
 * of its own exports (`# Sphinx profile: <name>`) and reads it
 * back. The name is a label only.
 *
 * An OpenVPN config is *recognized* as a stored, labeled record
 * (protocol=openvpn, text preserved); connecting one is refused
 * in Phase 1 with the reason named — see [OPENVPN_CONNECT_REFUSAL].
 * That refusal is the honest Phase 1 behavior per TUNNEL-SPEC,
 * tied to the Android OpenVPN licensing gate (GPLv3/AGPLv3
 * embeddable options would end the edition's MIT story).
 *
 * Pure Kotlin — no Android APIs. Private keys exist here only as
 * the config text the user imported or explicitly exports; the
 * store (lists/TunnelStore) keeps them in app-private storage
 * and nothing in this file logs or prints them.
 */
sealed class ServerProfile {
    abstract val protocol: String
    abstract val name: String?
    abstract val endpoint: String?
    abstract fun exportText(): String

    /** A copy carrying [newName] as its Sphinx name. For WireGuard
     *  profiles this rewrites the name comment; for OpenVPN
     *  records the name lives in the store, not the text, so the
     *  record is re-labeled without touching its config text. */
    abstract fun withName(newName: String?): ServerProfile
}

/** One [Peer] section of a WireGuard profile. */
data class WgPeer(
    val publicKey: String,
    val presharedKey: String?,
    val endpoint: String?,
    val allowedIps: List<String>,
    val persistentKeepalive: Int?,
)

class WgProfile(
    override val name: String?,
    val privateKey: String?,
    val clientAddresses: List<String>,
    val dnsServers: List<String>,
    val mtu: Int?,
    val peers: List<WgPeer>,
    private val rawLines: List<String>,
) : ServerProfile() {

    override val protocol: String get() = PROTOCOL_WIREGUARD

    /** The first peer is the profile's headline server (the
     *  corpus's profile facts are stated in these terms). */
    val firstPeer: WgPeer? get() = peers.firstOrNull()
    override val endpoint: String? get() = firstPeer?.endpoint
    val serverPublicKey: String? get() = firstPeer?.publicKey
    val allowedIps: List<String> get() = firstPeer?.allowedIps ?: emptyList()
    val presharedKey: String? get() = firstPeer?.presharedKey
    val persistentKeepalive: Int? get() = firstPeer?.persistentKeepalive

    /**
     * "all" when the allowed-IPs cover the whole device for every
     * address family the profile uses, else "some" (a split
     * tunnel — the UI must say "some traffic", never present it
     * as full protection).
     */
    val scope: String
        get() {
            val union = peers.flatMap { it.allowedIps }.toSet()
            val v4Default = "0.0.0.0/0" in union
            val v6Default = "::/0" in union
            val hasV6 = clientAddresses.any { it.contains(':') } || v6Default
            val hasV4 = clientAddresses.any { it.contains('.') } || v4Default
            return if ((!hasV4 || v4Default) && (!hasV6 || v6Default) &&
                (v4Default || v6Default)
            ) {
                "all"
            } else {
                "some"
            }
        }

    override fun exportText(): String = rawLines.joinToString("\n") + "\n"

    override fun withName(newName: String?): WgProfile {
        val lines = rawLines.toMutableList()
        val hasComment = lines.isNotEmpty() && isSphinxNameComment(lines[0])
        val clean = newName?.trim()?.takeIf { it.isNotEmpty() }
        when {
            clean != null && hasComment -> lines[0] = "# Sphinx profile: $clean"
            clean != null -> lines.add(0, "# Sphinx profile: $clean")
            hasComment -> lines.removeAt(0)
        }
        return WgProfile(
            clean, privateKey, clientAddresses, dnsServers, mtu, peers, lines,
        )
    }

    companion object {
        const val PROTOCOL_WIREGUARD = "wireguard"
    }
}

/** An OpenVPN profile record: config text preserved losslessly,
 *  labeled, never connected in Phase 1. */
class OvpnProfile(
    override val name: String?,
    override val endpoint: String?,
    private val rawLines: List<String>,
) : ServerProfile() {
    override val protocol: String get() = PROTOCOL_OPENVPN
    override fun exportText(): String = rawLines.joinToString("\n") + "\n"
    override fun withName(newName: String?): OvpnProfile =
        OvpnProfile(newName?.trim()?.takeIf { it.isNotEmpty() }, endpoint, rawLines)

    companion object {
        const val PROTOCOL_OPENVPN = "openvpn"
    }
}

/** The result of parsing config text: a profile, or a refusal
 *  with the corpus reason named. */
sealed class TunnelParseResult {
    data class Valid(val profile: ServerProfile) : TunnelParseResult()
    data class Refused(val reason: String) : TunnelParseResult()
}

object TunnelProfileParser {

    const val REFUSAL_INVALID_KEY = "invalid-key"
    const val REFUSAL_ENDPOINT_MISSING_PORT = "endpoint-missing-port"
    const val REFUSAL_INVALID_CIDR = "invalid-cidr"
    const val REFUSAL_MISSING_SERVER_KEY = "missing-server-key"
    const val REFUSAL_UNRECOGNIZED = "unrecognized-format"

    const val OPENVPN_CONNECT_REFUSAL: String =
        "OpenVPN profiles are stored and labeled in this version, but " +
            "connecting one is refused: Android has no system OpenVPN " +
            "program to run, and the embeddable OpenVPN libraries are " +
            "GPL/AGPL, which would end this app's MIT license story. " +
            "This profile is kept exactly as imported."

    private const val NAME_PREFIX = "# Sphinx profile:"

    fun isSphinxNameComment(line: String): Boolean = line.startsWith(NAME_PREFIX)

    fun sphinxNameOf(firstLine: String): String? =
        if (isSphinxNameComment(firstLine)) {
            firstLine.substring(NAME_PREFIX.length).trim().takeIf { it.isNotEmpty() }
        } else {
            null
        }

    /** Split into lines with the single trailing-newline
     *  normalization the spec allows: CRLF becomes LF and any
     *  run of trailing blank lines collapses to the one final
     *  newline [exportText] writes. */
    fun normalizedLines(text: String): List<String> {
        val lines = text.split("\n").map { it.trimEnd('\r') }.toMutableList()
        while (lines.isNotEmpty() && lines.last().isEmpty()) lines.removeAt(lines.lastIndex)
        return lines
    }

    /**
     * Parse config text. [fallbackName] supplies the profile
     * name when the text carries no Sphinx name comment (from
     * the file name on file import, per TUNNEL-SPEC); it never
     * overrides a name comment.
     */
    fun parse(text: String, fallbackName: String? = null): TunnelParseResult {
        val lines = normalizedLines(text)
        if (lines.isEmpty()) return TunnelParseResult.Refused(REFUSAL_UNRECOGNIZED)
        val hasInterface = lines.any { it.trim().equals("[Interface]", ignoreCase = true) }
        if (hasInterface) return parseWireGuard(lines, fallbackName)
        if (looksLikeOpenVpn(lines)) return TunnelParseResult.Valid(parseOpenVpn(lines, fallbackName))
        return TunnelParseResult.Refused(REFUSAL_UNRECOGNIZED)
    }

    private fun looksLikeOpenVpn(lines: List<String>): Boolean =
        lines.any { raw ->
            val line = raw.trim()
            line == "client" || line.startsWith("remote ") ||
                line.startsWith("dev ") || line.startsWith("proto ")
        }

    private fun parseOpenVpn(lines: List<String>, fallbackName: String?): OvpnProfile {
        var endpoint: String? = null
        for (raw in lines) {
            val line = raw.trim()
            if (line.startsWith("remote ")) {
                val parts = line.removePrefix("remote ").trim().split(Regex("\\s+"))
                if (parts.size >= 2) endpoint = "${parts[0]}:${parts[1]}"
                else if (parts.isNotEmpty()) endpoint = parts[0]
                break
            }
        }
        return OvpnProfile(fallbackName?.trim()?.takeIf { it.isNotEmpty() }, endpoint, lines)
    }

    private fun parseWireGuard(lines: List<String>, fallbackName: String?): TunnelParseResult {
        val name = lines.firstOrNull()?.let { sphinxNameOf(it) }
            ?: fallbackName?.trim()?.takeIf { it.isNotEmpty() }

        var privateKey: String? = null
        var addresses: List<String> = emptyList()
        var dns: List<String> = emptyList()
        var mtu: Int? = null

        data class PeerDraft(
            var publicKey: String? = null,
            var presharedKey: String? = null,
            var endpoint: String? = null,
            var allowedIps: List<String> = emptyList(),
            var keepalive: Int? = null,
        )

        val peerDrafts = ArrayList<PeerDraft>()
        var section = 0 // 0 = preamble, 1 = Interface, 2 = Peer
        var currentPeer: PeerDraft? = null

        for (raw in lines) {
            val line = raw.trim()
            when {
                line.equals("[Interface]", ignoreCase = true) -> {
                    section = 1
                    currentPeer = null
                    continue
                }
                line.equals("[Peer]", ignoreCase = true) -> {
                    section = 2
                    currentPeer = PeerDraft()
                    peerDrafts.add(currentPeer)
                    continue
                }
                line.startsWith("[") -> {
                    // An unknown section: its lines stay in the
                    // raw text (lossless), but they are not fields
                    // Sphinx can act on.
                    section = 0
                    currentPeer = null
                    continue
                }
            }
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue
            val eq = line.indexOf('=')
            if (eq <= 0) continue
            val key = line.substring(0, eq).trim()
            val value = line.substring(eq + 1).trim()
            fun csv(): List<String> = value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            when (section) {
                1 -> when (key) {
                    "PrivateKey" -> privateKey = value
                    "Address" -> addresses = csv()
                    "DNS" -> dns = csv()
                    "MTU" -> mtu = value.toIntOrNull()
                    else -> Unit // extras bag: preserved in rawLines
                }
                2 -> when (key) {
                    "PublicKey" -> currentPeer?.publicKey = value
                    "PresharedKey" -> currentPeer?.presharedKey = value
                    "Endpoint" -> currentPeer?.endpoint = value
                    "AllowedIPs" -> currentPeer?.allowedIps = csv()
                    "PersistentKeepalive" -> currentPeer?.keepalive = value.toIntOrNull()
                    else -> Unit // extras bag: preserved in rawLines
                }
            }
        }

        // --- Validation, in the corpus's vocabulary. Each bad
        // case in the corpus carries exactly one fault, and the
        // checks below name it. A refused profile changes
        // nothing in the store (the store writes only Valid). ---
        if (privateKey != null && !isValidKey(privateKey)) {
            return TunnelParseResult.Refused(REFUSAL_INVALID_KEY)
        }
        if (peerDrafts.isEmpty() || peerDrafts.any { it.publicKey == null }) {
            return TunnelParseResult.Refused(REFUSAL_MISSING_SERVER_KEY)
        }
        for (peer in peerDrafts) {
            if (!isValidKey(peer.publicKey)) {
                return TunnelParseResult.Refused(REFUSAL_INVALID_KEY)
            }
            if (peer.presharedKey != null && !isValidKey(peer.presharedKey)) {
                return TunnelParseResult.Refused(REFUSAL_INVALID_KEY)
            }
        }
        for (peer in peerDrafts) {
            val ep = peer.endpoint ?: return TunnelParseResult.Refused(REFUSAL_ENDPOINT_MISSING_PORT)
            if (parseEndpoint(ep) == null) {
                return TunnelParseResult.Refused(REFUSAL_ENDPOINT_MISSING_PORT)
            }
        }
        for (cidr in addresses + peerDrafts.flatMap { it.allowedIps }) {
            if (!isValidCidr(cidr)) return TunnelParseResult.Refused(REFUSAL_INVALID_CIDR)
        }

        val peers = peerDrafts.map { draft ->
            WgPeer(
                publicKey = draft.publicKey!!,
                presharedKey = draft.presharedKey,
                endpoint = draft.endpoint,
                allowedIps = draft.allowedIps,
                persistentKeepalive = draft.keepalive,
            )
        }
        return TunnelParseResult.Valid(
            WgProfile(name, privateKey, addresses, dns, mtu, peers, lines)
        )
    }

    /** host:port or [v6host]:port → (host, port), or null when
     *  there is no usable port (the corpus refusal). */
    fun parseEndpoint(endpoint: String): Pair<String, Int>? {
        val value = endpoint.trim()
        if (value.startsWith("[")) {
            val close = value.indexOf(']')
            if (close < 0) return null
            val host = value.substring(1, close)
            val rest = value.substring(close + 1)
            if (!rest.startsWith(":")) return null
            val port = rest.substring(1).toIntOrNull() ?: return null
            if (host.isEmpty() || port !in 1..65535) return null
            return host to port
        }
        val colon = value.lastIndexOf(':')
        if (colon <= 0) return null
        val host = value.substring(0, colon)
        val port = value.substring(colon + 1).toIntOrNull() ?: return null
        if (host.isEmpty() || port !in 1..65535) return null
        return host to port
    }

    /** A WireGuard key: 32 bytes as canonical base64 — 44
     *  characters, and re-encoding the decoded bytes reproduces
     *  the input exactly. */
    fun isValidKey(value: String?): Boolean {
        val key = value?.trim() ?: return false
        if (key.length != 44) return false
        val decoded = try {
            Base64.getDecoder().decode(key)
        } catch (e: IllegalArgumentException) {
            return false
        }
        if (decoded.size != 32) return false
        return Base64.getEncoder().encodeToString(decoded) == key
    }

    /** CIDR notation with a valid address and a prefix inside
     *  the family's range. A bare address is not a CIDR. */
    fun isValidCidr(value: String): Boolean {
        val slash = value.lastIndexOf('/')
        if (slash <= 0) return false
        val address = value.substring(0, slash)
        val prefix = value.substring(slash + 1).toIntOrNull() ?: return false
        return if (address.contains(':')) {
            isValidIpv6(address) && prefix in 0..128
        } else {
            isValidIpv4(address) && prefix in 0..32
        }
    }

    fun isValidIpv4(address: String): Boolean {
        val parts = address.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all { it.isDigit() } &&
                part.toInt() in 0..255
        }
    }

    fun isValidIpv6(address: String): Boolean {
        var rest = address
        // An embedded IPv4 tail counts as two groups.
        var extraGroups = 0
        if (rest.contains('.')) {
            val lastColon = rest.lastIndexOf(':')
            if (lastColon < 0) return false
            if (!isValidIpv4(rest.substring(lastColon + 1))) return false
            rest = rest.substring(0, lastColon)
            extraGroups = 2
        }
        val halves = rest.split("::")
        if (halves.size > 2) return false
        fun groups(part: String): List<String> =
            if (part.isEmpty()) emptyList() else part.split(':')
        val head = groups(halves[0])
        val tail = if (halves.size == 2) groups(halves[1]) else emptyList()
        val total = head.size + tail.size + extraGroups
        val shapeOk = (head + tail).all { group ->
            group.length in 1..4 && group.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
        }
        if (!shapeOk) return false
        return if (halves.size == 2) total < 8 else total == 8
    }

    /**
     * The config text for a profile created on this device: the
     * caller supplies a private key generated by the tunnel
     * library's own crypto (never hand-rolled, never derived
     * from the name — see lists/TunnelStore.generateKeyPair).
     * Building text and re-parsing it through [parse] keeps one
     * front door for validation.
     */
    fun buildLocalConfigText(
        name: String,
        privateKey: String,
        serverPublicKey: String,
        endpoint: String,
        clientAddress: String,
        dnsServers: List<String> = emptyList(),
        allowedIps: List<String> = listOf("0.0.0.0/0"),
    ): String {
        val lines = ArrayList<String>()
        lines.add("# Sphinx profile: $name")
        lines.add("[Interface]")
        lines.add("PrivateKey = $privateKey")
        lines.add("Address = $clientAddress")
        if (dnsServers.isNotEmpty()) lines.add("DNS = ${dnsServers.joinToString(", ")}")
        lines.add("")
        lines.add("[Peer]")
        lines.add("PublicKey = $serverPublicKey")
        lines.add("Endpoint = $endpoint")
        lines.add("AllowedIPs = ${allowedIps.joinToString(", ")}")
        return lines.joinToString("\n") + "\n"
    }
}
