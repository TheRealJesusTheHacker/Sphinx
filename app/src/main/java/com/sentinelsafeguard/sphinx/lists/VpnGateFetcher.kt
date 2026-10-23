package com.sentinelsafeguard.sphinx.lists

import com.sentinelsafeguard.sphinx.core.VpnGate
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * The production fetch of the VPN Gate feed — at use time only
 * (the user opens the public-nodes section on purpose; nothing
 * fetches in the background, and nothing is bundled).
 *
 * Discipline, mirroring ListUpdater's: HTTPS only, redirects
 * are NOT followed automatically (a redirect off the feed's own
 * HTTPS answer is a failure, not a detour), timeouts bounded,
 * and the body is size-capped WHILE reading — an oversized
 * response is refused whole, never parsed in part. Returns the
 * feed text, or null on any failure; the caller (the directory
 * flow) decides between the labeled cache and the honest empty
 * state. Blocking — run it from a background thread.
 */
object VpnGateFetcher {

    fun fetchFeedText(): String? {
        var connection: HttpURLConnection? = null
        return try {
            connection = URL(VpnGate.FEED_URL).openConnection() as HttpURLConnection
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("User-Agent", USER_AGENT)
            if (connection.responseCode != HttpURLConnection.HTTP_OK) return null
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            connection.inputStream.use { input ->
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (out.size() + read > VpnGate.MAX_FEED_BYTES) return null
                    out.write(buffer, 0, read)
                }
            }
            out.toByteArray().toString(Charsets.UTF_8)
        } catch (e: Exception) {
            null
        } finally {
            connection?.disconnect()
        }
    }

    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val READ_TIMEOUT_MS = 15_000
    private const val USER_AGENT = "Sphinx (Android public-nodes directory)"
}
