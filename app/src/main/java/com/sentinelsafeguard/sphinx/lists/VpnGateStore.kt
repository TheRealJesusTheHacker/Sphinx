package com.sentinelsafeguard.sphinx.lists

import android.content.Context
import com.sentinelsafeguard.sphinx.core.VpnGate
import java.io.File

/**
 * The VPN Gate directory's on-device cache: the last good feed,
 * in app-private storage (filesDir), WITH its fetch time —
 * docs/TUNNEL-SPEC.md, Phase 2. The codec and the age labeling
 * are pure (core/VpnGate); this class is only the file. Writes
 * are atomic (temp file + rename), the fleet's store discipline:
 * a crash mid-write keeps the previous cache.
 *
 * The cache is a convenience for a dead feed, never a claim:
 * it is only ever shown labeled with its age, and there is no
 * bundled/offline list behind it — no cache file simply means
 * the honest empty state.
 */
class VpnGateStore(context: Context) {

    private val appContext = context.applicationContext
    private val cacheFile = File(appContext.filesDir, CACHE_FILE_NAME)

    fun loadCache(): VpnGate.CachedFeed? {
        val stored = try {
            if (cacheFile.isFile) cacheFile.readText() else null
        } catch (e: Exception) {
            null
        }
        return VpnGate.decodeCache(stored)
    }

    /** Record a live fetch. A failure to cache never fails the
     *  listing the user is looking at. */
    fun saveCache(feedText: String, fetchedAtMs: Long) {
        try {
            val bytes = VpnGate.encodeCache(feedText, fetchedAtMs)
                .toByteArray(Charsets.UTF_8)
            val temp = File(cacheFile.parentFile, cacheFile.name + ".tmp")
            temp.writeBytes(bytes)
            if (!temp.renameTo(cacheFile)) {
                temp.copyTo(cacheFile, overwrite = true)
                temp.delete()
            }
        } catch (e: Exception) {
            // Listing live must not fail because caching did.
        }
    }

    companion object {
        private const val CACHE_FILE_NAME = "vpngate-cache.txt"
    }
}
