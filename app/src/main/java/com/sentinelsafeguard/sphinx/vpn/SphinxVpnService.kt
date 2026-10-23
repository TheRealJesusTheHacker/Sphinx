package com.sentinelsafeguard.sphinx.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import com.sentinelsafeguard.sphinx.MainActivity
import com.sentinelsafeguard.sphinx.R
import com.sentinelsafeguard.sphinx.core.AppRules
import com.sentinelsafeguard.sphinx.core.CaptureMode
import com.sentinelsafeguard.sphinx.core.DnsPacket
import com.sentinelsafeguard.sphinx.core.DnsForwarder
import com.sentinelsafeguard.sphinx.core.DropCounts
import com.sentinelsafeguard.sphinx.core.FilterLists
import com.sentinelsafeguard.sphinx.core.IpFlow
import com.sentinelsafeguard.sphinx.core.IpUdpPacket
import com.sentinelsafeguard.sphinx.core.QueryLog
import com.sentinelsafeguard.sphinx.lists.ListStore
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Sphinx's Android edition engine.
 *
 * Establishes a TUN interface and routes ONLY the virtual DNS server
 * address (10.10.10.10) through it, so the system hands this service its
 * DNS lookups and nothing else. Each query is checked against the
 * active lists (downloaded lists when valid, otherwise the bundled
 * list; the user's allowlist always wins): blocked names get a sinkhole
 * answer built on the spot; allowed queries are forwarded to an upstream
 * resolver over a protected socket (protected, so the query can't loop
 * back into the VPN) and the real answer is written back into the TUN.
 *
 * There is no remote VPN server. Nothing leaves the phone except the
 * allowed DNS queries themselves — to the public resolvers first,
 * and, if those can't be reached from this network, to the DNS
 * servers the phone itself was using when the filter engaged
 * (captured before the interface came up; the governing rule is
 * that an allowed query degrades toward the network's own
 * resolution, never toward silence) — and, when the user taps
 * "Update lists now", HTTPS fetches of the blocklist sources shown
 * in the app. The query log is memory-only, on this device, and
 * can be turned off in the app.
 *
 * Phase 3 per-app rules change the capture shape, per
 * docs/FILTER-SPEC.md ("Per-app rules"). With no app blocked outright,
 * the interface runs in FILTER mode — the routing above, unchanged,
 * except that apps the user exempted are disallowed from the VPN and
 * bypass filtering entirely. When at least one app is blocked
 * outright, the interface runs in APP_BLOCK mode instead: only the
 * blocked apps are routed in, over a default route, and every packet
 * they send is dropped on the spot. Android cannot run both shapes on
 * one interface (routes are per-interface, and an allowlist changes
 * the whole VPN's population), so while APP_BLOCK mode lasts, every
 * other app bypasses the VPN and its DNS is not filtered. That trade
 * is stated in the app and in the README, in the open.
 */
class SphinxVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.sentinelsafeguard.sphinx.action.START"
        const val ACTION_STOP = "com.sentinelsafeguard.sphinx.action.STOP"
        const val ACTION_RELOAD_LISTS = "com.sentinelsafeguard.sphinx.action.RELOAD_LISTS"

        /** Tear the interface down and rebuild it with the rule
         *  state now on disk — app rules for the new interface, and
         *  the lists (allowlist, custom entries) reloaded into
         *  memory — how a rule change takes effect on a running
         *  filter, through the same shutdown/start lifecycle as a
         *  stop followed by a start. */
        const val ACTION_RESTART = "com.sentinelsafeguard.sphinx.action.RESTART"

        private const val VIRTUAL_DNS = "10.10.10.10"
        private const val VIRTUAL_DNS_V6 = "fd00:10:10::10"
        private const val DNS_PORT = 53
        private const val CHANNEL_ID = "sphinx_status"
        private const val NOTIFICATION_ID = 1
        private const val UPSTREAM_TIMEOUT_MS = 3000
        private const val MAX_PACKET = 65535
        private const val OWNER_CACHE_CAP = 512
        private const val OWNER_CACHE_TTL_NANOS = 60_000_000_000L // 60 s
        private const val WORK_QUEUE_CAP = 512
        private const val SYSTEM_DNS_REFRESH_MS = 30_000L

        @Volatile
        var isRunning: Boolean = false
            private set

        val blockedCount = AtomicLong(0)
        val allowedCount = AtomicLong(0)

        /** Packets dropped in APP_BLOCK mode: the total, and the
         *  per-app counts behind it. Memory-only, like everything
         *  else Sphinx counts. */
        val droppedPacketCount = AtomicLong(0)
        val dropCounts = DropCounts()

        /** Recent queries, newest last in the buffer (snapshot() shows
         *  newest first). Memory-only; shared with the UI so the user
         *  can see and clear what Sphinx questioned. */
        val queryLog = QueryLog()
    }

    private var tunInterface: ParcelFileDescriptor? = null
    private var readerThread: Thread? = null

    // Recreated by startFilter() when a previous shutdown() killed the
    // pool: a stopped ExecutorService can never take tasks again, and
    // this instance can be re-started after onRevoke/ACTION_STOP paths
    // that did not destroy it.
    private var workers: ExecutorService = newWorkerPool()

    /**
     * The packet workers — a fixed pool behind a BOUNDED queue. The
     * bound matters most in APP_BLOCK mode: every packet a blocked
     * (by definition untrusted) app sends becomes queued work, and an
     * unbounded queue would let a flooding app grow this service's
     * memory until the system kills it — taking the filter down with
     * it. When the queue is full, execute() refuses the packet: in
     * app-block mode refused *is* dropped, which is the point of the
     * mode; in filter mode the query goes unanswered and the asking
     * app retries, exactly as it does on an upstream timeout. The
     * counters count packets the workers actually processed, so under
     * an extreme flood the drop counts understate the total stopped —
     * bounded memory wins over exact bookkeeping in a flood.
     */
    private fun newWorkerPool(): ExecutorService = ThreadPoolExecutor(
        4, 4, 0L, TimeUnit.MILLISECONDS,
        LinkedBlockingQueue(WORK_QUEUE_CAP),
        ThreadPoolExecutor.AbortPolicy(),
    )
    private val writeLock = Any()

    @Volatile
    private var running = false

    private lateinit var store: ListStore

    // The lists in force. Loaded off the main thread (parsing a real
    // blocklist takes a moment); the first load is awaited before the
    // filter starts, and later reloads swap the reference atomically —
    // queries in flight keep using the list they started with, and the
    // new list answers only once it is fully parsed and validated.
    @Volatile
    private var filterLists: FilterLists? = null

    private val listsReady = CountDownLatch(1)

    @Volatile
    private var logEnabled = true

    // The DNS servers the phone itself was using, read from the
    // non-VPN networks (see captureSystemDns). Captured BEFORE the
    // interface is established — once Sphinx is up, the system's
    // DNS is Sphinx — and refreshed when the snapshot goes stale,
    // so a network change (Wi-Fi ↔ mobile) heals it. These are the
    // floor of the upstream chain: the resolvers that provably
    // answered this phone a moment ago.
    @Volatile
    private var capturedSystemDns: List<InetAddress> = emptyList()

    @Volatile
    private var systemDnsCapturedAtMs: Long = 0L

    override fun onCreate() {
        super.onCreate()
        store = ListStore(this)
        Thread({
            try {
                reloadListsNow()
            } catch (e: Exception) {
                // One retry before giving up: a transient storage
                // hiccup must not decide whether the filter can run.
                // If the load still fails, filterLists stays null,
                // the latch still falls (finally), and startFilter
                // refuses to establish — a filter that cannot
                // question must never capture the phone's DNS and
                // then answer nothing at all.
                try {
                    reloadListsNow()
                } catch (e2: Exception) {
                    // Stays null; startFilter fails loud (stays off).
                }
            } finally {
                listsReady.countDown()
            }
        }, "sphinx-list-loader").start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                shutdown()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RELOAD_LISTS -> {
                // A list update, an allowlist edit, or a settings
                // change: reload in the background and swap when ready.
                // Never starts the filter by itself.
                Thread({ reloadListsNow() }, "sphinx-list-reloader").start()
                return START_NOT_STICKY
            }
            ACTION_RESTART -> {
                // A rule change on a running filter: rebuild the
                // interface through the ordinary shutdown/start path,
                // so the new rules run on exactly the lifecycle a stop
                // and start would have produced — no third state. The
                // lists are reloaded too, not just the interface: a
                // profile switch (Phase 4) changes the allowlist and
                // custom entries, which live only in the in-memory
                // lists — rebuilding the interface alone would leave
                // the running filter questioning with the *previous*
                // profile's lists until some unrelated reload (Phase 4
                // audit finding). A stop and start would have loaded
                // them fresh; so does a restart, now.
                if (running) {
                    shutdown()
                    startFilter()
                    Thread({ reloadListsNow() }, "sphinx-list-reloader").start()
                    return START_STICKY
                }
                // Not running: a restart changes nothing, so don't
                // claim stickiness for it — a sticky-but-idle service
                // would be resurrected by the system with a null
                // intent, which the start path reads as "start the
                // filter", turning protection on by itself after a
                // crash while the user believes it is off.
                return START_NOT_STICKY
            }
            else -> {
                if (!running) {
                    // Go foreground BEFORE waiting for the lists.
                    // When the boot receiver (Phase 4) starts this
                    // service with startForegroundService, Android
                    // gives the service only a few seconds to call
                    // startForeground or it kills the app — and at
                    // boot, under load from everything else starting,
                    // the first list parse can take longer than that
                    // (Phase 4 audit finding). The notification goes
                    // up now; startFilter posts it again (same ID —
                    // a no-op update) once the interface is up.
                    startForegroundWithNotification()
                    // Don't run unfiltered while the lists load: wait
                    // for the first load (bounded — parsing is fast,
                    // and the bundled asset cannot be missing).
                    listsReady.await(15, TimeUnit.SECONDS)
                    startFilter()
                }
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        shutdown()
        stopSelf() // the VPN is gone; don't linger as a zombie instance
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun reloadListsNow() {
        filterLists = store.loadEffectiveLists()
        logEnabled = store.queryLogEnabled()
    }

    private fun startFilter() {
        if (filterLists == null) {
            // The lists never loaded (the loader retried and
            // failed). Establishing now would capture the phone's
            // DNS and answer nothing at all — no sinkholes, no
            // forwards, a silent blackhole wearing the filter's
            // name. Fail loud instead: stay off, and record that.
            store.setFilterOnIntent(false)
            stopSelf()
            return
        }
        if (workers.isShutdown) {
            workers = newWorkerPool()
        }
        startForegroundWithNotification()
        // Save the originals first (the fleet's engage discipline):
        // the phone's own DNS servers, captured before the
        // interface exists — after establish() the system's DNS
        // would read as Sphinx itself.
        capturedSystemDns = captureSystemDns()
        systemDnsCapturedAtMs = SystemClock.elapsedRealtime()
        val rules = store.loadAppRules()
        var mode = rules.captureMode()
        var builder = buildInterface(rules, mode)
        if (mode == CaptureMode.APP_BLOCK && builder == null) {
            // Degenerate rule state, guarded deliberately: every
            // blocked app has been uninstalled, so the app-block
            // population came up empty — and an empty allowlist under
            // a default route would capture the WHOLE phone into the
            // drop path. Run in filter mode instead (FILTER-SPEC.md,
            // "Per-app rules") until the rules name an installed app.
            mode = CaptureMode.FILTER
            builder = buildInterface(rules, mode)
        }
        val descriptor = builder!!.establish()
        if (descriptor == null) {
            store.setFilterOnIntent(false)
            stopSelf()
            return
        }
        tunInterface = descriptor
        running = true
        isRunning = true
        // The filter is genuinely on: record the user's intent, so
        // boot auto-start (Phase 4, opt-in) restarts what was left
        // on — and only what was left on.
        store.setFilterOnIntent(true)
        readerThread = Thread(
            { packetLoop(descriptor, mode) },
            "sphinx-tun-reader",
        ).apply { start() }
    }

    /**
     * The interface for one capture mode. In FILTER mode this never
     * fails to build. In APP_BLOCK mode it returns null when no
     * blocked app could be added to the population (all uninstalled)
     * — the caller falls back to FILTER rather than establish an
     * empty-population default-route interface.
     */
    private fun buildInterface(rules: AppRules, mode: CaptureMode): Builder? {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1500)
        when (mode) {
            CaptureMode.FILTER -> {
                // The Phase 1/2 shape: only the virtual DNS address is
                // routed in, so the system hands us its DNS lookups
                // and nothing else. Exempted apps are disallowed from
                // the VPN outright — neither the route nor the VPN's
                // DNS server applies to them; they connect exactly as
                // if Sphinx were not installed.
                builder
                    .addAddress(VIRTUAL_DNS, 32)
                    .addRoute(VIRTUAL_DNS, 32)
                    .addDnsServer(VIRTUAL_DNS)
                for (pkg in rules.excludedPackages) {
                    try {
                        builder.addDisallowedApplication(pkg)
                    } catch (e: Exception) {
                        // The app was uninstalled after the rule was
                        // set (the documented NameNotFoundException),
                        // or refused for any other reason: the rule
                        // simply matches nothing. One bad rule must
                        // never take the whole start path down.
                    }
                }
            }
            CaptureMode.APP_BLOCK -> {
                // Only the blocked apps are routed in — every other
                // app bypasses this VPN entirely while this mode lasts
                // (see the class doc and FILTER-SPEC.md). A default
                // route on both families draws a blocked app's whole
                // traffic into the tunnel, where the reader drops it
                // all. The virtual DNS server is still the nominal
                // resolver, so even its lookups arrive as packets and
                // are dropped like everything else it sends.
                builder
                    .addAddress(VIRTUAL_DNS, 32)
                    .addAddress(VIRTUAL_DNS_V6, 128)
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                    .addDnsServer(VIRTUAL_DNS)
                var added = 0
                for (pkg in rules.blockedPackages) {
                    try {
                        builder.addAllowedApplication(pkg)
                        added++
                    } catch (e: Exception) {
                        // Uninstalled since the rule was set (the
                        // documented NameNotFoundException), or refused
                        // for any other reason. If that leaves the
                        // population empty, the caller falls back to
                        // FILTER below — a bad rule degrades the mode,
                        // it never crashes the start.
                    }
                }
                if (added == 0) return null
            }
        }
        return builder
    }

    private fun packetLoop(descriptor: ParcelFileDescriptor, mode: CaptureMode) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val output = FileOutputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(MAX_PACKET)
        while (running) {
            val length = try {
                input.read(buffer)
            } catch (e: Exception) {
                break // TUN closed during shutdown
            }
            if (length <= 0) continue
            val packet = buffer.copyOf(length)
            try {
                workers.execute {
                    if (mode == CaptureMode.APP_BLOCK) dropPacket(packet)
                    else handlePacket(packet, output)
                }
            } catch (e: Exception) {
                // Pool shut down mid-stop, or the bounded queue is
                // full under a flood: drop the packet (see
                // newWorkerPool); the loop condition ends the thread
                // on the next pass when shutting down.
            }
        }
    }

    /**
     * APP_BLOCK mode: a packet from an app the user blocked outright.
     * It is dropped — never forwarded, never answered, never sent
     * anywhere. Only its IP/transport headers are read, to count the
     * drop against the app that sent it.
     */
    private fun dropPacket(packet: ByteArray) {
        droppedPacketCount.incrementAndGet()
        dropCounts.increment(attributeOwner(packet))
    }

    // Flow-key → owning package ("" = looked up, unknown), stamped
    // when cached. Entries expire: every blocked app shares the same
    // tunnel source addresses, so a flow key is ports and destination
    // — and ephemeral ports are reused once a connection closes. A
    // permanent entry could pin a recycled flow to the app that held
    // it earlier, which is a guess wearing a fact's clothes; past the
    // TTL the platform is asked again, and an unanswered re-ask lands
    // in the unattributed bucket where uncertainty belongs. Bounded
    // by a blunt clear when it grows past the cap; attribution is a
    // display nicety, never worth unbounded memory.
    private class CachedOwner(val owner: String, val atNanos: Long)

    private val ownerCache = ConcurrentHashMap<String, CachedOwner>()

    /**
     * Best-effort: which app sent this packet, via the platform's
     * connection-owner lookup. Null when the platform can't say (old
     * Android, an unparseable packet, a flow already gone) — the drop
     * is counted as unattributed rather than guessed at.
     */
    private fun attributeOwner(packet: ByteArray): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        val flow = IpFlow.parse(packet, packet.size) ?: return null
        if (flow.sourcePort == 0 || flow.destPort == 0) return null
        val key = buildString {
            append(flow.protocol).append('|')
            append(flow.sourceAddress.toHex()).append(':').append(flow.sourcePort)
            append('|')
            append(flow.destAddress.toHex()).append(':').append(flow.destPort)
        }
        ownerCache[key]?.let { cached ->
            if (System.nanoTime() - cached.atNanos < OWNER_CACHE_TTL_NANOS) {
                return cached.owner.ifEmpty { null }
            }
        }
        val owner = try {
            val manager = getSystemService(ConnectivityManager::class.java)
            val uid = manager.getConnectionOwnerUid(
                flow.protocol,
                InetSocketAddress(
                    InetAddress.getByAddress(flow.sourceAddress), flow.sourcePort,
                ),
                InetSocketAddress(
                    InetAddress.getByAddress(flow.destAddress), flow.destPort,
                ),
            )
            if (uid >= 0) packageManager.getPackagesForUid(uid)?.firstOrNull() else null
        } catch (e: Exception) {
            null
        }
        if (ownerCache.size > OWNER_CACHE_CAP) ownerCache.clear()
        ownerCache[key] = CachedOwner(owner ?: "", System.nanoTime())
        return owner
    }

    /**
     * The DNS servers of every non-VPN network that offers
     * internet — the phone's own resolvers, in the platform's
     * order. Read from the live networks at capture time; whatever
     * was gathered stands if the platform refuses partway, and an
     * empty result simply leaves the upstream chain at its public
     * head.
     */
    private fun captureSystemDns(): List<InetAddress> {
        val manager = getSystemService(ConnectivityManager::class.java)
            ?: return emptyList()
        val servers = LinkedHashSet<InetAddress>()
        try {
            for (network in manager.allNetworks) {
                val caps = manager.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                manager.getLinkProperties(network)?.dnsServers?.let { servers.addAll(it) }
            }
        } catch (e: Exception) {
            // Whatever was gathered stands.
        }
        return servers.toList()
    }

    /** The captured snapshot, refreshed when it is empty or older
     *  than [SYSTEM_DNS_REFRESH_MS] — a network handover while the
     *  filter runs must not strand the chain's floor on the
     *  previous network's servers. A refresh that finds nothing
     *  keeps the previous snapshot rather than emptying the floor. */
    private fun systemDnsServers(): List<InetAddress> {
        val age = SystemClock.elapsedRealtime() - systemDnsCapturedAtMs
        if (capturedSystemDns.isEmpty() || age > SYSTEM_DNS_REFRESH_MS) {
            val fresh = captureSystemDns()
            if (fresh.isNotEmpty() || capturedSystemDns.isEmpty()) {
                capturedSystemDns = fresh
            }
            systemDnsCapturedAtMs = SystemClock.elapsedRealtime()
        }
        return capturedSystemDns
    }

    private fun handlePacket(packet: ByteArray, output: FileOutputStream) {
        // Nothing in here may throw: one malformed packet gets dropped,
        // never takes a worker — or the filter — down with it.
        try {
            val ip = IpUdpPacket.parse(packet, packet.size) ?: return
            if (ip.destPort != DNS_PORT) return
            if (!ip.destAddress.contentEquals(VIRTUAL_DNS_BYTES)) return

            val queryBytes = packet.copyOfRange(ip.payloadOffset, ip.payloadOffset + ip.payloadLength)
            val dns = DnsPacket.parse(queryBytes, queryBytes.size) ?: return
            if (dns.isResponse) return

            val lists = filterLists ?: return
            val blocked = lists.isBlocked(dns.questionName)
            if (logEnabled) {
                queryLog.record(dns.questionName, blocked, System.currentTimeMillis())
            }
            if (blocked) {
                blockedCount.incrementAndGet()
                writeResponse(output, IpUdpPacket.buildResponse(ip, dns.buildSinkholeResponse()))
            } else {
                // Count at the decision, per FILTER-SPEC.md ("allowed
                // (forwarded)") — an upstream failure must not make a
                // let-through query vanish from both counters.
                allowedCount.incrementAndGet()
                val answer = forward(queryBytes)
                if (answer != null) {
                    writeResponse(output, IpUdpPacket.buildResponse(ip, answer))
                }
                // No answer from any upstream: leave the query unanswered
                // and let the asking app retry, per FILTER-SPEC.md.
            }
        } catch (e: Exception) {
            // Dropped. Hostile input ends here, quietly.
        }
    }

    /**
     * Send a DNS query to the upstream chain; null if the whole
     * chain fails. The exchange itself is [DnsForwarder] — the
     * pure-Kotlin port of the Python editions' forwarder,
     * JVM-tested there — fed with the chain the spec now requires:
     * the public resolvers at the head and the phone's own DNS
     * servers, captured at engage time, as the floor. This
     * service's protect() is supplied — and its verdict honored
     * by the forwarder — so the upstream sockets (UDP, and TCP
     * when a truncated answer is completed per RFC 7766) can't
     * loop back into the VPN. Accept only the answer to *this*
     * query: matching ID, QR (response) bit set — the same
     * discipline every stub resolver applies (FILTER-SPEC.md,
     * forwarding rules), enforced in the forwarder.
     */
    private fun forward(query: ByteArray): ByteArray? =
        DnsForwarder.forwardQuery(
            query,
            resolvers = DnsForwarder.upstreamChain(systemDnsServers()),
            timeoutMs = UPSTREAM_TIMEOUT_MS,
            port = DNS_PORT,
            protectUdp = { protect(it) },
            protectTcp = { protect(it) },
        )

    private fun writeResponse(output: FileOutputStream, packet: ByteArray) {
        synchronized(writeLock) {
            try {
                output.write(packet)
                output.flush()
            } catch (e: Exception) {
                // TUN is going away (shutdown); nothing useful to do.
            }
        }
    }

    private fun shutdown() {
        running = false
        isRunning = false
        // The filter is off from here: record it. (A restart calls
        // shutdown() and then startFilter(), which records "on"
        // again once the new interface is genuinely up.)
        store.setFilterOnIntent(false)
        workers.shutdownNow()
        try {
            tunInterface?.close()
        } catch (e: Exception) {
            // Already closed.
        }
        tunInterface = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun startForegroundWithNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            )
            manager.createNotificationChannel(channel)
        }

        val openApp = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, SphinxVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(R.drawable.ic_sphinx)
            .setContentIntent(openApp)
            .addAction(0, getString(R.string.notification_stop), stop)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }
}

private val VIRTUAL_DNS_BYTES = byteArrayOf(10, 10, 10, 10)

private fun ByteArray.toHex(): String =
    joinToString("") { "%02x".format(it.toInt() and 0xFF) }
