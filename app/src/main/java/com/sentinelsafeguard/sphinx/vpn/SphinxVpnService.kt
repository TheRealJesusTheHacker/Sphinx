package com.sentinelsafeguard.sphinx.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.sentinelsafeguard.sphinx.MainActivity
import com.sentinelsafeguard.sphinx.R
import com.sentinelsafeguard.sphinx.core.DnsPacket
import com.sentinelsafeguard.sphinx.core.FilterLists
import com.sentinelsafeguard.sphinx.core.IpUdpPacket
import com.sentinelsafeguard.sphinx.core.QueryLog
import com.sentinelsafeguard.sphinx.lists.ListStore
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
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
 * allowed DNS queries themselves (to the public resolver — exactly
 * where they would have gone without Sphinx) and, when the user taps
 * "Update lists now", HTTPS fetches of the blocklist sources shown in
 * the app. The query log is memory-only, on this device, and can be
 * turned off in the app.
 */
class SphinxVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.sentinelsafeguard.sphinx.action.START"
        const val ACTION_STOP = "com.sentinelsafeguard.sphinx.action.STOP"
        const val ACTION_RELOAD_LISTS = "com.sentinelsafeguard.sphinx.action.RELOAD_LISTS"

        private const val VIRTUAL_DNS = "10.10.10.10"
        private const val DNS_PORT = 53
        private const val CHANNEL_ID = "sphinx_status"
        private const val NOTIFICATION_ID = 1
        private const val UPSTREAM_TIMEOUT_MS = 3000
        private const val MAX_PACKET = 32767

        private val UPSTREAM_RESOLVERS = listOf("1.1.1.1", "9.9.9.9")

        @Volatile
        var isRunning: Boolean = false
            private set

        val blockedCount = AtomicLong(0)
        val allowedCount = AtomicLong(0)

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
    private var workers: ExecutorService = Executors.newFixedThreadPool(4)
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

    override fun onCreate() {
        super.onCreate()
        store = ListStore(this)
        Thread({
            reloadListsNow()
            listsReady.countDown()
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
            else -> {
                if (!running) {
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
        if (workers.isShutdown) {
            workers = Executors.newFixedThreadPool(4)
        }
        startForegroundWithNotification()
        val descriptor = Builder()
            .setSession(getString(R.string.app_name))
            .addAddress(VIRTUAL_DNS, 32)
            .addRoute(VIRTUAL_DNS, 32)
            .addDnsServer(VIRTUAL_DNS)
            .setMtu(1500)
            .establish()
        if (descriptor == null) {
            stopSelf()
            return
        }
        tunInterface = descriptor
        running = true
        isRunning = true
        readerThread = Thread({ packetLoop(descriptor) }, "sphinx-tun-reader").apply { start() }
    }

    private fun packetLoop(descriptor: ParcelFileDescriptor) {
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
                workers.execute { handlePacket(packet, output) }
            } catch (e: Exception) {
                // Pool shut down mid-stop: drop the packet; the loop
                // condition ends the thread on the next pass.
            }
        }
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

    /** Send a DNS query to the upstream resolvers; null if all fail. */
    private fun forward(query: ByteArray): ByteArray? {
        val queryId = if (query.size >= 2) {
            ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
        } else {
            return null
        }
        for (resolver in UPSTREAM_RESOLVERS) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protect(socket) // keep our own queries out of the VPN
                socket.soTimeout = UPSTREAM_TIMEOUT_MS
                // Connected, not just addressed: the kernel then only
                // delivers datagrams that actually come from this
                // resolver, so a stray or spoofed packet from anything
                // else on the network can't be mistaken for the answer.
                socket.connect(InetSocketAddress(InetAddress.getByName(resolver), DNS_PORT))
                socket.send(DatagramPacket(query, query.size))
                val buffer = ByteArray(MAX_PACKET)
                // Accept only the answer to *this* query: matching ID,
                // QR (response) bit set. Anything else is ignored — the
                // same discipline every stub resolver applies
                // (FILTER-SPEC.md, forwarding rules). The 3-second
                // budget covers the whole wait, not each datagram:
                // soTimeout is per-receive, so a stream of mismatched
                // packets must not be able to stretch it forever.
                val deadlineNanos =
                    System.nanoTime() + UPSTREAM_TIMEOUT_MS * 1_000_000L
                while (true) {
                    val response = DatagramPacket(buffer, buffer.size)
                    socket.receive(response)
                    if (response.length >= 4) {
                        val responseId =
                            ((buffer[0].toInt() and 0xFF) shl 8) or (buffer[1].toInt() and 0xFF)
                        val isResponse = buffer[2].toInt() and 0x80 != 0
                        if (responseId == queryId && isResponse) {
                            return buffer.copyOf(response.length)
                        }
                    }
                    if (System.nanoTime() > deadlineNanos) {
                        throw java.net.SocketTimeoutException("no matching response in time")
                    }
                }
            } catch (e: Exception) {
                // Timeout or socket error: try the next resolver.
            } finally {
                socket?.close()
            }
        }
        return null
    }

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
