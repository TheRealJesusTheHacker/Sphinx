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
import com.sentinelsafeguard.sphinx.core.Blocklist
import com.sentinelsafeguard.sphinx.core.DnsPacket
import com.sentinelsafeguard.sphinx.core.IpUdpPacket
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

/**
 * Sphinx's Android edition engine.
 *
 * Establishes a TUN interface and routes ONLY the virtual DNS server
 * address (10.10.10.10) through it, so the system hands this service its
 * DNS lookups and nothing else. Each query is checked against the
 * blocklist: blocked names get a sinkhole answer built on the spot;
 * allowed queries are forwarded to an upstream resolver over a protected
 * socket (protected, so the query can't loop back into the VPN) and the
 * real answer is written back into the TUN.
 *
 * There is no remote VPN server. Nothing leaves the phone except the
 * allowed DNS queries themselves, which go to the public resolver —
 * exactly where they would have gone without Sphinx.
 */
class SphinxVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.sentinelsafeguard.sphinx.action.START"
        const val ACTION_STOP = "com.sentinelsafeguard.sphinx.action.STOP"

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
    }

    private var tunInterface: ParcelFileDescriptor? = null
    private var readerThread: Thread? = null
    private val workers = Executors.newFixedThreadPool(4)
    private val writeLock = Any()

    @Volatile
    private var running = false

    private lateinit var blocklist: Blocklist

    override fun onCreate() {
        super.onCreate()
        blocklist = assets.open("starter-blocklist.txt").bufferedReader().useLines { lines ->
            Blocklist.fromLines(lines)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        if (!running) startFilter()
        return START_STICKY
    }

    override fun onRevoke() {
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun startFilter() {
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
            workers.execute { handlePacket(packet, output) }
        }
    }

    private fun handlePacket(packet: ByteArray, output: FileOutputStream) {
        val ip = IpUdpPacket.parse(packet, packet.size) ?: return
        if (ip.destPort != DNS_PORT) return
        if (!ip.destAddress.contentEquals(VIRTUAL_DNS_BYTES)) return

        val queryBytes = packet.copyOfRange(ip.payloadOffset, ip.payloadOffset + ip.payloadLength)
        val dns = DnsPacket.parse(queryBytes, queryBytes.size) ?: return
        if (dns.isResponse) return

        if (blocklist.isBlocked(dns.questionName)) {
            blockedCount.incrementAndGet()
            writeResponse(output, IpUdpPacket.buildResponse(ip, dns.buildSinkholeResponse()))
        } else {
            val answer = forward(queryBytes)
            if (answer != null) {
                allowedCount.incrementAndGet()
                writeResponse(output, IpUdpPacket.buildResponse(ip, answer))
            }
            // No answer from any upstream: leave the query unanswered and
            // let the asking app retry, per FILTER-SPEC.md.
        }
    }

    /** Send a DNS query to the upstream resolvers; null if all fail. */
    private fun forward(query: ByteArray): ByteArray? {
        for (resolver in UPSTREAM_RESOLVERS) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protect(socket) // keep our own queries out of the VPN
                socket.soTimeout = UPSTREAM_TIMEOUT_MS
                val address = InetAddress.getByName(resolver)
                socket.send(DatagramPacket(query, query.size, address, DNS_PORT))
                val buffer = ByteArray(MAX_PACKET)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                return buffer.copyOf(response.length)
            } catch (e: Exception) {
                // Try the next resolver.
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
