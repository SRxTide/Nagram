package xyz.nextalone.nagram.xray

import android.text.TextUtils
import android.util.Base64
import libXray.LibXray
import org.json.JSONArray
import org.json.JSONObject
import org.telegram.messenger.FileLog
import org.telegram.messenger.NotificationCenter
import org.telegram.messenger.SharedConfig
import org.telegram.tgnet.ConnectionsManager
import org.telegram.tgnet.RequestTimeDelegate
import tw.nekomimi.nekogram.utils.UIUtil
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Bridge between Telegram's proxy system and the embedded Xray core.
 *
 * Xray-backed proxies are stored as regular [SharedConfig.ProxyInfo] entries whose
 * [SharedConfig.ProxyInfo.xrayLink] field holds the original share link (vless/vmess/trojan/ss/socks).
 * When such a proxy is enabled, the Xray core is started with a local SOCKS5 inbound and
 * the native Telegram connection is pointed at 127.0.0.1 instead of the remote server.
 */
object XrayCore {

    private const val TAG = "XrayCore"

    const val LOCAL_HOST = "127.0.0.1"
    const val LOCAL_PORT = 10808
    private const val API_VERSION = 3

    private var runningLink: String? = null

    val isRunning: Boolean
        @JvmName("isCoreRunning")
        get() = try {
            invoke("getXrayState", null)?.optBoolean("running") == true
        } catch (e: Exception) {
            FileLog.e(TAG, e)
            false
        }

    @JvmStatic
    val supportedSchemes: Array<String> = arrayOf(
        "vless://", "vmess://", "trojan://", "ss://", "socks://"
    )

    @JvmStatic
    fun isXrayLink(link: String?): Boolean {
        if (link.isNullOrEmpty()) return false
        for (scheme in supportedSchemes) {
            if (link.startsWith(scheme)) return true
        }
        return false
    }

    @JvmStatic
    fun isXray(info: SharedConfig.ProxyInfo?): Boolean {
        return info != null && !TextUtils.isEmpty(info.xrayLink)
    }

    private fun invoke(method: String, payload: JSONObject?): JSONObject? {
        val request = JSONObject()
        request.put("apiVersion", API_VERSION)
        request.put("method", method)
        if (payload != null) {
            request.put("payload", payload)
        }
        val response = JSONObject(LibXray.invoke(request.toString()))
        if (!response.optBoolean("success")) {
            throw RuntimeException(response.optString("error"))
        }
        return response.optJSONObject("data")
    }

    /**
     * Parse a single share link into an Xray outbound JSON object.
     *
     * The libXray v26 converter deliberately accepts only a strict subset of
     * v2rayN links. Real-world clients (including Exclave) are more tolerant:
     * empty type/flow values are legal and type defaults to raw TCP. Parse the
     * common URI formats ourselves first, then use libXray as a fallback for
     * formats such as encrypted subscriptions.
     */
    @JvmStatic
    fun parseOutbound(link: String): JSONObject? {
        val text = link.trim()
        if (!isXrayLink(text)) return null
        return try {
            when {
                text.startsWith("vless://", true) -> parseRayUri(text, "vless")
                text.startsWith("trojan://", true) -> parseRayUri(text, "trojan")
                text.startsWith("vmess://", true) -> parseVmess(text)
                text.startsWith("ss://", true) -> parseShadowsocks(text)
                text.startsWith("socks://", true) -> parseSocks(text)
                else -> null
            } ?: parseOutboundWithLibXray(text)
        } catch (e: Exception) {
            FileLog.e(TAG, e)
            parseOutboundWithLibXray(text)
        }
    }

    private fun parseOutboundWithLibXray(link: String): JSONObject? {
        return try {
            val data = invoke("convertShareLinksToXrayJson", JSONObject().put("text", link))
            val outbounds = data?.optJSONArray("outbounds")
            if (outbounds != null && outbounds.length() > 0) outbounds.getJSONObject(0) else null
        } catch (e: Exception) {
            FileLog.e(TAG, e)
            null
        }
    }

    /** Exclave-compatible VLESS/Trojan/URI-style VMess parser. */
    private fun parseRayUri(link: String, protocol: String): JSONObject? {
        val uri = URI(link)
        val host = uri.host ?: return null
        val port = uri.port.takeIf { it in 1..65535 } ?: return null
        val user = decode(uri.rawUserInfo ?: "").substringBefore(":")
        if (user.isEmpty()) return null
        val query = parseQuery(uri.rawQuery)

        val settings = JSONObject().put("address", host).put("port", port)
        when (protocol) {
            "vless" -> {
                // Preserve UUID spelling. Xray performs the final validation.
                settings.put("id", user)
                settings.put("encryption", query["encryption"].orEmpty().ifEmpty { "none" })
                query["flow"]?.takeIf { it.isNotEmpty() && it != "none" }?.let { settings.put("flow", it) }
            }
            "vmess" -> {
                settings.put("id", user)
                settings.put("security", query["encryption"].orEmpty().ifEmpty { "auto" })
            }
            "trojan" -> settings.put("password", decode(uri.rawUserInfo ?: ""))
        }

        return JSONObject()
            .put("protocol", protocol)
            .put("settings", settings)
            .put("streamSettings", buildStreamSettings(query, protocol))
            .apply { decode(uri.rawFragment ?: "").takeIf { it.isNotEmpty() }?.let { put("tag", it) } }
    }

    private fun parseVmess(link: String): JSONObject? {
        val payload = link.substringAfter("vmess://").substringBefore("#")
        val decoded = decodeBase64(payload)
        if (decoded != null && decoded.trimStart().startsWith("{")) {
            val json = JSONObject(decoded)
            val host = json.optString("add")
            val port = json.optString("port").toIntOrNull() ?: json.optInt("port")
            val id = json.optString("id")
            if (host.isEmpty() || port !in 1..65535 || id.isEmpty()) return null
            val settings = JSONObject()
                .put("address", host)
                .put("port", port)
                .put("id", id)
                .put("security", json.optString("scy").ifEmpty { "auto" })
            val fields = mutableMapOf<String, String>()
            fun copy(from: String, to: String = from) {
                json.optString(from).takeIf { it.isNotEmpty() }?.let { fields[to] = it }
            }
            copy("net", "type"); copy("type", "headerType"); copy("host"); copy("path")
            copy("sni"); copy("alpn"); copy("fp"); copy("pbk"); copy("sid"); copy("spx")
            json.optString("tls").takeIf { it.isNotEmpty() }?.let { fields["security"] = it }
            return JSONObject()
                .put("protocol", "vmess")
                .put("settings", settings)
                .put("streamSettings", buildStreamSettings(fields, "vmess"))
                .apply { json.optString("ps").takeIf { it.isNotEmpty() }?.let { put("tag", it) } }
        }
        return parseRayUri(link, "vmess")
    }

    private fun parseShadowsocks(link: String): JSONObject? {
        val withoutFragment = link.substringBefore("#")
        val uri = URI(withoutFragment)
        var host = uri.host
        var port = uri.port
        var userInfo = uri.rawUserInfo?.let(::decode).orEmpty()
        if (host == null || port !in 1..65535) {
            val plain = decodeBase64(withoutFragment.substringAfter("ss://")) ?: return null
            val at = plain.lastIndexOf('@')
            if (at <= 0) return null
            userInfo = plain.substring(0, at)
            val target = URI("ss://" + plain.substring(at + 1))
            host = target.host
            port = target.port
        } else if (!userInfo.contains(':')) {
            userInfo = decodeBase64(userInfo) ?: return null
        }
        if (host.isNullOrEmpty() || port !in 1..65535 || !userInfo.contains(':')) return null
        val method = userInfo.substringBefore(':')
        val password = userInfo.substringAfter(':')
        if (method.isEmpty()) return null
        return JSONObject()
            .put("protocol", "shadowsocks")
            .put("settings", JSONObject()
                .put("address", host)
                .put("port", port)
                .put("method", method)
                .put("password", password))
    }

    private fun parseSocks(link: String): JSONObject? {
        val uri = URI(link)
        val host = uri.host ?: return null
        val port = uri.port.takeIf { it in 1..65535 } ?: return null
        val settings = JSONObject().put("address", host).put("port", port)
        val userInfo = decode(uri.rawUserInfo ?: "")
        if (userInfo.contains(':')) {
            settings.put("user", userInfo.substringBefore(':'))
            settings.put("pass", userInfo.substringAfter(':'))
        }
        return JSONObject().put("protocol", "socks").put("settings", settings)
    }

    /** Transport/security rules follow Exclave's V2RayFmt parser. */
    private fun buildStreamSettings(query: Map<String, String>, protocol: String): JSONObject {
        val rawType = query["type"].orEmpty().lowercase()
        val network = when (rawType) {
            "", "tcp", "raw" -> "raw"
            "websocket" -> "ws"
            "gun" -> "grpc"
            "splithttp" -> "xhttp"
            "mkcp" -> "kcp"
            "ws", "grpc", "httpupgrade", "xhttp", "kcp" -> rawType
            else -> "raw" // Exclave intentionally falls back to TCP for unknown values.
        }
        val stream = JSONObject().put("network", network)
        when (network) {
            "raw" -> if (query["headerType"] == "http") {
                val request = JSONObject()
                query["path"]?.takeIf { it.isNotEmpty() }?.let {
                    request.put("path", JSONArray(it.split(",")))
                }
                query["host"]?.takeIf { it.isNotEmpty() }?.let {
                    request.put("headers", JSONObject().put("Host", JSONArray(it.split(","))))
                }
                stream.put("rawSettings", JSONObject().put("header", JSONObject()
                    .put("type", "http").put("request", request)))
            }
            "ws" -> stream.put("wsSettings", JSONObject()
                .put("path", query["path"].orEmpty())
                .put("host", query["host"].orEmpty()))
            "grpc" -> stream.put("grpcSettings", JSONObject()
                .put("authority", query["authority"].orEmpty())
                .put("serviceName", query["serviceName"].orEmpty())
                .put("multiMode", query["mode"] == "multi"))
            "httpupgrade" -> stream.put("httpupgradeSettings", JSONObject()
                .put("host", query["host"].orEmpty())
                .put("path", query["path"].orEmpty()))
            "xhttp" -> stream.put("xhttpSettings", JSONObject()
                .put("host", query["host"].orEmpty())
                .put("path", query["path"].orEmpty())
                .put("mode", query["mode"].orEmpty()))
            "kcp" -> query["headerType"]?.takeIf { it.isNotEmpty() && it != "none" }?.let {
                stream.put("kcpSettings", JSONObject().put("header", JSONObject().put("type", it)))
            }
        }

        var security = query["security"].orEmpty().lowercase()
        if (security == "xtls") security = "tls"
        if (security !in setOf("none", "tls", "reality")) security = "none"
        if (protocol == "trojan" && security == "none" && !query.containsKey("security")) security = "tls"
        stream.put("security", security)

        if (security == "tls") {
            val tls = JSONObject()
            query["sni"]?.takeIf { it.isNotEmpty() }?.let { tls.put("serverName", it) }
            query["fp"]?.takeIf { it.isNotEmpty() }?.let { tls.put("fingerprint", it) }
            query["alpn"]?.takeIf { it.isNotEmpty() }?.let { tls.put("alpn", JSONArray(it.split(","))) }
            if (query["allowInsecure"] in setOf("1", "true") || query["insecure"] in setOf("1", "true")) {
                tls.put("allowInsecure", true)
            }
            stream.put("tlsSettings", tls)
        } else if (security == "reality") {
            val reality = JSONObject()
            query["sni"]?.takeIf { it.isNotEmpty() }?.let { reality.put("serverName", it) }
            query["fp"]?.takeIf { it.isNotEmpty() }?.let { reality.put("fingerprint", it) }
            query["pbk"]?.takeIf { it.isNotEmpty() }?.let { reality.put("password", it) }
            query["sid"]?.takeIf { it.isNotEmpty() }?.let { reality.put("shortId", it) }
            query["spx"]?.takeIf { it.isNotEmpty() }?.let { reality.put("spiderX", it) }
            stream.put("realitySettings", reality)
        }
        return stream
    }

    private fun parseQuery(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrEmpty()) return emptyMap()
        val result = LinkedHashMap<String, String>()
        for (part in rawQuery.split('&')) {
            val index = part.indexOf('=')
            val key = decode(if (index >= 0) part.substring(0, index) else part)
            val value = decode(if (index >= 0) part.substring(index + 1) else "")
            result[key] = value
        }
        return result
    }

    private fun decode(value: String): String = try {
        URLDecoder.decode(value, StandardCharsets.UTF_8.name())
    } catch (_: Exception) {
        value
    }

    private fun decodeBase64(value: String): String? {
        val clean = value.trim().replace('-', '+').replace('_', '/')
        val padded = clean + "=".repeat((4 - clean.length % 4) % 4)
        return try {
            String(Base64.decode(padded, Base64.DEFAULT), StandardCharsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Build a full runnable Xray config for the given share link.
     */
    @JvmStatic
    fun buildConfig(link: String): String? {
        val outbound = parseOutbound(link) ?: return null
        return try {
            outbound.put("tag", "proxy")
            val inbound = JSONObject()
                .put("tag", "socks-in")
                .put("listen", LOCAL_HOST)
                .put("port", LOCAL_PORT)
                .put("protocol", "socks")
                .put("settings", JSONObject().put("auth", "noauth").put("udp", true).put("ip", "127.0.0.1"))
            val config = JSONObject()
                .put("log", JSONObject().put("loglevel", "warning"))
                .put("inbounds", JSONArray().put(inbound))
                .put("outbounds", JSONArray().put(outbound).put(JSONObject().put("protocol", "freedom").put("tag", "direct")))
            config.toString()
        } catch (e: Exception) {
            FileLog.e(TAG, e)
            null
        }
    }

    /**
     * Parse a share link and convert it into a Telegram [SharedConfig.ProxyInfo].
     */
    @JvmStatic
    fun parseProxy(link: String): SharedConfig.ProxyInfo? {
        val outbound = parseOutbound(link) ?: return null
        val settings = outbound.optJSONObject("settings") ?: return null

        // libXray API v3 projects share links to a flat settings object:
        // {"address":"host","port":443,...}. Keep compatibility with the
        // classic Xray config shape (vnext[] / servers[]) as well.
        var address = settings.optString("address")
        var port = settings.optInt("port")
        if (address.isEmpty() || port <= 0) {
            val servers = settings.optJSONArray("vnext") ?: settings.optJSONArray("servers")
            if (servers != null && servers.length() > 0) {
                val server = servers.optJSONObject(0)
                address = server?.optString("address") ?: ""
                port = server?.optInt("port") ?: 0
            }
        }
        if (address.isEmpty() || port <= 0) return null
        return SharedConfig.ProxyInfo(address, port, "", "", "", link)
    }

    @JvmStatic
    fun protocolOf(link: String?): String {
        if (link.isNullOrEmpty()) return ""
        val idx = link.indexOf("://")
        return if (idx > 0) link.substring(0, idx) else ""
    }

    /**
     * Start the Xray core with the config generated from the given link.
     * Replaces any previously running instance.
     */
    @JvmStatic
    @Synchronized
    fun start(link: String): Boolean {
        if (runningLink == link && isRunning) return true
        stopInternal()
        val config = buildConfig(link) ?: return false
        return try {
            invoke("runXray", JSONObject().put("xrayJson", config))
            runningLink = link
            FileLog.d("$TAG: core started (${protocolOf(link)}) -> $LOCAL_HOST:$LOCAL_PORT")
            true
        } catch (e: Exception) {
            FileLog.e(TAG, e)
            false
        }
    }

    @JvmStatic
    @Synchronized
    fun stop() {
        stopInternal()
    }

    private fun stopInternal() {
        if (runningLink != null) {
            try {
                invoke("stopXray", null)
            } catch (e: Exception) {
                FileLog.e(TAG, e)
            }
            runningLink = null
        }
    }

    @JvmStatic
    fun effectiveAddress(info: SharedConfig.ProxyInfo?): String {
        return if (isXray(info)) LOCAL_HOST else info?.address ?: ""
    }

    @JvmStatic
    fun effectivePort(info: SharedConfig.ProxyInfo?): Int {
        return if (isXray(info)) LOCAL_PORT else info?.port ?: 0
    }

    @JvmStatic
    fun effectiveUsername(info: SharedConfig.ProxyInfo?): String {
        return if (isXray(info)) "" else info?.username ?: ""
    }

    @JvmStatic
    fun effectivePassword(info: SharedConfig.ProxyInfo?): String {
        return if (isXray(info)) "" else info?.password ?: ""
    }

    @JvmStatic
    fun effectiveSecret(info: SharedConfig.ProxyInfo?): String {
        return if (isXray(info)) "" else info?.secret ?: ""
    }

    /**
     * Make sure the core is running for the given proxy (no-op for regular proxies).
     * Used before ping checks, since the core may not be running when the proxy is disabled.
     */
    @JvmStatic
    fun prepareInfo(info: SharedConfig.ProxyInfo) {
        if (isXray(info) && runningLink != info.xrayLink) {
            try {
                start(info.xrayLink!!)
            } catch (e: Exception) {
                FileLog.e(TAG, e)
            }
        }
    }

    /**
     * Central choke point: apply (or disable) a proxy, transparently handling
     * Xray-backed entries by launching the core and pointing the native
     * connection to the local SOCKS5 inbound.
     */
    @JvmStatic
    fun applyProxy(enable: Boolean, info: SharedConfig.ProxyInfo?) {
        UIUtil.runOnIoDispatcher {
            val enableFinal = enable && info != null
            var ok = true
            if (enableFinal && isXray(info)) {
                ok = start(info!!.xrayLink!!)
            } else {
                stop()
            }
            if (enableFinal && ok) {
                ConnectionsManager.setProxySettings(
                    true,
                    effectiveAddress(info),
                    effectivePort(info),
                    effectiveUsername(info),
                    effectivePassword(info),
                    effectiveSecret(info)
                )
            } else {
                ConnectionsManager.setProxySettings(false, "", 0, "", "", "")
            }
            UIUtil.runOnUIThread {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged)
            }
        }
    }

    /**
     * Ping check through the effective (local for Xray) address.
     */
    @JvmStatic
    fun checkProxy(account: Int, info: SharedConfig.ProxyInfo, delegate: RequestTimeDelegate): Long {
        prepareInfo(info)
        return ConnectionsManager.getInstance(account).checkProxy(
            effectiveAddress(info),
            effectivePort(info),
            effectiveUsername(info),
            effectivePassword(info),
            effectiveSecret(info),
            delegate
        )
    }

    @JvmStatic
    fun coreVersion(): String {
        return try {
            invoke("xrayVersion", null)?.optString("version") ?: ""
        } catch (e: Exception) {
            FileLog.e(TAG, e)
            ""
        }
    }
}
