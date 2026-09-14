package xyz.nextalone.nagram.xray

import android.text.TextUtils
import libXray.LibXray
import org.json.JSONArray
import org.json.JSONObject
import org.telegram.messenger.FileLog
import org.telegram.messenger.NotificationCenter
import org.telegram.messenger.SharedConfig
import org.telegram.tgnet.ConnectionsManager
import org.telegram.tgnet.RequestTimeDelegate
import tw.nekomimi.nekogram.utils.UIUtil

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
            invoke("GetXrayState", null)?.optBoolean("running") == true
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
     * Parse a single share link into an Xray outbound JSON object
     * using the core's built-in link parser.
     */
    @JvmStatic
    fun parseOutbound(link: String): JSONObject? {
        if (!isXrayLink(link)) return null
        return try {
            val data = invoke("ConvertShareLinksToXrayJson", JSONObject().put("text", link))
            val outbounds = data?.optJSONArray("outbounds")
            if (outbounds != null && outbounds.length() > 0) outbounds.getJSONObject(0) else null
        } catch (e: Exception) {
            FileLog.e(TAG, e)
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
            invoke("RunXray", JSONObject().put("xrayJson", config))
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
                invoke("StopXray", null)
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
            invoke("XrayVersion", null)?.optString("version") ?: ""
        } catch (e: Exception) {
            FileLog.e(TAG, e)
            ""
        }
    }
}
