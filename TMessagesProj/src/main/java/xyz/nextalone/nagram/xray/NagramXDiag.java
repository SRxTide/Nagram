package xyz.nextalone.nagram.xray;

import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Startup diagnostic v2:
 * - installs an uncaught-exception handler from ApplicationLoader's static block
 *   (earliest possible Java entry point)
 * - mirrors every breadcrumb to the system Downloads folder IMMEDIATELY, so even
 *   native crashes leave a trail showing the last step reached
 */
public class NagramXDiag {

    private static final SimpleDateFormat TS = new SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US);
    private static final Object LOCK = new Object();
    private static final StringBuilder EARLY_BUFFER = new StringBuilder();
    private static File logFile;
    private static Context appContext;
    private static Uri mirrorUri;
    private static boolean flushing;

    /** Call from ApplicationLoader static block: no Context yet. */
    public static void installHandlerEarly() {
        try {
            final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
            Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
                record("FATAL thread=" + t.getName() + "\n" + stackOf(e));
                flush();
                if (prev != null) {
                    prev.uncaughtException(t, e);
                }
            });
        } catch (Throwable ignored) {
        }
    }

    /** Call from attachBaseContext: Context available, start mirroring. */
    public static void install(Context context) {
        try {
            appContext = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            File dir = appContext.getExternalFilesDir(null);
            if (dir == null) {
                dir = appContext.getFilesDir();
            }
            logFile = new File(dir, "nagramx_diag.log");
            // noinspection ResultOfMethodCallIgnored
            logFile.delete();
            String early;
            synchronized (LOCK) {
                early = EARLY_BUFFER.toString();
                EARLY_BUFFER.setLength(0);
            }
            if (!early.isEmpty()) {
                appendToFile(early);
            }
            log("attachBaseContext model=" + Build.MODEL + " sdk=" + Build.VERSION.SDK_INT
                    + " abis=" + String.join(",", Build.SUPPORTED_ABIS));
        } catch (Throwable ignored) {
        }
    }

    public static void log(String msg) {
        record(msg);
        flush();
    }

    private static void record(String msg) {
        String line = TS.format(new Date()) + " " + msg + "\n";
        synchronized (LOCK) {
            if (logFile != null) {
                appendToFile(line);
            } else {
                EARLY_BUFFER.append(line);
            }
        }
    }

    private static void appendToFile(String line) {
        try {
            FileOutputStream fos = new FileOutputStream(logFile, true);
            fos.write(line.getBytes("UTF-8"));
            fos.close();
        } catch (Throwable ignored) {
        }
    }

    /** Mirror the whole log to Downloads so the user can read it without adb. */
    private static void flush() {
        if (flushing) {
            return;
        }
        flushing = true;
        try {
            Context ctx = appContext;
            byte[] data = currentContent();
            if (data == null || data.length == 0) {
                return;
            }
            if (Build.VERSION.SDK_INT >= 29) {
                if (mirrorUri == null && ctx != null) {
                    ContentValues cv = new ContentValues();
                    cv.put(MediaStore.Downloads.DISPLAY_NAME, "nagramx_diag.log");
                    cv.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
                    mirrorUri = ctx.getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                }
                if (mirrorUri != null && ctx != null) {
                    OutputStream os = ctx.getContentResolver().openOutputStream(mirrorUri, "wt");
                    if (os != null) {
                        os.write(data);
                        os.close();
                    }
                }
            } else if (ctx != null) {
                File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                // noinspection ResultOfMethodCallIgnored
                downloads.mkdirs();
                FileOutputStream fos = new FileOutputStream(new File(downloads, "nagramx_diag.log"));
                fos.write(data);
                fos.close();
            }
        } catch (Throwable t) {
            synchronized (LOCK) {
                if (logFile != null) {
                    appendToFile(TS.format(new Date()) + " mirror:FAILED " + t + "\n");
                }
            }
        } finally {
            flushing = false;
        }
    }

    private static byte[] currentContent() {
        try {
            synchronized (LOCK) {
                if (logFile != null && logFile.exists()) {
                    byte[] data = new byte[(int) logFile.length()];
                    FileInputStream fis = new FileInputStream(logFile);
                    // noinspection ResultOfMethodCallIgnored
                    fis.read(data);
                    fis.close();
                    return data;
                }
                return EARLY_BUFFER.toString().getBytes("UTF-8");
            }
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String stackOf(Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }
}
