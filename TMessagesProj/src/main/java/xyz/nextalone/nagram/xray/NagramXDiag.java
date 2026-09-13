package xyz.nextalone.nagram.xray;

import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Startup diagnostic: breadcrumbs + uncaught exception dump written to the
 * system Downloads folder, so users can report launch crashes without adb.
 */
public class NagramXDiag {

    private static final SimpleDateFormat TS = new SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US);
    private static File logFile;
    private static final Object LOCK = new Object();

    public static void install(Context context) {
        try {
            log(context, "attachBaseContext");
            final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
            Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
                synchronized (LOCK) {
                    append("FATAL on thread " + t.getName() + "\n" + stackOf(e) + "\n");
                }
                flushToDownloads(context);
                if (prev != null) {
                    prev.uncaughtException(t, e);
                }
            });
        } catch (Throwable ignored) {
        }
    }

    public static void log(String msg) {
        try {
            append(msg);
        } catch (Throwable ignored) {
        }
    }

    private static void log(Context context, String msg) {
        try {
            if (logFile == null) {
                File dir = context.getExternalFilesDir(null);
                if (dir == null) {
                    dir = context.getFilesDir();
                }
                logFile = new File(dir, "nagramx_diag.log");
                if (logFile.exists()) {
                    // noinspection ResultOfMethodCallIgnored
                    logFile.delete();
                }
            }
            append(msg);
        } catch (Throwable ignored) {
        }
    }

    private static void append(String msg) {
        try {
            if (logFile != null) {
                FileOutputStream fos = new FileOutputStream(logFile, true);
                fos.write((TS.format(new Date()) + " " + msg + "\n").getBytes("UTF-8"));
                fos.close();
            }
        } catch (Throwable ignored) {
        }
    }

    private static String stackOf(Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    private static void flushToDownloads(Context context) {
        try {
            if (logFile == null || !logFile.exists()) {
                return;
            }
            byte[] data = new byte[(int) logFile.length()];
            java.io.FileInputStream fis = new java.io.FileInputStream(logFile);
            // noinspection ResultOfMethodCallIgnored
            fis.read(data);
            fis.close();

            if (Build.VERSION.SDK_INT >= 29) {
                ContentValues cv = new ContentValues();
                cv.put(MediaStore.Downloads.DISPLAY_NAME, "nagramx_diag.log");
                cv.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
                cv.put(MediaStore.Downloads.IS_PENDING, 1);
                Uri uri = context.getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                if (uri == null) {
                    return;
                }
                OutputStream os = context.getContentResolver().openOutputStream(uri);
                if (os != null) {
                    os.write(data);
                    os.close();
                }
                ContentValues done = new ContentValues();
                done.put(MediaStore.Downloads.IS_PENDING, 0);
                context.getContentResolver().update(uri, done, null, null);
            } else {
                File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                // noinspection ResultOfMethodCallIgnored
                downloads.mkdirs();
                FileOutputStream fos = new FileOutputStream(new File(downloads, "nagramx_diag.log"));
                fos.write(data);
                fos.close();
            }
        } catch (Throwable ignored) {
        }
    }
}
