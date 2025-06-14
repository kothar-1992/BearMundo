package com.bearmod;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Bitmap;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.os.SystemClock;
import android.view.View;
import android.graphics.Matrix;
import android.graphics.RectF;
import android.util.Log;
import java.util.Map;
import java.util.HashMap;
import java.util.Objects;

public class ESPView extends View implements Runnable {

    private int mFPS = 0;
    private int mFPSCounter = 0;
    private long mFPSTime = 0;


    Paint p;
    Bitmap bitmap;
    Bitmap out;
    Bitmap out2;
    Paint mStrokePaint;
    Paint mTextPaint;
    Paint mFilledPaint;
    //
   Thread mThread;

        int screenWidth, screenHeight;
    private final BitmapPool bitmapPool = new BitmapPool();

    private static class BitmapPool {
        private final Map<Integer, Bitmap> pool = new HashMap<>();

        public Bitmap get(int width, int height) {
            int key = Objects.hash(width, height);
            Bitmap bitmap = pool.get(key);
            if (bitmap == null || bitmap.isRecycled()) {
                bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
                pool.put(key, bitmap);
            }
            return bitmap;
        }

        public void recycleAll() {
            for (Bitmap bitmap : pool.values()) {
                if (bitmap != null && !bitmap.isRecycled()) {
                    bitmap.recycle();
                }
            }
            pool.clear();
        }
    }
    public ESPView(Context context) {
        super(context, null, 0);

        InitializePaints();


        // LAG FIX / full smooth
        setFocusableInTouchMode(false);
        setEnabled(false);
        setFitsSystemWindows(false);
        setHapticFeedbackEnabled(false);
        setFocusable(false);
        setFocusedByDefault(false);
        setFocusable(false);

        setForceDarkAllowed(false);
        setHovered(false);
        setKeepScreenOn(false);
      //  setAutoHandwritingEnabled(false);//Crash
        setActivated(false);
       setHovered(false);

        setBackgroundColor(Color.TRANSPARENT);

       mThread = new Thread(this);
        mThread.start();

    }

    public void InitializePaints() {
        mStrokePaint = new Paint();
        mStrokePaint.setStyle(Paint.Style.STROKE);
        mStrokePaint.setAntiAlias(true);
        mStrokePaint.setColor(Color.rgb(0, 0, 0));

        mFilledPaint = new Paint();
        mFilledPaint.setStyle(Paint.Style.FILL);
        mFilledPaint.setAntiAlias(true);
        mFilledPaint.setColor(Color.rgb(0, 0, 0));

        mTextPaint = new Paint();
        mTextPaint.setStyle(Paint.Style.FILL_AND_STROKE);
        mTextPaint.setAntiAlias(true);
        mTextPaint.setColor(Color.rgb(0, 0, 0));
        mTextPaint.setTextAlign(Paint.Align.CENTER);
        mTextPaint.setStrokeWidth(1.1f);

        }

        @Override
        protected void onDraw(Canvas canvas) {
            if (canvas != null && this.getVisibility() == View.VISIBLE) {
                this.ClearCanvas(canvas);
                try {
                    NativeUtils.safeDrawOn(this, canvas);
                } catch (Exception e) {
                    // Draw a fallback message if native method fails
                    Paint errorPaint = new Paint();
                    errorPaint.setColor(Color.RED);
                    errorPaint.setTextSize(40);
                    errorPaint.setTextAlign(Paint.Align.CENTER);
                    canvas.drawText("Native rendering unavailable", canvas.getWidth()/2, canvas.getHeight()/2, errorPaint);

                    // Log the error
                    Log.e("ESPView", "Error in native drawing", e);
                }
            }
        }


    public void drawText(Canvas canvas, int alpha, int red, int green, int blue, float strokeWidth, String text, float x, float y, float textSize, boolean autoScale) {
        mTextPaint.setARGB(alpha, red, green, blue);
        mTextPaint.setStrokeWidth(strokeWidth);

        if (autoScale) {
            if (this.getRight() > 1950 || this.getBottom() > 1920) {
                textSize += 4;
            } else if (this.getRight() == 1950 || this.getBottom() == 1920) {
                textSize += 2;
            }
        }
        mTextPaint.setTextSize(textSize);
        canvas.drawText(text, x, y, mTextPaint);
    }




    public void drawRect(Canvas canvas, int alpha, int red, int green, int blue, float strokeWidth, float left, float top, float right, float bottom, float radius) {
        mStrokePaint.setColor(Color.rgb(red, green, blue));
        mStrokePaint.setAlpha(alpha);
        mStrokePaint.setStrokeWidth(strokeWidth);
        canvas.drawRoundRect(new RectF(left, top, right, bottom), radius, radius, mStrokePaint);
    }

    public void drawCircle(Canvas canvas, int alpha, int red, int green, int blue, float centerX, float centerY, float radius, float strokeWidth) {
        mStrokePaint.setARGB(alpha, red, green, blue);
        mStrokePaint.setStrokeWidth(strokeWidth);
        canvas.drawCircle(centerX, centerY, radius, mStrokePaint);
    }

    public void drawLine(Canvas canvas, int alpha, int red, int green, int blue, float lineWidth, float startX, float startY, float endX, float endY) {
        mStrokePaint.setColor(Color.rgb(red, green, blue));
        mStrokePaint.setAlpha(alpha);
        mStrokePaint.setStrokeWidth(lineWidth);
        canvas.drawLine(startX, startY, endX, endY, mStrokePaint);
    }
    public void drawFilledRect(Canvas canvas, int alpha, int red, int green, int blue, float left, float top, float right, float bottom, float radius) {
        mFilledPaint.setColor(Color.rgb(red, green, blue));
        mFilledPaint.setAlpha(alpha);
        canvas.drawRoundRect(new RectF(left, top, right, bottom), radius, radius, mFilledPaint);
    }

    private int getWeaponIcon(int id) {

        return 0;
    }
     public void ClearCanvas(Canvas cvs) {
         cvs.drawColor(Color.TRANSPARENT, PorterDuff.Mode.SCREEN);
    }

    public static Bitmap scale(Bitmap bitmap, int maxWidth, int maxHeight) {
        int width;
        int height;
        float widthRatio = (float) bitmap.getWidth() / maxWidth;
        float heightRatio = (float) bitmap.getHeight() / maxHeight;

        if (widthRatio >= heightRatio) {
            width = maxWidth;
            height = (int) (((float) width / bitmap.getWidth()) * bitmap.getHeight());
        } else {
            height = maxHeight;
            width = (int) (((float) height / bitmap.getHeight()) * bitmap.getWidth());
        }

        Bitmap scaledBitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        float ratioX = (float) width / bitmap.getWidth();
        float ratioY = (float) height / bitmap.getHeight();
        float middleX = width / 2.0f;
        float middleY = height / 2.0f;
        Matrix scaleMatrix = new Matrix();
        scaleMatrix.setScale(ratioX, ratioY, middleX, middleY);

        Canvas canvas = new Canvas(scaledBitmap);
        canvas.setMatrix(scaleMatrix);
        canvas.drawBitmap(bitmap, middleX - (float) bitmap.getWidth() / 2, middleY - (float) bitmap.getHeight() / 2, new Paint(Paint.FILTER_BITMAP_FLAG));
        return scaledBitmap;
    }



 @Override
 public void run() {
  android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
  while (mThread.isAlive() && !mThread.isInterrupted()) {
   try {
       long sleepTime = 1000 / 120;//GetDeviceMaxFps2();//
    long t1 = System.currentTimeMillis();
    postInvalidate();
    long td = System.currentTimeMillis() - t1;

    long sleepDuration = Math.max(0, sleepTime - td);
    Thread.sleep(sleepDuration);
   } catch (Exception e) {
    Thread.currentThread().interrupt();
    return;
   }
  }
 }


    }
