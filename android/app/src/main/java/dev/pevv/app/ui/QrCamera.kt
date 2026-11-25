package dev.pevv.app.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.view.HapticFeedbackConstants
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.TorchState
import androidx.camera.core.ZoomState
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LiveData
import androidx.lifecycle.Observer
import com.google.zxing.PlanarYUVLuminanceSource
import dev.pevv.app.R
import dev.pevv.app.core.QrDebounce
import dev.pevv.app.core.QrReader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors
import kotlin.math.max
import kotlin.math.min

/**
 * Camera QR scanner: reports every QR text it decodes (debounced) through [onText]. CameraX + ZXing, all on the
 * phone, nothing leaves it. Pinch or slider zoom, tap to focus, flash, front/back switch, and a photo-picker
 * route for a QR saved as an image. Handles a denied permission and a device with no camera.
 */
@Composable
fun QrCamera(onText: (String) -> Unit, modifier: Modifier = Modifier) {
    val ctx = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val view = LocalView.current
    val scope = rememberCoroutineScope()
    val current by rememberUpdatedState(onText)
    val debounce = remember { QrDebounce() }
    var message by remember { mutableStateOf<String?>(null) }
    val hasCamera = remember { ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) }
    var granted by remember { mutableStateOf(cameraGranted(ctx)) }
    var denied by remember { mutableStateOf(false) }

    // Every result, from the camera thread or the picker, ends up here on the main thread.
    fun deliver(text: String) {
        if (!debounce.accept(text, SystemClock.elapsedRealtime())) return
        view.performHapticFeedback(if (Build.VERSION.SDK_INT >= 30) HapticFeedbackConstants.CONFIRM else HapticFeedbackConstants.KEYBOARD_TAP)
        current(text)
    }

    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it; if (!it) denied = true }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) scope.launch {
            val text = withContext(Dispatchers.Default) { decodeImage(ctx, uri) }
            if (text == null) message = ctx.getString(R.string.qr_no_code_in_image) else deliver(text)
        }
    }
    val pickImage = { picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) }

    LaunchedEffect(Unit) { if (hasCamera && !granted) ask.launch(Manifest.permission.CAMERA) }
    // Coming back from the system settings: pick up a permission granted there.
    DisposableEffect(owner) {
        val obs = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_RESUME) granted = cameraGranted(ctx) }
        owner.lifecycle.addObserver(obs)
        onDispose { owner.lifecycle.removeObserver(obs) }
    }
    LaunchedEffect(message) { if (message != null) { delay(3000); message = null } }

    if (hasCamera && granted) {
        LiveCamera(modifier, message, pickImage) { text -> deliver(text) }
        return
    }
    Column(modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            when {
                !hasCamera -> stringResource(R.string.qr_no_camera)
                denied -> stringResource(R.string.qr_camera_denied)
                else -> stringResource(R.string.camera_needed)
            },
        )
        if (hasCamera) PrimaryButton(stringResource(R.string.allow_camera), { ask.launch(Manifest.permission.CAMERA) })
        if (hasCamera && denied) PrimaryButton(stringResource(R.string.qr_open_settings), { openAppSettings(ctx) })
        PrimaryButton(stringResource(R.string.qr_gallery), pickImage)
        message?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

private fun cameraGranted(ctx: Context) = ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

private fun openAppSettings(ctx: Context) {
    try {
        ctx.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", ctx.packageName, null)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (_: Exception) {
    }
}

@Composable
private fun LiveCamera(modifier: Modifier, message: String?, onGallery: () -> Unit, onCode: (String) -> Unit) {
    val ctx = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val onCodeNow by rememberUpdatedState(onCode)
    var front by remember { mutableStateOf(false) }
    var camera by remember { mutableStateOf<Camera?>(null) }
    var hasBoth by remember { mutableStateOf(false) }
    var hasFlash by remember { mutableStateOf(false) }
    var torchOn by remember { mutableStateOf(false) }
    var zoom by remember { mutableStateOf<ZoomState?>(null) }
    var failed by remember { mutableStateOf(false) }
    var lowLight by remember { mutableStateOf(false) }
    var focusAt by remember { mutableStateOf<Offset?>(null) }
    val zoomNow by rememberUpdatedState(zoom)
    val view = remember { PreviewView(ctx).also { it.scaleType = PreviewView.ScaleType.FILL_CENTER } }

    DisposableEffect(owner, front) {
        var disposed = false
        val executor = Executors.newSingleThreadExecutor()
        val reader = QrReader()
        val main = Handler(Looper.getMainLooper())
        var provider: ProcessCameraProvider? = null
        var preview: Preview? = null
        var analysis: ImageAnalysis? = null
        var zoomData: LiveData<ZoomState>? = null
        var torchData: LiveData<Int>? = null
        val zoomObs = Observer<ZoomState> { zoom = it }
        val torchObs = Observer<Int> { torchOn = it == TorchState.ON }
        val future = ProcessCameraProvider.getInstance(ctx)
        future.addListener({
            // The effect may already be gone (the screen left before CameraX was ready): bind nothing then.
            if (disposed) return@addListener
            try {
                val p = future.get()
                provider = p
                val back = p.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)
                val fr = p.hasCamera(CameraSelector.DEFAULT_FRONT_CAMERA)
                hasBoth = back && fr
                val selector = if ((front && fr) || !back) CameraSelector.DEFAULT_FRONT_CAMERA else CameraSelector.DEFAULT_BACK_CAMERA
                val pv = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                val res = ResolutionSelector.Builder()
                    .setResolutionStrategy(ResolutionStrategy(android.util.Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER))
                    .build()
                val an = ImageAnalysis.Builder()
                    .setResolutionSelector(res)
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                var frameNo = 0
                var lastRefocus = SystemClock.elapsedRealtime()
                an.setAnalyzer(executor) { img ->
                    // use{} closes the ImageProxy on every path, which is what lets the next frame arrive.
                    img.use {
                        try {
                            val plane = it.planes[0]
                            val buf = plane.buffer
                            buf.rewind()
                            val data = ByteArray(buf.remaining()).also { b -> buf.get(b) }
                            val stride = plane.rowStride
                            if (stride >= it.width && data.size >= stride * (it.height - 1) + it.width) {
                                val src = PlanarYUVLuminanceSource(data, stride, it.height, 0, 0, it.width, it.height, false)
                                val n = frameNo++
                                // Inverted / low-contrast passes are slower: only every third frame.
                                val text = reader.decode(src, thorough = n % 3 == 2)
                                val now = SystemClock.elapsedRealtime()
                                if (text != null) {
                                    lastRefocus = now
                                    main.post { if (!disposed) onCodeNow(text) }
                                } else if (now - lastRefocus > 4000) {
                                    // Nothing readable for a while: probably blurred, so refocus on the centre once.
                                    lastRefocus = now
                                    main.post {
                                        val c = camera
                                        if (!disposed && c != null && view.width > 0) {
                                            c.cameraControl.startFocusAndMetering(FocusMeteringAction.Builder(view.meteringPointFactory.createPoint(view.width / 2f, view.height / 2f)).build())
                                        }
                                    }
                                }
                                if (n % 10 == 0) {
                                    // Mean brightness of a sparse sample: very dark means the flash should be on.
                                    var sum = 0L
                                    var cnt = 0
                                    var k = 0
                                    while (k < data.size) { sum += data[k].toInt() and 0xFF; cnt++; k += 97 }
                                    val dark = cnt > 0 && sum / cnt < 45
                                    main.post { if (!disposed) lowLight = dark }
                                }
                            }
                        } catch (_: Exception) {
                        }
                    }
                }
                preview = pv
                analysis = an
                p.unbind(pv, an)
                val cam = p.bindToLifecycle(owner, selector, pv, an)
                camera = cam
                hasFlash = cam.cameraInfo.hasFlashUnit()
                zoomData = cam.cameraInfo.zoomState.also { it.observe(owner, zoomObs) }
                torchData = cam.cameraInfo.torchState.also { it.observe(owner, torchObs) }
                failed = false
            } catch (_: Exception) {
                failed = true
            }
        }, ContextCompat.getMainExecutor(ctx))
        onDispose {
            disposed = true
            zoomData?.removeObserver(zoomObs)
            torchData?.removeObserver(torchObs)
            analysis?.clearAnalyzer()
            val pr = provider
            if (pr != null) {
                val use = listOfNotNull(preview, analysis)
                if (use.isNotEmpty()) pr.unbind(*use.toTypedArray())
            }
            executor.shutdown()
            camera = null
            zoom = null
            hasFlash = false
            torchOn = false
        }
    }
    LaunchedEffect(focusAt) { if (focusAt != null) { delay(900); focusAt = null } }

    val desc = stringResource(R.string.camera_desc)
    Box(modifier.background(Color.Black)) {
        AndroidView(
            { view },
            Modifier.fillMaxSize()
                .semantics { contentDescription = desc }
                .pointerInput(camera) {
                    detectTapGestures { pt ->
                        val c = camera ?: return@detectTapGestures
                        val point = view.meteringPointFactory.createPoint(pt.x, pt.y)
                        // AF + AE at the tap; after the auto-cancel delay CameraX returns to continuous autofocus.
                        c.cameraControl.startFocusAndMetering(FocusMeteringAction.Builder(point, FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE).build())
                        focusAt = pt
                    }
                }
                .pointerInput(camera) {
                    detectTransformGestures { _, _, change, _ ->
                        val c = camera ?: return@detectTransformGestures
                        val z = zoomNow ?: return@detectTransformGestures
                        if (change != 1f) c.cameraControl.setZoomRatio((z.zoomRatio * change).coerceIn(z.minZoomRatio, z.maxZoomRatio))
                    }
                },
        )
        Canvas(Modifier.fillMaxSize()) {
            val side = min(size.width, size.height) * 0.62f
            val tl = Offset((size.width - side) / 2f, (size.height - side) / 2f)
            val box = Rect(tl, Size(side, side))
            val dim = Path().apply {
                fillType = PathFillType.EvenOdd
                addRect(Rect(Offset.Zero, size))
                addRoundRect(RoundRect(box, CornerRadius(16.dp.toPx())))
            }
            drawPath(dim, Color.Black.copy(alpha = 0.45f))
            val arm = side * 0.14f
            val w = 4.dp.toPx()
            fun corner(x: Float, y: Float, dx: Float, dy: Float) {
                drawLine(Color.White, Offset(x, y), Offset(x + dx * arm, y), w)
                drawLine(Color.White, Offset(x, y), Offset(x, y + dy * arm), w)
            }
            corner(box.left, box.top, 1f, 1f)
            corner(box.right, box.top, -1f, 1f)
            corner(box.left, box.bottom, 1f, -1f)
            corner(box.right, box.bottom, -1f, -1f)
            focusAt?.let { drawCircle(Color.White, 28.dp.toPx(), it, style = Stroke(2.dp.toPx())) }
        }
        Row(Modifier.align(Alignment.TopCenter).fillMaxWidth().background(Color.Black.copy(alpha = 0.4f)), horizontalArrangement = Arrangement.SpaceEvenly) {
            if (hasFlash) TextButton({ camera?.cameraControl?.enableTorch(!torchOn) }) {
                Text(stringResource(if (torchOn) R.string.qr_torch_off else R.string.qr_torch_on), color = Color.White)
            }
            if (hasBoth) TextButton({ front = !front }) { Text(stringResource(R.string.qr_switch_camera), color = Color.White) }
            TextButton(onGallery) { Text(stringResource(R.string.qr_gallery), color = Color.White) }
        }
        Column(Modifier.align(Alignment.BottomCenter).fillMaxWidth().background(Color.Black.copy(alpha = 0.4f)).padding(horizontal = 12.dp)) {
            val status = if (failed) stringResource(R.string.qr_camera_failed) else message
            status?.let { Text(it, color = Color.White, style = MaterialTheme.typography.bodySmall) }
            if (lowLight && !torchOn) Text(stringResource(if (hasFlash) R.string.qr_low_light_flash else R.string.qr_low_light), color = Color.White, style = MaterialTheme.typography.bodySmall)
            val z = zoom
            if (z != null && z.maxZoomRatio > z.minZoomRatio) {
                val zoomDesc = stringResource(R.string.qr_zoom)
                Slider(z.linearZoom, { camera?.cameraControl?.setLinearZoom(it) }, Modifier.semantics { contentDescription = zoomDesc })
            }
        }
    }
}

/** Reads a QR out of a picked image; large photos are sampled down to a size ZXing handles, and retried smaller. */
private fun decodeImage(ctx: Context, uri: Uri): String? {
    return try {
        val cr = ctx.contentResolver
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        cr.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sample = 1
        while (max(bounds.outWidth, bounds.outHeight) / sample > 2048) sample *= 2
        val reader = QrReader()
        for (extra in intArrayOf(1, 2, 4)) {
            if (extra > 1 && max(bounds.outWidth, bounds.outHeight) / (sample * extra) < 300) break
            val opts = BitmapFactory.Options().apply { inSampleSize = sample * extra }
            val bmp = cr.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) } ?: continue
            try {
                val px = IntArray(bmp.width * bmp.height)
                bmp.getPixels(px, 0, bmp.width, 0, 0, bmp.width, bmp.height)
                reader.decodeArgb(bmp.width, bmp.height, px)?.let { return it }
            } finally {
                bmp.recycle()
            }
        }
        null
    } catch (_: Exception) {
        null
    } catch (_: OutOfMemoryError) {
        null
    }
}
