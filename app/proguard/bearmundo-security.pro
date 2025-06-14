# ===========================
# Bear Mundo Security ProGuard Rules
# ===========================

# Keep native methods
-keepclasseswithmembernames class org.bearmod.security.** { native <methods>; }
-keepclassmembers class org.bearmod.security.** { native <methods>; }
-keepclasseswithmembers class org.bearmod.security.** { native <methods>; }

# Protect critical security classes
-keep class org.bearmod.security.BearBinder {!private *;}
-keep class org.bearmod.security.ExtQueryHandler {!private *;}
-keep class org.bearmod.security.AccountResponse {!private *;}
-keep class org.bearmod.security.AccountSession {!private *;}
-keep class org.bearmod.security.ServiceConnection {!private *;}
-keep class org.bearmod.security.BearBleCallback {!private *;}
-keep class org.bearmod.security.reflection.BearReflectionStub$** {*;}

# Keep security-related annotations
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes SourceFile,LineNumberTable
-keepattributes Exceptions

# Keep security-related interfaces
-keep interface org.bearmod.security.** { *; }

# Keep security-related enums
-keep enum org.bearmod.security.** { *; }

# Keep security-related serialization
-keepclassmembers class org.bearmod.security.** {
    @com.google.gson.annotations.SerializedName <fields>;
}

# Keep security-related R8 rules
-keepclassmembers,allowobfuscation class org.bearmod.security.** {
    @com.google.gson.annotations.SerializedName <fields>;
}

# Keep security-related Kotlin
-keep class org.bearmod.security.**$Companion { *; }
-keepclassmembers class org.bearmod.security.**$Companion { *; }

# Keep security-related coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# Keep security-related reflection
-keepclassmembers class org.bearmod.security.reflection.** {
    *;
}

# Keep security-related JNI
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep security-related serialization
-keepclassmembers class org.bearmod.security.** implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# Keep security-related Parcelable
-keepclassmembers class org.bearmod.security.** implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

# Keep security-related WebView
-keepclassmembers class org.bearmod.security.** extends android.webkit.WebView {
    *;
}

# Keep security-related ContentProvider
-keepclassmembers class org.bearmod.security.** extends android.content.ContentProvider {
    *;
}

# Keep security-related Service
-keepclassmembers class org.bearmod.security.** extends android.app.Service {
    *;
}

# Keep security-related BroadcastReceiver
-keepclassmembers class org.bearmod.security.** extends android.content.BroadcastReceiver {
    *;
}

# Keep security-related Activity
-keepclassmembers class org.bearmod.security.** extends android.app.Activity {
    *;
}

# Keep security-related Fragment
-keepclassmembers class org.bearmod.security.** extends android.app.Fragment {
    *;
}

# Keep security-related View
-keepclassmembers class org.bearmod.security.** extends android.view.View {
    *;
}

# Keep security-related Application
-keepclassmembers class org.bearmod.security.** extends android.app.Application {
    *;
}

# Keep security-related AsyncTask
-keepclassmembers class org.bearmod.security.** extends android.os.AsyncTask {
    *;
}

# Keep security-related Handler
-keepclassmembers class org.bearmod.security.** extends android.os.Handler {
    *;
}

# Keep security-related Thread
-keepclassmembers class org.bearmod.security.** extends java.lang.Thread {
    *;
}

# Keep security-related Runnable
-keepclassmembers class org.bearmod.security.** implements java.lang.Runnable {
    *;
}

# Keep security-related Callable
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.Callable {
    *;
}

# Keep security-related Future
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.Future {
    *;
}

# Keep security-related Executor
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.Executor {
    *;
}

# Keep security-related ExecutorService
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.ExecutorService {
    *;
}

# Keep security-related ScheduledExecutorService
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.ScheduledExecutorService {
    *;
}

# Keep security-related ThreadFactory
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.ThreadFactory {
    *;
}

# Keep security-related RejectedExecutionHandler
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.RejectedExecutionHandler {
    *;
}

# Keep security-related TimeUnit
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.TimeUnit {
    *;
}

# Keep security-related TimeoutException
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.TimeoutException {
    *;
}

# Keep security-related ExecutionException
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ExecutionException {
    *;
}

# Keep security-related CancellationException
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.CancellationException {
    *;
}

# Keep security-related InterruptedException
-keepclassmembers class org.bearmod.security.** extends java.lang.InterruptedException {
    *;
}

# Keep security-related RejectedExecutionException
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.RejectedExecutionException {
    *;
}

# Keep security-related CompletionException
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.CompletionException {
    *;
}

# Keep security-related CompletionStage
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.CompletionStage {
    *;
}

# Keep security-related CompletableFuture
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.CompletableFuture {
    *;
}

# Keep security-related ForkJoinPool
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ForkJoinPool {
    *;
}

# Keep security-related ForkJoinTask
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ForkJoinTask {
    *;
}

# Keep security-related RecursiveAction
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.RecursiveAction {
    *;
}

# Keep security-related RecursiveTask
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.RecursiveTask {
    *;
}

# Keep security-related CountedCompleter
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.CountedCompleter {
    *;
}

# Keep security-related ForkJoinWorkerThread
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ForkJoinWorkerThread {
    *;
}

# Keep security-related ThreadPoolExecutor
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ThreadPoolExecutor {
    *;
}

# Keep security-related ScheduledThreadPoolExecutor
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ScheduledThreadPoolExecutor {
    *;
}

# Keep security-related AbstractExecutorService
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.AbstractExecutorService {
    *;
}

# Keep security-related AbstractQueuedSynchronizer
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.locks.AbstractQueuedSynchronizer {
    *;
}

# Keep security-related ReentrantLock
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.locks.ReentrantLock {
    *;
}

# Keep security-related ReentrantReadWriteLock
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.locks.ReentrantReadWriteLock {
    *;
}

# Keep security-related StampedLock
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.locks.StampedLock {
    *;
}

# Keep security-related Condition
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.locks.Condition {
    *;
}

# Keep security-related Lock
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.locks.Lock {
    *;
}

# Keep security-related ReadWriteLock
-keepclassmembers class org.bearmod.security.** implements java.util.concurrent.locks.ReadWriteLock {
    *;
}

# Keep security-related AtomicBoolean
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicBoolean {
    *;
}

# Keep security-related AtomicInteger
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicInteger {
    *;
}

# Keep security-related AtomicLong
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicLong {
    *;
}

# Keep security-related AtomicReference
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicReference {
    *;
}

# Keep security-related AtomicIntegerArray
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicIntegerArray {
    *;
}

# Keep security-related AtomicLongArray
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicLongArray {
    *;
}

# Keep security-related AtomicReferenceArray
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicReferenceArray {
    *;
}

# Keep security-related AtomicIntegerFieldUpdater
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicIntegerFieldUpdater {
    *;
}

# Keep security-related AtomicLongFieldUpdater
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicLongFieldUpdater {
    *;
}

# Keep security-related AtomicReferenceFieldUpdater
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicReferenceFieldUpdater {
    *;
}

# Keep security-related AtomicMarkableReference
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicMarkableReference {
    *;
}

# Keep security-related AtomicStampedReference
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.atomic.AtomicStampedReference {
    *;
}

# Keep security-related ConcurrentHashMap
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap {
    *;
}

# Keep security-related ConcurrentSkipListMap
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentSkipListMap {
    *;
}

# Keep security-related ConcurrentSkipListSet
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentSkipListSet {
    *;
}

# Keep security-related ConcurrentLinkedQueue
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentLinkedQueue {
    *;
}

# Keep security-related ConcurrentLinkedDeque
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentLinkedDeque {
    *;
}

# Keep security-related ArrayBlockingQueue
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ArrayBlockingQueue {
    *;
}

# Keep security-related LinkedBlockingQueue
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.LinkedBlockingQueue {
    *;
}

# Keep security-related LinkedBlockingDeque
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.LinkedBlockingDeque {
    *;
}

# Keep security-related PriorityBlockingQueue
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.PriorityBlockingQueue {
    *;
}

# Keep security-related DelayQueue
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.DelayQueue {
    *;
}

# Keep security-related SynchronousQueue
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.SynchronousQueue {
    *;
}

# Keep security-related LinkedTransferQueue
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.LinkedTransferQueue {
    *;
}

# Keep security-related ConcurrentHashMap.KeySetView
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.KeySetView {
    *;
}

# Keep security-related ConcurrentHashMap.ValuesView
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.ValuesView {
    *;
}

# Keep security-related ConcurrentHashMap.EntrySetView
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.EntrySetView {
    *;
}

# Keep security-related ConcurrentHashMap.Node
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.Node {
    *;
}

# Keep security-related ConcurrentHashMap.TreeNode
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.TreeNode {
    *;
}

# Keep security-related ConcurrentHashMap.TreeBin
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.TreeBin {
    *;
}

# Keep security-related ConcurrentHashMap.ForwardingNode
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.ForwardingNode {
    *;
}

# Keep security-related ConcurrentHashMap.ReservationNode
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.ReservationNode {
    *;
}

# Keep security-related ConcurrentHashMap.Traverser
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.Traverser {
    *;
}

# Keep security-related ConcurrentHashMap.BaseIterator
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.BaseIterator {
    *;
}

# Keep security-related ConcurrentHashMap.KeyIterator
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.KeyIterator {
    *;
}

# Keep security-related ConcurrentHashMap.ValueIterator
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.ValueIterator {
    *;
}

# Keep security-related ConcurrentHashMap.EntryIterator
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.EntryIterator {
    *;
}

# Keep security-related ConcurrentHashMap.MapEntry
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.MapEntry {
    *;
}

# Keep security-related ConcurrentHashMap.KeySet
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.KeySet {
    *;
}

# Keep security-related ConcurrentHashMap.Values
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.Values {
    *;
}

# Keep security-related ConcurrentHashMap.EntrySet
-keepclassmembers class org.bearmod.security.** extends java.util.concurrent.ConcurrentHashMap.EntrySet {
    *;
}

# ===========================
# End Bear Mundo Security ProGuard Rules
# =========================== 