# Hilt / Dagger
-dontwarn dagger.hilt.**
-keep class dagger.hilt.** { *; }
-keep class * extends dagger.hilt.android.internal.managers.ViewComponentManager$FragmentContextWrapper { *; }

# MessagePack (MSF RPC)
-keep class org.msgpack.** { *; }
-dontwarn org.msgpack.**

# Kotlin coroutines
-dontwarn kotlinx.coroutines.**

# AndroidX / Compose
-dontwarn androidx.compose.**

# Keep Hilt-injected classes
-keep,allowobfuscation @dagger.hilt.android.lifecycle.HiltViewModel class * { *; }
-keep,allowobfuscation @javax.inject.Inject class * { *; }
-keep class org.csploit.strix.di.** { *; }
