# kotlinx.serialization (the app uses the JsonElement tree, but keep the runtime metadata safe).
-keepattributes *Annotation*, InnerClasses
-dontwarn org.slf4j.**
# Bouncy Castle: only Argon2 is used, by name; the rest can be shrunk.
-dontwarn org.bouncycastle.**
-keep class org.bouncycastle.crypto.generators.Argon2BytesGenerator { *; }
-keep class org.bouncycastle.crypto.params.Argon2Parameters { *; }
-keep class org.bouncycastle.crypto.params.Argon2Parameters$Builder { *; }
# OkHttp / Okio
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
