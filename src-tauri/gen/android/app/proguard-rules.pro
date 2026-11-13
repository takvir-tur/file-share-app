# Add project specific ProGuard rules here.
# Preserve BeamDrop JNI bridge classes, storage reflection helpers, and Android services.
-keep class com.beamdrop.app.BeamDropBridge { *; }
-keep class com.beamdrop.app.BeamDropStorage { *; }
-keep class com.beamdrop.app.BeamDropReceiveService { *; }
-keep class com.beamdrop.app.BeamDropTileService { *; }
-keep class com.beamdrop.app.MainActivity { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
