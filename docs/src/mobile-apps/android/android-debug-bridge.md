---
authors: ShutdownRepo
category: mobile-apps
---

# Android Debug Bridge ⚙️

## Theory

Android Debug Bridge (adb) is a versatile command-line tool that lets you communicate with a device. The adb command facilitates a variety of device actions, such as installing and debugging apps, and it provides access to a Unix shell that you can use to run a variety of commands on a device.

## Practical

| Command | Description |
| ----------------------- | ------------------------------------------- |
| `adb devices` | List connected devices |
| `adb shell` | shell on connected phone (then su for root) |
| `adb install "app.apk"` | install app on your phone |
| `adb backup ` | backup \ |
| `adb logcat` | logs on your phone |

## Frequent problems

Sometimes ADB can no longer connect to the mobile. There are several reasons for this.

### Make sure Developers options and USB debugging are activated

* Enable Developers options

1. Go to the settings of the Android device. 
2. Go to the system settings. 
3. Go to "About the phone". 
4. Tap 7 times "build number". 
5. The options for developers appear in the system settings. 

* Inside Developers options, enable USB Debugging

> When in doubt, reboot (Confucious)

## Resources

[https://developer.android.com/studio/debug/dev-options](https://developer.android.com/studio/debug/dev-options)

[https://developer.android.com/studio/command-line/adb](https://developer.android.com/studio/command-line/adb)