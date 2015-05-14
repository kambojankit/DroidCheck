package com.techarha.android.security.droidcheck;

import java.io.File;
import java.io.IOException;

/**
 * Created by ankit on 15/05/15.
 */
public class Runner {

    final static String[] apkNameList = {"SampleProject.apk"};

    final static String BASE_PATH_WIN = "";
    final static String BASE_PATH_MAC = "/Developer/android-sdk/";

    final static String SDK_FILE_PATH_MAC = BASE_PATH_MAC+"sdk/build-tools/18.0.1";

    final static String APK_FILE_PATH = "/Developer/Android-apks/";

    public static void main(String[] args) {

        String command = "./aapt dump permissions "+APK_FILE_PATH+apkNameList[0];

        System.out.println(command);

        try {
            System.out.println(Runtime.getRuntime().exec(command, null, new File(SDK_FILE_PATH_MAC)));
        } catch (IOException e) {
            System.out.println("An Exception has occurred." + e);
        }
    }
}
