package com.techarha.android.security.droidcheck;

import com.techarha.android.security.droidcheck.analyser.StaticAnalyser;

import java.io.File;
import java.io.IOException;

/**
 * INPUT:
 *      APK_FILE_PATH: should be the path where directories benign and malicious are created, which in turn contain directory apks and text file apkList.txt.
 *      apks folder will contain all the sample apks, and apkList.txt will contain the names of all the collected samples.
 *
 *      BASE_PATH: The path where android sdk is stored.
 *      VERSION: version of the build tools to use, use any of the ones installed on the system.
 *      SDK_FILE_PATH: represents the full path of the 'aapt' tool.
 *
 *      RESULT_PATH: The path to output Results of analysis.
 *
 * Created by ankit on 15/05/15.
 */
public class Runner {
    //PATH TO APKs
    final static String APK_FILE_PATH = "/Developer/android-security/android-apks/";

    //ANDROID SDK PATHS
    final static String BASE_PATH = "/Developer/android-sdk/";
    final static String VERSION = "18.0.1";
    final static String SDK_FILE_PATH = BASE_PATH+"sdk/build-tools/"+VERSION;

    //ANALYSIS OUTPUT PATHS
    final static String RESULT_PATH = "/Developer/android-security/results/";

    public static void main(String[] args) {
        new StaticAnalyser().analysePermissions(SDK_FILE_PATH,RESULT_PATH,APK_FILE_PATH);
    }
}
